package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blackestwhite/masterdns-qs-tunnel/internal/config"
	"github.com/blackestwhite/masterdns-qs-tunnel/internal/dnswire"
	"github.com/blackestwhite/masterdns-qs-tunnel/internal/protocol"
	"github.com/blackestwhite/masterdns-qs-tunnel/internal/resolver"
	"github.com/blackestwhite/masterdns-qs-tunnel/internal/socks"
)

// clientStream tracks a single SOCKS5 connection multiplexed over the DNS tunnel.
type clientStream struct {
	id         uint32
	conn       net.Conn
	downlinkCh chan downlinkEvent
	cancel     context.CancelFunc
}

// downlinkEvent carries a packet received from the server on the UDP downlink path.
type downlinkEvent struct {
	kind    protocol.DownlinkKind
	payload []byte
}

type Service struct {
	cfg          config.ClientConfig
	clientID     string
	announceIP   netip.Addr
	spoofIP      netip.Addr
	resolvers    *resolver.Pool
	plans        []protocol.DomainPlan
	sendConn     *net.UDPConn
	sockListener net.Listener
	downlinkConn *net.UDPConn
	nextQueryID  atomic.Uint32
	nextOffset   atomic.Uint64
	planMu       sync.Mutex
	nextPlanIndex int
	nextStreamID  atomic.Uint32
	streamsMu     sync.RWMutex
	streams       map[uint32]*clientStream
}

func New(cfg config.ClientConfig) (*Service, error) {
	if err := cfg.EnsureClientID(); err != nil {
		return nil, err
	}

	resolverEndpoints, err := loadResolvers(cfg)
	if err != nil {
		return nil, err
	}
	resolverPool, err := resolver.NewPool(resolverEndpoints)
	if err != nil {
		return nil, err
	}

	plans, err := protocol.PrepareDomainPlans(cfg.SendDomains, cfg.MaxQNameLen, cfg.MaxLabelLen, cfg.OffsetWidth, cfg.ClientIDLength)
	if err != nil {
		return nil, err
	}

	announceIP, err := netip.ParseAddr(cfg.AnnouncePublicIP)
	if err != nil || !announceIP.Is4() {
		return nil, fmt.Errorf("announce_public_ip must be a valid IPv4 address")
	}
	spoofIP, err := netip.ParseAddr(cfg.SpoofSourceIP)
	if err != nil || !spoofIP.Is4() {
		return nil, fmt.Errorf("spoof_source_ip must be a valid IPv4 address")
	}

	sockListener, err := net.Listen("tcp", cfg.SocksListen)
	if err != nil {
		return nil, fmt.Errorf("listen socks: %w", err)
	}

	downlinkAddr, err := net.ResolveUDPAddr("udp", cfg.DownlinkBind)
	if err != nil {
		_ = sockListener.Close()
		return nil, fmt.Errorf("resolve downlink_bind: %w", err)
	}
	downlinkConn, err := net.ListenUDP("udp", downlinkAddr)
	if err != nil {
		_ = sockListener.Close()
		return nil, fmt.Errorf("listen downlink: %w", err)
	}

	sendConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		_ = sockListener.Close()
		_ = downlinkConn.Close()
		return nil, fmt.Errorf("create send socket: %w", err)
	}

	return &Service{
		cfg:          cfg,
		clientID:     cfg.ClientID,
		announceIP:   announceIP,
		spoofIP:      spoofIP,
		resolvers:    resolverPool,
		plans:        plans,
		sendConn:     sendConn,
		sockListener: sockListener,
		downlinkConn: downlinkConn,
		streams:      make(map[uint32]*clientStream),
	}, nil
}

func (s *Service) ClientID() string {
	return s.clientID
}

func (s *Service) Run(ctx context.Context) error {
	defer s.close()

	errCh := make(chan error, 3)
	go func() { errCh <- s.runSocksAcceptLoop(ctx) }()
	go func() { errCh <- s.runDownlinkLoop(ctx) }()
	go func() { errCh <- s.runInfoLoop(ctx) }()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			if err == nil || errors.Is(err, context.Canceled) {
				continue
			}
			return err
		}
	}
}

func (s *Service) close() {
	if s.sockListener != nil {
		_ = s.sockListener.Close()
	}
	if s.sendConn != nil {
		_ = s.sendConn.Close()
	}
	if s.downlinkConn != nil {
		_ = s.downlinkConn.Close()
	}
	// Cancel all active streams.
	s.streamsMu.Lock()
	for _, stream := range s.streams {
		stream.cancel()
		_ = stream.conn.Close()
	}
	s.streams = make(map[uint32]*clientStream)
	s.streamsMu.Unlock()
}

// runSocksAcceptLoop accepts SOCKS5 TCP connections and starts a handler goroutine
// for each one.
func (s *Service) runSocksAcceptLoop(ctx context.Context) error {
	for {
		conn, err := s.sockListener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleSocksConn(ctx, conn)
	}
}

// handleSocksConn handles a single inbound SOCKS5 connection end-to-end.
func (s *Service) handleSocksConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	host, port, err := socks.Handshake(conn)
	if err != nil {
		return
	}

	streamID := s.nextStreamID.Add(1)
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	downlinkCh := make(chan downlinkEvent, 128)
	stream := &clientStream{
		id:         streamID,
		conn:       conn,
		downlinkCh: downlinkCh,
		cancel:     cancel,
	}
	s.addStream(stream)
	defer s.removeStream(streamID)

	// Announce the new stream to the server.
	if err := s.sendFrame(protocol.BuildConnectFrame(streamID, host, port)); err != nil {
		_ = socks.SendFailure(conn)
		return
	}

	// Wait for the server to establish the TCP connection.
	select {
	case event, ok := <-downlinkCh:
		if !ok || event.kind != protocol.DownlinkConnected {
			_ = socks.SendFailure(conn)
			return
		}
	case <-time.After(30 * time.Second):
		_ = socks.SendFailure(conn)
		return
	case <-streamCtx.Done():
		_ = socks.SendFailure(conn)
		return
	}

	if err := socks.SendSuccess(conn); err != nil {
		return
	}

	// Goroutine: read from SOCKS5 TCP connection, send uplink via DNS.
	go func() {
		defer cancel()
		buf := make([]byte, 4096)
		for {
			n, readErr := conn.Read(buf)
			if n > 0 {
				if sendErr := s.sendFrame(protocol.BuildStreamDataFrame(streamID, buf[:n])); sendErr != nil {
					return
				}
			}
			if readErr != nil {
				// Notify server that this stream is closing.
				_ = s.sendFrame(protocol.BuildStreamCloseFrame(streamID))
				return
			}
		}
	}()

	// Current goroutine: receive downlink data, write to SOCKS5 TCP connection.
	for {
		select {
		case event, ok := <-downlinkCh:
			if !ok {
				return
			}
			switch event.kind {
			case protocol.DownlinkData:
				if _, err := conn.Write(event.payload); err != nil {
					return
				}
			case protocol.DownlinkClose:
				return
			}
		case <-streamCtx.Done():
			return
		}
	}
}

// runDownlinkLoop reads UDP packets from the server and demultiplexes them to
// the correct SOCKS5 stream by stream ID.
func (s *Service) runDownlinkLoop(ctx context.Context) error {
	buf := make([]byte, 65535)
	for {
		if err := s.downlinkConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		n, _, err := s.downlinkConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isTimeout(err) {
				continue
			}
			return err
		}

		kind, streamID, payload, parseErr := protocol.ParseDownlink(buf[:n])
		if parseErr != nil {
			continue
		}

		s.deliverDownlink(streamID, downlinkEvent{
			kind:    kind,
			payload: append([]byte(nil), payload...),
		})
	}
}

func (s *Service) runInfoLoop(ctx context.Context) error {
	if err := s.sendInfoFrame(); err != nil {
		return err
	}
	ticker := time.NewTicker(s.cfg.InfoInterval.Value())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.sendInfoFrame(); err != nil {
				return err
			}
		}
	}
}

func (s *Service) sendInfoFrame() error {
	localAddr, ok := s.downlinkConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("unexpected downlink local addr type %T", s.downlinkConn.LocalAddr())
	}
	port := localAddr.Port
	if s.cfg.AnnounceReceivePort > 0 {
		port = s.cfg.AnnounceReceivePort
	}

	frame, err := protocol.BuildInfoFrame(protocol.InfoFrame{
		ClientIP:   s.announceIP,
		ClientPort: uint16(port),
		SpoofIP:    s.spoofIP,
		SpoofPort:  uint16(s.cfg.SpoofSourcePort),
	}, s.cfg.InfoSecret)
	if err != nil {
		return err
	}
	return s.sendFrame(frame)
}

func (s *Service) sendFrame(frame []byte) error {
	offset := s.nextOffset.Add(1) - 1

	s.planMu.Lock()
	qnames, nextIndex, err := protocol.BuildQNames(frame, offset, s.clientID, s.plans, s.nextPlanIndex, s.cfg.MaxLabelLen, s.cfg.OffsetWidth)
	if err == nil {
		s.nextPlanIndex = nextIndex
	}
	s.planMu.Unlock()
	if err != nil {
		return err
	}

	for _, qname := range qnames {
		packet := dnswire.BuildQuery(qname, uint16(s.nextQueryID.Add(1)), s.cfg.QueryType)
		for _, target := range s.resolvers.NextN(s.cfg.Duplication) {
			if _, err := s.sendConn.WriteToUDPAddrPort(packet, target.AddrPort()); err != nil {
				return err
			}
			if delay := s.cfg.SendDelay.Value(); delay > 0 {
				time.Sleep(delay)
			}
		}
	}
	return nil
}

func (s *Service) addStream(stream *clientStream) {
	s.streamsMu.Lock()
	s.streams[stream.id] = stream
	s.streamsMu.Unlock()
}

func (s *Service) removeStream(id uint32) {
	s.streamsMu.Lock()
	delete(s.streams, id)
	s.streamsMu.Unlock()
}

// deliverDownlink routes a downlink event to the matching stream (non-blocking).
func (s *Service) deliverDownlink(streamID uint32, event downlinkEvent) {
	s.streamsMu.RLock()
	stream, ok := s.streams[streamID]
	s.streamsMu.RUnlock()
	if !ok {
		return
	}
	select {
	case stream.downlinkCh <- event:
	default:
		// Channel full; drop to avoid blocking the downlink loop.
	}
}

func loadResolvers(cfg config.ClientConfig) ([]resolver.Endpoint, error) {
	combined := make([]resolver.Endpoint, 0, 16)
	seen := map[string]struct{}{}
	addAll := func(items []resolver.Endpoint) {
		for _, item := range items {
			key := item.String()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			combined = append(combined, item)
		}
	}

	if len(cfg.Resolvers) > 0 {
		items, err := resolver.ParseEntries(cfg.Resolvers)
		if err != nil {
			return nil, err
		}
		addAll(items)
	}
	if cfg.ResolversFile != "" {
		items, err := resolver.LoadFile(cfg.ResolversFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		addAll(items)
	}
	if len(combined) == 0 {
		return nil, fmt.Errorf("no resolvers loaded")
	}
	return combined, nil
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}


func New(cfg config.ClientConfig) (*Service, error) {
	if err := cfg.EnsureClientID(); err != nil {
		return nil, err
	}

	resolverEndpoints, err := loadResolvers(cfg)
	if err != nil {
		return nil, err
	}
	resolverPool, err := resolver.NewPool(resolverEndpoints)
	if err != nil {
		return nil, err
	}

	plans, err := protocol.PrepareDomainPlans(cfg.SendDomains, cfg.MaxQNameLen, cfg.MaxLabelLen, cfg.OffsetWidth, cfg.ClientIDLength)
	if err != nil {
		return nil, err
	}

	announceIP, err := netip.ParseAddr(cfg.AnnouncePublicIP)
	if err != nil || !announceIP.Is4() {
		return nil, fmt.Errorf("announce_public_ip must be a valid IPv4 address")
	}
	spoofIP, err := netip.ParseAddr(cfg.SpoofSourceIP)
	if err != nil || !spoofIP.Is4() {
		return nil, fmt.Errorf("spoof_source_ip must be a valid IPv4 address")
	}

	relayAddr, err := net.ResolveUDPAddr("udp", cfg.RelayListen)
	if err != nil {
		return nil, fmt.Errorf("resolve relay_listen: %w", err)
	}
	relayConn, err := net.ListenUDP("udp", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("listen relay: %w", err)
	}

	downlinkAddr, err := net.ResolveUDPAddr("udp", cfg.DownlinkBind)
	if err != nil {
		_ = relayConn.Close()
		return nil, fmt.Errorf("resolve downlink_bind: %w", err)
	}
	downlinkConn, err := net.ListenUDP("udp", downlinkAddr)
	if err != nil {
		_ = relayConn.Close()
		return nil, fmt.Errorf("listen downlink: %w", err)
	}

	sendConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		_ = relayConn.Close()
		_ = downlinkConn.Close()
		return nil, fmt.Errorf("create send socket: %w", err)
	}

	return &Service{
		cfg:          cfg,
		clientID:     cfg.ClientID,
		announceIP:   announceIP,
		spoofIP:      spoofIP,
		resolvers:    resolverPool,
		plans:        plans,
		sendConn:     sendConn,
		relayConn:    relayConn,
		downlinkConn: downlinkConn,
	}, nil
}

func (s *Service) ClientID() string {
	return s.clientID
}

func (s *Service) Run(ctx context.Context) error {
	defer s.close()

	errCh := make(chan error, 3)
	go func() { errCh <- s.runRelayLoop(ctx) }()
	go func() { errCh <- s.runDownlinkLoop(ctx) }()
	go func() { errCh <- s.runInfoLoop(ctx) }()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			if err == nil || errors.Is(err, context.Canceled) {
				continue
			}
			return err
		}
	}
}

func (s *Service) close() {
	if s.sendConn != nil {
		_ = s.sendConn.Close()
	}
	if s.relayConn != nil {
		_ = s.relayConn.Close()
	}
	if s.downlinkConn != nil {
		_ = s.downlinkConn.Close()
	}
}

func (s *Service) runRelayLoop(ctx context.Context) error {
	buf := make([]byte, 65535)
	for {
		if err := s.relayConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		n, addr, err := s.relayConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isTimeout(err) {
				continue
			}
			return err
		}

		payload := append([]byte(nil), buf[:n]...)
		s.setRelayPeer(addr)
		if err := s.sendFrame(protocol.BuildDataFrame(payload)); err != nil {
			return err
		}
	}
}

func (s *Service) runDownlinkLoop(ctx context.Context) error {
	buf := make([]byte, 65535)
	for {
		if err := s.downlinkConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		n, _, err := s.downlinkConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isTimeout(err) {
				continue
			}
			return err
		}

		peer := s.getRelayPeer()
		if peer == nil {
			continue
		}
		if _, err := s.relayConn.WriteToUDP(buf[:n], peer); err != nil {
			return err
		}
	}
}

func (s *Service) runInfoLoop(ctx context.Context) error {
	if err := s.sendInfoFrame(); err != nil {
		return err
	}
	ticker := time.NewTicker(s.cfg.InfoInterval.Value())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.sendInfoFrame(); err != nil {
				return err
			}
		}
	}
}

func (s *Service) sendInfoFrame() error {
	localAddr, ok := s.downlinkConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("unexpected downlink local addr type %T", s.downlinkConn.LocalAddr())
	}
	port := localAddr.Port
	if s.cfg.AnnounceReceivePort > 0 {
		port = s.cfg.AnnounceReceivePort
	}

	frame, err := protocol.BuildInfoFrame(protocol.InfoFrame{
		ClientIP:   s.announceIP,
		ClientPort: uint16(port),
		SpoofIP:    s.spoofIP,
		SpoofPort:  uint16(s.cfg.SpoofSourcePort),
	}, s.cfg.InfoSecret)
	if err != nil {
		return err
	}
	return s.sendFrame(frame)
}

func (s *Service) sendFrame(frame []byte) error {
	offset := s.nextOffset.Add(1) - 1

	s.planMu.Lock()
	qnames, nextIndex, err := protocol.BuildQNames(frame, offset, s.clientID, s.plans, s.nextPlanIndex, s.cfg.MaxLabelLen, s.cfg.OffsetWidth)
	if err == nil {
		s.nextPlanIndex = nextIndex
	}
	s.planMu.Unlock()
	if err != nil {
		return err
	}

	for _, qname := range qnames {
		packet := dnswire.BuildQuery(qname, uint16(s.nextQueryID.Add(1)), s.cfg.QueryType)
		for _, target := range s.resolvers.NextN(s.cfg.Duplication) {
			if _, err := s.sendConn.WriteToUDPAddrPort(packet, target.AddrPort()); err != nil {
				return err
			}
			if delay := s.cfg.SendDelay.Value(); delay > 0 {
				time.Sleep(delay)
			}
		}
	}
	return nil
}

func (s *Service) setRelayPeer(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	copyAddr := *addr
	s.relayPeerMu.Lock()
	s.relayPeer = &copyAddr
	s.relayPeerMu.Unlock()
}

func (s *Service) getRelayPeer() *net.UDPAddr {
	s.relayPeerMu.RLock()
	defer s.relayPeerMu.RUnlock()
	if s.relayPeer == nil {
		return nil
	}
	copyAddr := *s.relayPeer
	return &copyAddr
}

func loadResolvers(cfg config.ClientConfig) ([]resolver.Endpoint, error) {
	combined := make([]resolver.Endpoint, 0, 16)
	seen := map[string]struct{}{}
	addAll := func(items []resolver.Endpoint) {
		for _, item := range items {
			key := item.String()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			combined = append(combined, item)
		}
	}

	if len(cfg.Resolvers) > 0 {
		items, err := resolver.ParseEntries(cfg.Resolvers)
		if err != nil {
			return nil, err
		}
		addAll(items)
	}
	if cfg.ResolversFile != "" {
		items, err := resolver.LoadFile(cfg.ResolversFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		addAll(items)
	}
	if len(combined) == 0 {
		return nil, fmt.Errorf("no resolvers loaded")
	}
	return combined, nil
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
