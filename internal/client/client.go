package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
)

const (
	// streamReadBufferSize is the TCP read buffer size used when pumping a proxied stream.
	streamReadBufferSize = 4096
	// streamInboxCapacity is the number of downlink packets buffered per stream before backpressure.
	streamInboxCapacity = 64
)
type streamEntry struct {
	id    uint32
	inbox chan []byte  // buffered downlink data for this stream
	finCh chan struct{} // closed when the server sends FrameStreamFin
	done  chan struct{} // closed when the local SOCKS5 connection is torn down
}

type Service struct {
	cfg           config.ClientConfig
	clientID      string
	announceIP    netip.Addr
	spoofIP       netip.Addr
	resolvers     *resolver.Pool
	plans         []protocol.DomainPlan
	sendConn      *net.UDPConn
	relayConn     *net.UDPConn
	downlinkConn  *net.UDPConn
	nextQueryID   atomic.Uint32
	nextOffset    atomic.Uint64
	nextStreamID  atomic.Uint32
	planMu        sync.Mutex
	nextPlanIndex int
	// legacy UDP relay
	relayPeerMu sync.RWMutex
	relayPeer   *net.UDPAddr
	// SOCKS5 stream registry
	streamMu sync.RWMutex
	streams  map[uint32]*streamEntry
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

	downlinkAddr, err := net.ResolveUDPAddr("udp", cfg.DownlinkBind)
	if err != nil {
		return nil, fmt.Errorf("resolve downlink_bind: %w", err)
	}
	downlinkConn, err := net.ListenUDP("udp", downlinkAddr)
	if err != nil {
		return nil, fmt.Errorf("listen downlink: %w", err)
	}

	sendConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		_ = downlinkConn.Close()
		return nil, fmt.Errorf("create send socket: %w", err)
	}

	svc := &Service{
		cfg:          cfg,
		clientID:     cfg.ClientID,
		announceIP:   announceIP,
		spoofIP:      spoofIP,
		resolvers:    resolverPool,
		plans:        plans,
		sendConn:     sendConn,
		downlinkConn: downlinkConn,
		streams:      make(map[uint32]*streamEntry),
	}

	// Legacy UDP relay (only when relay_listen is set and socks5_listen is not)
	if cfg.Socks5Listen == "" && cfg.RelayListen != "" {
		relayAddr, err := net.ResolveUDPAddr("udp", cfg.RelayListen)
		if err != nil {
			_ = downlinkConn.Close()
			_ = sendConn.Close()
			return nil, fmt.Errorf("resolve relay_listen: %w", err)
		}
		relayConn, err := net.ListenUDP("udp", relayAddr)
		if err != nil {
			_ = downlinkConn.Close()
			_ = sendConn.Close()
			return nil, fmt.Errorf("listen relay: %w", err)
		}
		svc.relayConn = relayConn
	}

	return svc, nil
}

func (s *Service) ClientID() string {
	return s.clientID
}

func (s *Service) Run(ctx context.Context) error {
	defer s.close()

	errCh := make(chan error, 4)

	if s.cfg.Socks5Listen != "" {
		// SOCKS5 proxy mode
		ln, err := net.Listen("tcp", s.cfg.Socks5Listen)
		if err != nil {
			return fmt.Errorf("listen socks5: %w", err)
		}
		go func() { errCh <- s.runSocks5Acceptor(ctx, ln) }()
		go func() { errCh <- s.runDownlinkLoopStreamed(ctx) }()
	} else {
		// Legacy UDP relay mode
		go func() { errCh <- s.runRelayLoop(ctx) }()
		go func() { errCh <- s.runDownlinkLoopRelay(ctx) }()
	}

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

// ── SOCKS5 mode ──────────────────────────────────────────────────────────────

// runSocks5Acceptor accepts TCP connections and spawns a handler per connection.
func (s *Service) runSocks5Acceptor(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleSocks5Conn(ctx, conn)
	}
}

// handleSocks5Conn performs the SOCKS5 handshake, then tunnels the TCP stream.
func (s *Service) handleSocks5Conn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	host, port, err := socks5Handshake(conn)
	if err != nil {
		return
	}

	streamID := s.nextStreamID.Add(1)

	entry := &streamEntry{
		id:    streamID,
		inbox: make(chan []byte, streamInboxCapacity),
		finCh: make(chan struct{}),
		done:  make(chan struct{}),
	}
	s.registerStream(entry)
	defer func() {
		s.unregisterStream(streamID)
		close(entry.done)
	}()

	// Tell the server to open a TCP connection to the destination.
	if err := s.sendFrame(protocol.BuildConnectFrame(streamID, host, port)); err != nil {
		return
	}

	// Reply success to the SOCKS5 client optimistically.
	if err := socks5SendSuccess(conn); err != nil {
		_ = s.sendFrame(protocol.BuildStreamFinFrame(streamID))
		return
	}

	// Half-duplex pump: client→server (reads TCP, sends FrameStreamData over DNS).
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		buf := make([]byte, streamReadBufferSize)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				if sendErr := s.sendFrame(protocol.BuildStreamDataFrame(streamID, chunk)); sendErr != nil {
					return
				}
			}
			if err != nil {
				_ = s.sendFrame(protocol.BuildStreamFinFrame(streamID))
				return
			}
		}
	}()

	// Half-duplex pump: server→client (receives downlink data, writes to TCP).
	for {
		select {
		case data := <-entry.inbox:
			if _, err := conn.Write(data); err != nil {
				return
			}
		case <-entry.finCh:
			// Server closed its end; drain any remaining inbox then close.
			for {
				select {
				case data := <-entry.inbox:
					_, _ = conn.Write(data)
				default:
					return
				}
			}
		case <-sendDone:
			return
		case <-ctx.Done():
			return
		}
	}
}

// runDownlinkLoopStreamed receives UDP downlink packets that carry stream IDs
// and routes them to the appropriate SOCKS5 connection.
//
// Downlink packet format (server → client):
//
//	[kind:1][stream_id:4][data...]
//
// kind=4 (FrameStreamData) or kind=5 (FrameStreamFin)
func (s *Service) runDownlinkLoopStreamed(ctx context.Context) error {
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
		if n < 5 {
			continue
		}
		kind := protocol.FrameKind(buf[0])
		streamID := binary.BigEndian.Uint32(buf[1:5])
		entry := s.lookupStream(streamID)
		if entry == nil {
			continue
		}
		switch kind {
		case protocol.FrameStreamData:
			data := make([]byte, n-5)
			copy(data, buf[5:n])
			select {
			case entry.inbox <- data:
			case <-entry.done:
			}
		case protocol.FrameStreamFin:
			select {
			case <-entry.finCh:
			default:
				close(entry.finCh)
			}
		}
	}
}

func (s *Service) registerStream(e *streamEntry) {
	s.streamMu.Lock()
	s.streams[e.id] = e
	s.streamMu.Unlock()
}

func (s *Service) unregisterStream(id uint32) {
	s.streamMu.Lock()
	delete(s.streams, id)
	s.streamMu.Unlock()
}

func (s *Service) lookupStream(id uint32) *streamEntry {
	s.streamMu.RLock()
	e := s.streams[id]
	s.streamMu.RUnlock()
	return e
}

// ── Legacy UDP relay mode ────────────────────────────────────────────────────

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

func (s *Service) runDownlinkLoopRelay(ctx context.Context) error {
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

// ── Shared helpers ───────────────────────────────────────────────────────────

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

// ── SOCKS5 protocol helpers ──────────────────────────────────────────────────

// socks5Handshake performs the SOCKS5 negotiation and returns the destination
// host and port from the CONNECT request.
func socks5Handshake(conn net.Conn) (host string, port uint16, err error) {
	// Phase 1: method negotiation
	header := make([]byte, 2)
	if _, err = io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		err = fmt.Errorf("not a SOCKS5 handshake")
		return
	}
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err = io.ReadFull(conn, methods); err != nil {
		return
	}
	// Accept no-auth (method 0) only.
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Phase 2: CONNECT request
	req := make([]byte, 4)
	if _, err = io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		err = fmt.Errorf("unsupported SOCKS5 command %d", req[1])
		return
	}
	switch req[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err = io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 0x03: // domain name
		lenByte := make([]byte, 1)
		if _, err = io.ReadFull(conn, lenByte); err != nil {
			return
		}
		domain := make([]byte, int(lenByte[0]))
		if _, err = io.ReadFull(conn, domain); err != nil {
			return
		}
		host = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err = io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		err = fmt.Errorf("unsupported SOCKS5 address type %d", req[3])
		return
	}
	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBytes); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(portBytes)
	return
}

// socks5SendSuccess sends a SOCKS5 success reply to the client.
func socks5SendSuccess(conn net.Conn) error {
	// VER=5, REP=0 (success), RSV=0, ATYP=1 (IPv4), BND.ADDR=0.0.0.0, BND.PORT=0
	_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return err
}

// ── Resolver loading ─────────────────────────────────────────────────────────

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

