package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/blackestwhite/masterdns-qs-tunnel/internal/base32x"
	"github.com/blackestwhite/masterdns-qs-tunnel/internal/config"
	"github.com/blackestwhite/masterdns-qs-tunnel/internal/dnswire"
	"github.com/blackestwhite/masterdns-qs-tunnel/internal/protocol"
	"github.com/blackestwhite/masterdns-qs-tunnel/internal/reassembly"
	"github.com/blackestwhite/masterdns-qs-tunnel/internal/spoof"
)

const (
	// streamReadBufferSize is the TCP read buffer size used when pumping a proxied stream.
	streamReadBufferSize = 4096
)

type Service struct {
	cfg         config.ServerConfig
	matchers    []protocol.DomainMatcher
	upstream    *net.UDPAddr // nil in direct-TCP mode
	dnsConn     *net.UDPConn
	replyConn   *net.UDPConn
	rawSender   *spoof.RawUDPSender
	sessionMu   sync.Mutex
	sessions    map[string]*session
	sessionTick time.Duration
}

// session holds per-client state including its stream table.
type session struct {
	id        string
	cancel    context.CancelFunc
	assembler *reassembly.Assembler

	mu       sync.Mutex
	info     protocol.InfoFrame
	hasInfo  bool
	lastSeen time.Time

	// legacy upstream mode: single UDP conn
	conn *net.UDPConn

	// direct-TCP mode: per-stream TCP connections
	streamMu sync.Mutex
	streams  map[uint32]*serverStream
}

// serverStream tracks one proxied TCP connection on the server side.
type serverStream struct {
	id     uint32
	conn   net.Conn
	cancel context.CancelFunc
}

func New(cfg config.ServerConfig) (*Service, error) {
	matchers, err := protocol.PrepareMatchers(cfg.AllowedDomains)
	if err != nil {
		return nil, err
	}

	sweepEvery := cfg.SessionIdle.Value() / 2
	if sweepEvery < 5*time.Second {
		sweepEvery = 5 * time.Second
	}

	svc := &Service{
		cfg:         cfg,
		matchers:    matchers,
		sessions:    make(map[string]*session),
		sessionTick: sweepEvery,
	}

	// Legacy upstream mode: only when upstream is non-empty.
	if cfg.Upstream != "" {
		upstreamAddr, err := net.ResolveUDPAddr("udp", cfg.Upstream)
		if err != nil {
			return nil, fmt.Errorf("resolve upstream: %w", err)
		}
		svc.upstream = upstreamAddr
	}

	return svc, nil
}

func (s *Service) Run(ctx context.Context) error {
	dnsAddr, err := net.ResolveUDPAddr("udp", s.cfg.Listen)
	if err != nil {
		return err
	}
	s.dnsConn, err = net.ListenUDP("udp", dnsAddr)
	if err != nil {
		return err
	}
	defer s.close()

	if s.cfg.UseRawSpoofing {
		s.rawSender, err = spoof.NewRawUDPSender()
		if err != nil {
			return fmt.Errorf("create raw spoof sender: %w", err)
		}
	} else {
		s.replyConn, err = net.ListenUDP("udp", nil)
		if err != nil {
			return fmt.Errorf("create reply socket: %w", err)
		}
	}

	go s.runSweeper(ctx)

	buf := make([]byte, 65535)
	for {
		if err := s.dnsConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		n, addr, err := s.dnsConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isTimeout(err) {
				continue
			}
			return err
		}
		packet := append([]byte(nil), buf[:n]...)
		if err := s.handleDNSPacket(ctx, packet, addr); err != nil {
			return err
		}
	}
}

func (s *Service) close() {
	if s.dnsConn != nil {
		_ = s.dnsConn.Close()
	}
	if s.replyConn != nil {
		_ = s.replyConn.Close()
	}
	if s.rawSender != nil {
		_ = s.rawSender.Close()
	}

	s.sessionMu.Lock()
	sessions := make([]*session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.sessions = map[string]*session{}
	s.sessionMu.Unlock()

	for _, sess := range sessions {
		sess.cancel()
		if sess.conn != nil {
			_ = sess.conn.Close()
		}
		sess.closeAllStreams()
	}
}

func (s *Service) handleDNSPacket(ctx context.Context, packet []byte, addr *net.UDPAddr) error {
	query, err := dnswire.ParseQuery(packet)
	if err != nil {
		return nil
	}
	matcher, suffixLen, ok := protocol.MatchDomain(query.Labels, s.matchers)
	if !ok {
		return nil
	}

	chunk, err := protocol.ParseChunk(query.Labels, matcher, suffixLen, s.cfg.ClientIDLength, s.cfg.OffsetWidth)
	if err != nil {
		return nil
	}

	sess, err := s.getOrCreateSession(ctx, chunk.ClientID)
	if err != nil {
		return err
	}
	sess.touch()

	assembled, complete, err := sess.assembler.Add(chunk.Offset, chunk.FragmentIndex, chunk.Last, chunk.EncodedData)
	if err != nil {
		return nil
	}
	if complete {
		frame, err := base32x.DecodeLowerNoPadding(assembled)
		if err == nil {
			kind, payload, err := protocol.ParseFrame(frame)
			if err == nil {
				switch kind {
				case protocol.FrameInfo:
					info, err := protocol.ParseInfoFrame(payload, s.cfg.InfoSecret)
					if err == nil {
						sess.setInfo(info)
					}
				case protocol.FrameData:
					// Legacy mode: forward raw payload to upstream UDP.
					if s.upstream != nil {
						if err := sess.sendUpstream(payload, s.upstream); err != nil {
							return err
						}
					}
				case protocol.FrameConnect:
					streamID, host, port, err := protocol.ParseConnectPayload(payload)
					if err == nil {
						s.handleConnect(ctx, sess, streamID, host, port)
					}
				case protocol.FrameStreamData:
					streamID, data, err := protocol.ParseStreamDataPayload(payload)
					if err == nil {
						sess.writeToStream(streamID, data)
					}
				case protocol.FrameStreamFin:
					streamID, err := protocol.ParseStreamFinPayload(payload)
					if err == nil {
						sess.closeStream(streamID)
					}
				}
			}
		}
	}

	response := dnswire.CreateEmptyNoErrorResponse(query.ID, query.Flags, query.Question)
	_, err = s.dnsConn.WriteToUDP(response, addr)
	return err
}

// handleConnect dials TCP to host:port and starts the stream reader goroutine.
func (s *Service) handleConnect(ctx context.Context, sess *session, streamID uint32, host string, port uint16) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		// Notify client that the connection failed.
		info, ok := sess.snapshotInfo()
		if ok {
			s.sendDownlink(protocol.FrameStreamFin, streamID, nil, info)
		}
		return
	}

	streamCtx, cancel := context.WithCancel(ctx)
	st := &serverStream{
		id:     streamID,
		conn:   conn,
		cancel: cancel,
	}
	sess.addStream(st)

	go s.runStreamReader(streamCtx, sess, st)
}

// runStreamReader reads from the TCP connection and sends data back to the
// client as downlink UDP packets: [kind:1][stream_id:4][data...]
func (s *Service) runStreamReader(ctx context.Context, sess *session, st *serverStream) {
	defer func() {
		sess.removeStream(st.id)
		_ = st.conn.Close()
		st.cancel()
		// Notify client that this stream has ended.
		info, ok := sess.snapshotInfo()
		if ok {
			s.sendDownlink(protocol.FrameStreamFin, st.id, nil, info)
		}
	}()

	buf := make([]byte, streamReadBufferSize)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = st.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := st.conn.Read(buf)
		if n > 0 {
			info, ok := sess.snapshotInfo()
			if ok {
				data := make([]byte, n)
				copy(data, buf[:n])
				s.sendDownlink(protocol.FrameStreamData, st.id, data, info)
			}
		}
		if err != nil {
			return
		}
	}
}

// sendDownlink sends a framed downlink UDP packet to the client.
// Packet format: [kind:1][stream_id:4][data...]
func (s *Service) sendDownlink(kind protocol.FrameKind, streamID uint32, data []byte, info protocol.InfoFrame) {
	pkt := make([]byte, 1+4+len(data))
	pkt[0] = byte(kind)
	binary.BigEndian.PutUint32(pkt[1:5], streamID)
	copy(pkt[5:], data)

	if s.rawSender != nil {
		_ = s.rawSender.SendUDP(pkt, info.SpoofIP, info.SpoofPort, info.ClientIP, info.ClientPort, s.cfg.ReplyTTL)
	} else if s.replyConn != nil {
		dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(info.ClientIP, info.ClientPort))
		_, _ = s.replyConn.WriteToUDP(pkt, dst)
	}
}

func (s *Service) getOrCreateSession(parent context.Context, id string) (*session, error) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	if existing := s.sessions[id]; existing != nil {
		return existing, nil
	}

	childCtx, cancel := context.WithCancel(parent)
	sess := &session{
		id:        id,
		cancel:    cancel,
		assembler: reassembly.New(s.cfg.ReassemblyTimeout.Value()),
		lastSeen:  time.Now(),
		streams:   make(map[uint32]*serverStream),
	}

	// Legacy mode: open a per-session UDP socket to forward to upstream.
	if s.upstream != nil {
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			cancel()
			return nil, err
		}
		sess.conn = conn
		go s.runSessionLoop(childCtx, sess)
	}

	s.sessions[id] = sess
	return sess, nil
}

// runSessionLoop handles the legacy upstream UDP mode.
func (s *Service) runSessionLoop(ctx context.Context, sess *session) {
	buf := make([]byte, 65535)
	for {
		if err := sess.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return
		}
		n, _, err := sess.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if isTimeout(err) {
				continue
			}
			return
		}

		info, ok := sess.snapshotInfo()
		if !ok {
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		if s.rawSender != nil {
			if err := s.rawSender.SendUDP(payload, info.SpoofIP, info.SpoofPort, info.ClientIP, info.ClientPort, s.cfg.ReplyTTL); err != nil {
				continue
			}
		} else {
			dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(info.ClientIP, info.ClientPort))
			if _, err := s.replyConn.WriteToUDP(payload, dst); err != nil {
				continue
			}
		}
		sess.touch()
	}
}

func (s *Service) runSweeper(ctx context.Context) {
	ticker := time.NewTicker(s.sessionTick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.pruneSessions(now)
		}
	}
}

func (s *Service) pruneSessions(now time.Time) {
	s.sessionMu.Lock()
	stale := make([]*session, 0)
	for id, sess := range s.sessions {
		if now.Sub(sess.lastActivity()) > s.cfg.SessionIdle.Value() {
			delete(s.sessions, id)
			stale = append(stale, sess)
		}
	}
	s.sessionMu.Unlock()

	for _, sess := range stale {
		sess.cancel()
		if sess.conn != nil {
			_ = sess.conn.Close()
		}
		sess.closeAllStreams()
	}
}

// ── session helpers ──────────────────────────────────────────────────────────

func (s *session) touch() {
	s.mu.Lock()
	s.lastSeen = time.Now()
	s.mu.Unlock()
}

func (s *session) lastActivity() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeen
}

func (s *session) setInfo(info protocol.InfoFrame) {
	s.mu.Lock()
	s.info = info
	s.hasInfo = true
	s.lastSeen = time.Now()
	s.mu.Unlock()
}

func (s *session) snapshotInfo() (protocol.InfoFrame, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info, s.hasInfo
}

func (s *session) sendUpstream(payload []byte, upstream *net.UDPAddr) error {
	if err := s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	_, err := s.conn.WriteToUDP(payload, upstream)
	return err
}

// ── stream management ────────────────────────────────────────────────────────

func (s *session) addStream(st *serverStream) {
	s.streamMu.Lock()
	s.streams[st.id] = st
	s.streamMu.Unlock()
}

func (s *session) removeStream(id uint32) {
	s.streamMu.Lock()
	delete(s.streams, id)
	s.streamMu.Unlock()
}

func (s *session) writeToStream(id uint32, data []byte) {
	s.streamMu.Lock()
	st := s.streams[id]
	s.streamMu.Unlock()
	if st == nil {
		return
	}
	_ = st.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = st.conn.Write(data)
}

func (s *session) closeStream(id uint32) {
	s.streamMu.Lock()
	st := s.streams[id]
	if st != nil {
		delete(s.streams, id)
	}
	s.streamMu.Unlock()
	if st != nil {
		st.cancel()
		_ = st.conn.Close()
	}
}

func (s *session) closeAllStreams() {
	s.streamMu.Lock()
	streams := make([]*serverStream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.streams = make(map[uint32]*serverStream)
	s.streamMu.Unlock()

	for _, st := range streams {
		st.cancel()
		_ = st.conn.Close()
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

