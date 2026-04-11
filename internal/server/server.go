package server

import (
	"context"
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

type Service struct {
	cfg         config.ServerConfig
	matchers    []protocol.DomainMatcher
	upstream    *net.UDPAddr
	dnsConn     *net.UDPConn
	replyConn   *net.UDPConn
	rawSender   *spoof.RawUDPSender
	sessionMu   sync.Mutex
	sessions    map[string]*session
	sessionTick time.Duration
}

type session struct {
	id        string
	conn      *net.UDPConn
	cancel    context.CancelFunc
	assembler *reassembly.Assembler

	mu       sync.Mutex
	info     protocol.InfoFrame
	hasInfo  bool
	lastSeen time.Time
}

func New(cfg config.ServerConfig) (*Service, error) {
	matchers, err := protocol.PrepareMatchers(cfg.AllowedDomains)
	if err != nil {
		return nil, err
	}
	upstreamAddr, err := net.ResolveUDPAddr("udp", cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("resolve upstream: %w", err)
	}
	sweepEvery := cfg.SessionIdle.Value() / 2
	if sweepEvery < 5*time.Second {
		sweepEvery = 5 * time.Second
	}
	return &Service{
		cfg:         cfg,
		matchers:    matchers,
		upstream:    upstreamAddr,
		sessions:    make(map[string]*session),
		sessionTick: sweepEvery,
	}, nil
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
		_ = sess.conn.Close()
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
					if err := sess.sendUpstream(payload, s.upstream); err != nil {
						return err
					}
				}
			}
		}
	}

	response := dnswire.CreateEmptyNoErrorResponse(query.ID, query.Flags, query.Question)
	_, err = s.dnsConn.WriteToUDP(response, addr)
	return err
}

func (s *Service) getOrCreateSession(parent context.Context, id string) (*session, error) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	if existing := s.sessions[id]; existing != nil {
		return existing, nil
	}

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	childCtx, cancel := context.WithCancel(parent)
	sess := &session{
		id:        id,
		conn:      conn,
		cancel:    cancel,
		assembler: reassembly.New(s.cfg.ReassemblyTimeout.Value()),
		lastSeen:  time.Now(),
	}
	s.sessions[id] = sess
	go s.runSessionLoop(childCtx, sess)
	return sess, nil
}

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
		_ = sess.conn.Close()
	}
}

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

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
