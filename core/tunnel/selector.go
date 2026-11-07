package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"sync/atomic"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"github.com/nekoskin/whispera/core/protocol/quic"
	"github.com/nekoskin/whispera/core/transport/grpc"

	quicgo "github.com/quic-go/quic-go"
)

func poisonEnabled() bool { return os.Getenv("WHISPERA_POISON") == "1" }

type poisonState struct {
	mu        sync.Mutex
	rng       *mrand.Rand
	countdown int
}

var poison = &poisonState{rng: mrand.New(mrand.NewSource(time.Now().UnixNano())), countdown: -1}

func (p *poisonState) drawGap() int {
	lo, hi := 15, 120
	if v := os.Getenv("WHISPERA_POISON_GAP"); v != "" {
		if i := strings.IndexByte(v, ','); i > 0 {
			if a, err := strconv.Atoi(v[:i]); err == nil {
				if b, err := strconv.Atoi(v[i+1:]); err == nil && a >= 1 && b >= a {
					lo, hi = a, b
				}
			}
		}
	}
	return lo + p.rng.Intn(hi-lo+1)
}

func poisonPreset(current, presets int) (int, bool) {
	if !poisonEnabled() || presets < 2 {
		return 0, false
	}
	poison.mu.Lock()
	defer poison.mu.Unlock()
	if poison.countdown < 0 {
		poison.countdown = poison.drawGap()
		return 0, false
	}
	if poison.countdown > 0 {
		poison.countdown--
		return 0, false
	}
	poison.countdown = poison.drawGap()
	alt := poison.rng.Intn(presets - 1)
	if alt >= current {
		alt++
	}
	return alt, true
}

const altTransportSessionIDLen = 8

func sendAltTransportAuth(conn net.Conn, psk []byte) error {
	if len(psk) != 32 {
		conn.Close()
		return fmt.Errorf("alt transport auth: PSK not available")
	}
	sessionID := make([]byte, altTransportSessionIDLen)
	if _, err := rand.Read(sessionID); err != nil {
		conn.Close()
		return err
	}
	token := protocol.ClientAuthToken(psk, sessionID)
	hdr := make([]byte, 1+altTransportSessionIDLen+2+len(token))
	hdr[0] = byte(altTransportSessionIDLen)
	copy(hdr[1:1+altTransportSessionIDLen], sessionID)
	binary.BigEndian.PutUint16(hdr[1+altTransportSessionIDLen:1+altTransportSessionIDLen+2], uint16(len(token)))
	copy(hdr[1+altTransportSessionIDLen+2:], token)
	if _, err := conn.Write(hdr); err != nil {
		conn.Close()
		return err
	}
	return nil
}

const datagramDialTimeout = 15 * time.Second

type datagramLane struct {
	mu      sync.Mutex
	quicGD  *quic.DatagramClient
	quic    *protocol.QUICLane
	dialing chan struct{}
}

var errNoQUICLane = errors.New("whispera: no QUIC lane to the server")

var closedChan = func() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}()

type selector struct {
	m *Manager

	sessionCache any
	lane         datagramLane
	strategy     *protocol.HandshakeStrategy
	wanted       atomic.Pointer[protocol.ConnLevers]
}

type resumedArmKey struct{}

func withResumedArm(ctx context.Context, arm int) context.Context {
	return context.WithValue(ctx, resumedArmKey{}, arm)
}

func resumedArm(ctx context.Context) (int, bool) {
	arm, ok := ctx.Value(resumedArmKey{}).(int)
	return arm, ok
}

func armLevers(arm, presets int) *protocol.ConnLevers {
	return &protocol.ConnLevers{Migrate: protocol.JointArmMigrates(arm, presets), Shaped: protocol.JointArmShaped(arm, presets)}
}

func (s *selector) preferLevers(ctx string, presets int, fragmented, migrate bool) {
	arm, ok := s.strategy.SelectJointOnline(ctx, presets, fragmented, migrate)
	if _, pinned := pinnedArm(arm, presets); ok && !pinned {
		s.wanted.Store(armLevers(arm, presets))
	}
}

func (s *selector) leversFit(c net.Conn) bool {
	want := s.wanted.Load()
	if want == nil {
		return true
	}
	have, _ := protocol.LeversOf(c)
	return have == *want
}

func newSelector(m *Manager) *selector {
	strategy := m.config.HandshakeStrategy
	if strategy == nil {
		strategy = protocol.NewHandshakeStrategy()
	}
	return &selector{
		m:            m,
		sessionCache: protocol.SharedSessionCache(),
		strategy:     strategy,
	}
}

func (s *selector) serverTarget() (addr, sni string) {
	addr = s.m.config.WhisperaAddr
	if addr == "" {
		addr = s.m.config.ServerAddr
	}
	sni = s.m.config.WhisperaSNI
	if net.ParseIP(sni) != nil {
		sni = ""
	}
	return addr, sni
}

func (s *selector) serverAddr(ctx context.Context) (string, bool) {
	addr, _ := s.serverTarget()
	if s.m.dialsIPv6(ctx) {
		return s.m.onIPv6(addr), true
	}
	return addr, false
}

func (s *selector) whisperaDial() (func(context.Context) (net.Conn, error), bool) {
	m := s.m
	if !m.config.EnableWhispera || len(m.config.WhisperaSecret) == 0 {
		return nil, false
	}
	addr, sni := s.serverTarget()
	var tcpDialer func(context.Context, string, string) (net.Conn, error)
	if m.asnBypassDialer != nil {
		tcpDialer = m.asnBypassDialer.DialTCP
	}
	cCfg := &protocol.ClientConfig{
		ServerAddr:    addr,
		ServerName:    sni,
		SharedSecret:  m.config.WhisperaSecret,
		ServerCertPin: m.config.WhisperaCertPin,
		ServerIDPub:   m.config.WhisperaIDPub,
		ServerSelPub:  m.config.WhisperaSelPub,
		DropECH:       m.config.DropECH,
		SessionCache:  s.sessionCache,
		TCPDialer:     tcpDialer,
		Control:       bindDefaultRoute,
	}
	strategy := s.strategy
	fragDialer := m.asnBypassDialer
	if m.config.TLSFragmentCount > 0 {
		fragDialer = nil
	}
	fragmented := fragDialer != nil && fragDialer.Fragmenting()
	return func(ctx context.Context) (net.Conn, error) {
		c := *cCfg
		addr, overIPv6 := s.serverAddr(ctx)
		c.ServerAddr = addr
		if c.ServerSelPub == "" {
			c.ServerSelPub = protocol.LearnedSelPub(c.ServerIDPub)
		}
		c.OnServerSelPub = func(selPub string) {
			protocol.RememberSelPub(c.ServerIDPub, selPub)
		}
		presets := fingerprint.PresetCount()
		network := networkKey(ctx, addr)
		jointCtx := armContext(sni, network, "joint")
		helloKey := armContext(sni, addr, "hello")

		release, err := sharedHellos.admit(ctx, helloKey, func() bool {
			return strategy.JointAnyAlive(jointCtx, presets, fragmented)
		})
		if err != nil {
			return nil, err
		}
		defer release()
		mark, err := sharedHellos.start(ctx, helloKey)
		if err != nil {
			return nil, err
		}
		strategy.SetJointChain(jointCtx, mark.pos, mark.gap)
		migrate := !chainGuarded(ctx) && !sharedHellos.limited(helloKey)

		a, resuming := resumedArm(ctx)
		onlineChose, isPinned := resuming, false
		if !resuming {
			a, onlineChose = strategy.SelectJointOnline(jointCtx, presets, fragmented, migrate)
			a, isPinned = pinnedArm(a, presets)
		}
		jointArm := a
		preset, budget := protocol.JointArmParts(a, presets)
		c.DropPQ = protocol.JointArmDropPQ(a, presets)
		if onlineChose || isPinned {
			c.Levers = armLevers(a, presets)
		}
		if onlineChose && !isPinned && !resuming {
			s.wanted.Store(c.Levers)
		}
		if alt, ok := poisonPreset(preset, presets); ok && !isPinned && !resuming {
			budget, jointArm = 1, -1
			c.HelloID = fingerprint.PresetAt(alt)
		} else {
			c.HelloID = fingerprint.PresetAt(preset)
			if onlineChose && !resuming && strategy.JointAliveArms(jointCtx, presets, fragmented) > 1 {
				c.HandshakeTimeout = protocol.FastRotateHandshakeTimeout
			}
			if fragmented {
				c.TCPDialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return fragDialer.DialTCPWithFragments(ctx, network, addr, budget)
				}
			}
		}

		c.Arm = jointArm
		gene, geneUsed := applyGene(&c, fragDialer)

		var flowLocal, flowRemote net.Addr
		var flowConnect time.Duration
		var dialID atomic.Uint64
		var netSet string
		predicted := strategy.JointPredict(jointCtx, jointArm)
		trace := func(result protocol.HandshakeResult, stage string, latency time.Duration, symptom protocol.Symptom, down int64, wire protocol.WireVerdict, measure protocol.DialMeasure) {
			if jointArm >= 0 && !resuming {
				trust, check := strategy.JointTrust(jointCtx)
				recordDial(dialRow{ctx: jointCtx, arm: jointArm, result: result, stage: stage, latency: latency, connect: flowConnect, symptom: symptom, down: down, wire: wire, measure: measure, trust: trust, check: check, set: netSet, predict: predicted})
			}
		}
		liveDeath := func(down int64, lived time.Duration, tail []protocol.WirePacket) {
			if id := dialID.Load(); id != 0 {
				strategy.NoteJointLiveDeath(jointCtx, id, down, lived, tail)
				s.preferLevers(jointCtx, presets, fragmented, migrate && !sharedHellos.limited(helloKey))
			}
		}

		observe := func(result protocol.HandshakeResult, symptom protocol.Symptom, latency time.Duration, wire protocol.WireVerdict, measure protocol.DialMeasure) {
			if result == protocol.HandshakeLocal {
				trace(result, dialStageHandshake, latency, symptom, 0, wire, measure)
				return
			}
			if geneUsed {
				observeGene(gene, result == protocol.HandshakeOK)
			}
			if jointArm < 0 || resuming {
				return
			}
			dialID.Store(strategy.NoteJointOnline(jointCtx, jointArm, protocol.DialNote{
				Alive:   result == protocol.HandshakeOK,
				Strong:  protocol.HandshakeBlocked(result),
				Wire:    wire,
				Slow:    protocol.PolicySlowness(latency, flowConnect),
				Measure: measure,
			}))
			trace(result, dialStageHandshake, latency, symptom, 0, wire, measure)
		}

		netArm := onlineChose && jointArm >= 0
		choice := dialChoice{
			fingerprint:    c.HelloID.Str(),
			netFingerprint: netArm && !isPinned,
			netRecords:     netArm && fragmented,
			netDropPQ:      netArm && !fingerprint.DropPQEnabled(),
		}
		netSet = netSetFields(choice, jointArm, presets, netArm && !isPinned)
		c.OnConnected = func(local, remote net.Addr, connect time.Duration) {
			flowLocal, flowRemote, flowConnect = local, remote, connect
			sharedWire.watch(local, remote, choice)
		}
		c.OnHelloSent = func() { sharedHellos.sent(helloKey) }
		handshake, connectFailed := protocol.HandshakeLocal, false
		c.OnHandshake = func(result protocol.HandshakeResult, symptom protocol.Symptom, latency time.Duration) {
			handshake = result
			wire, measure, frames := sharedWire.settle(flowLocal, flowRemote, flowConnect, result == protocol.HandshakeOK)
			measure.ChainPos, measure.ChainGap = mark.pos, mark.gap
			observe(result, symptom, latency, wire, measure)
			switch result {
			case protocol.HandshakeOK:
				m.clearFailure()
			case protocol.HandshakeLocal:
			default:
				pattern := noteBlockPattern(protocol.DialHandshakeDead, wire, measure.Packets, frames)
				m.noteFailure(FailureCause{Cause: CauseHandshakeBlocked, Symptom: string(symptom), Wire: wire.String(), Pattern: pattern, AtMs: time.Now().UnixMilli()})
			}
		}
		c.OnConnectFail = func(result protocol.HandshakeResult, symptom protocol.Symptom, latency time.Duration) {
			connectFailed = true
			if cause, known := connectFailure(symptom); known {
				m.noteFailure(cause)
			}
			trace(result, dialStageConnect, latency, symptom, 0, protocol.WireNoSignature, protocol.DialMeasure{})
		}
		c.OnLiveReset = func() {
			tail, frames := sharedWire.tail(flowLocal, flowRemote)
			liveDeath(0, 0, tail)
			pattern := noteBlockPattern(protocol.DialLiveDead, protocol.WireNoSignature, tail, frames)
			m.noteFailure(FailureCause{Cause: CauseLiveBlocked, Symptom: string(protocol.SymptomLiveReset), Pattern: pattern, AtMs: time.Now().UnixMilli()})
			trace(protocol.HandshakeResetFast, dialStageLiveReset, 0, protocol.SymptomLiveReset, 0, protocol.WireNoSignature, protocol.DialMeasure{Packets: tail})
		}
		c.OnLiveEnd = func(end protocol.LiveEnd) {
			if !end.Stalled || end.Reset {
				sharedWire.drop(flowLocal, flowRemote)
				return
			}
			tail, frames := sharedWire.tail(flowLocal, flowRemote)
			if end.Symptom() == protocol.SymptomStallVolume {
				liveDeath(end.Down, end.Dur, tail)
				pattern := noteBlockPattern(protocol.DialLiveDead, protocol.WireNoSignature, tail, frames)
				m.noteFailure(FailureCause{Cause: CauseLiveBlocked, Symptom: string(end.Symptom()), Pattern: pattern, Down: end.Down, AtMs: time.Now().UnixMilli()})
			}
			trace(protocol.HandshakeIncomplete, dialStageLiveEnd, end.Dur, end.Symptom(), end.Down, protocol.WireNoSignature, protocol.DialMeasure{Packets: tail})
		}
		conn, err := protocol.Client(ctx, &c)
		sharedHellos.settle(helloKey, mark, handshake, connectFailed)
		if err == nil {
			m.noteServerAnswered(overIPv6)
		} else if !errors.Is(ctx.Err(), context.Canceled) {
			m.noteDialFailed(overIPv6, connectFailed, sharedHellos.failed(helloKey) && strategy.JointAliveArms(jointCtx, presets, fragmented) == 0)
		}
		return conn, err
	}, true
}

func (s *selector) startDatagramLane() { s.laneDial() }

func (s *selector) currentLane() *protocol.QUICLane {
	s.lane.mu.Lock()
	defer s.lane.mu.Unlock()
	return s.lane.quic
}

func (s *selector) quicLane(ctx context.Context) (*protocol.QUICLane, error) {
	if lane := s.currentLane(); lane != nil {
		return lane, nil
	}
	done, ok := s.laneDial()
	if !ok {
		return nil, errNoQUICLane
	}
	select {
	case <-done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if lane := s.currentLane(); lane != nil {
		return lane, nil
	}
	return nil, errNoQUICLane
}

func (s *selector) laneDial() (<-chan struct{}, bool) {
	m := s.m
	if !m.config.EnableWhispera || m.config.WhisperaQUICAddr == "" || len(m.config.WhisperaSecret) == 0 {
		return nil, false
	}

	s.lane.mu.Lock()
	defer s.lane.mu.Unlock()
	if s.lane.quic != nil {
		return closedChan, true
	}
	if s.lane.dialing != nil {
		return s.lane.dialing, true
	}
	done := make(chan struct{})
	s.lane.dialing = done

	sni := m.config.WhisperaSNI
	if net.ParseIP(sni) != nil {
		sni = ""
	}
	cfg := &protocol.ClientConfig{
		ServerAddr:    m.config.WhisperaAddr,
		ServerName:    sni,
		SharedSecret:  m.config.WhisperaSecret,
		ServerCertPin: m.config.WhisperaCertPin,
		ServerIDPub:   m.config.WhisperaIDPub,
		ServerSelPub:  m.config.WhisperaSelPub,
		QUICAddr:      m.quicAddr(),
		OnQUICConn:    s.adoptDatagramConn,
		Control:       bindDefaultRoute,
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), datagramDialTimeout)
		defer cancel()

		lane, err := protocol.DialQUICLane(ctx, cfg)
		if err != nil {
			log.Warn("QUIC lane unavailable, UDP stays on the tunnel and TCP flows have no QUIC to fall back to: %v", err)
		}
		s.lane.mu.Lock()
		s.lane.dialing = nil
		s.lane.quic = lane
		s.lane.mu.Unlock()
		close(done)
		if lane == nil {
			return
		}
		m.noteQUICLaneUp(lane)
		<-lane.Done()
		s.lane.mu.Lock()
		if s.lane.quic == lane {
			s.lane.quic = nil
		}
		s.lane.mu.Unlock()
	}()
	return done, true
}

func (s *selector) adoptDatagramConn(c *quicgo.Conn) {
	gd := quic.NewDatagramClient(c)

	s.lane.mu.Lock()
	old := s.lane.quicGD
	s.lane.quicGD = gd
	s.lane.mu.Unlock()
	if old != nil {
		old.Close()
	}

	go func() {
		<-c.Context().Done()
		s.lane.mu.Lock()
		if s.lane.quicGD == gd {
			s.lane.quicGD = nil
		}
		s.lane.mu.Unlock()
		gd.Close()
	}()
}

func (s *selector) grpcDial() (func(context.Context) (net.Conn, error), bool) {
	m := s.m
	if !m.config.EnableGRPC || m.config.GRPCAddr == "" {
		return nil, false
	}
	t, err := grpc.New(&grpc.Config{
		ListenAddr: "127.0.0.1:0",
		ServerName: m.config.GRPCServerName,
		UseTLS:     m.config.GRPCUseTLS,
	})
	if err != nil {
		return nil, false
	}
	addr := m.config.GRPCAddr
	psk := m.config.PSK
	return func(ctx context.Context) (net.Conn, error) {
		conn, err := t.Dial(ctx, addr)
		if err != nil {
			return nil, err
		}
		if err := sendAltTransportAuth(conn, psk); err != nil {
			return nil, err
		}
		return conn, nil
	}, true
}

func (s *selector) dial() func(context.Context) (net.Conn, error) {
	if d, ok := s.whisperaDial(); ok {
		return d
	}
	if d, ok := s.grpcDial(); ok {
		return d
	}
	return nil
}

func (m *Manager) DatagramClient(addr string) (*quic.DatagramClient, bool) {
	if !m.config.EnableWhispera {
		return nil, false
	}
	s := &m.selector.lane
	s.mu.Lock()
	gd := s.quicGD
	s.mu.Unlock()
	return gd, gd != nil
}
