package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"

	"time"

	"github.com/nekoskin/whispera/core/protocol"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"github.com/nekoskin/whispera/core/protocol/quic"
	"github.com/nekoskin/whispera/core/transport/grpc"
	"github.com/nekoskin/whispera/core/transport/yadisk"

	quicgo "github.com/quic-go/quic-go"
)

func helloSplitEnabled() bool { return os.Getenv("WHISPERA_HELLO_SPLIT") == "1" }

var (
	shapeSearchOnce sync.Once
	shapeSearchInst *protocol.ShapeSearch
)

func shapeSearch() *protocol.ShapeSearch {
	shapeSearchOnce.Do(func() { shapeSearchInst = protocol.NewShapeSearch() })
	return shapeSearchInst
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
	dialing bool
}

type selector struct {
	m *Manager

	sessionCache any
	lane         datagramLane
	strategy     *protocol.HandshakeStrategy
	shape        *shapeController
}

func newSelector(m *Manager) *selector {
	strategy := m.config.HandshakeStrategy
	if strategy == nil {
		strategy = protocol.NewHandshakeStrategy()
	}
	sni := m.config.WhisperaSNI
	if net.ParseIP(sni) != nil {
		sni = ""
	}
	return &selector{
		m:            m,
		sessionCache: protocol.SharedSessionCache(),
		strategy:     strategy,
		shape:        newShapeController(strategy, sni),
	}
}

func (s *selector) whisperaDial() (func(context.Context) (net.Conn, error), bool) {
	m := s.m
	if !m.config.EnableWhispera || len(m.config.WhisperaSecret) == 0 {
		return nil, false
	}
	addr := m.config.WhisperaAddr
	if addr == "" {
		addr = m.config.ServerAddr
	}
	sni := m.config.WhisperaSNI
	if net.ParseIP(sni) != nil {
		sni = ""
	}
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
	}
	strategy := s.strategy
	splitCtx := sni + "|split"
	fragCtx := sni + "|frag"
	jointCtx := sni + "|joint"
	// A pinned count is the operator's word and outranks the controller.
	fragDialer := m.asnBypassDialer
	if m.config.TLSFragmentCount > 0 {
		fragDialer = nil
	}
	fragmented := fragDialer != nil && fragDialer.Fragmenting()
	return func(ctx context.Context) (net.Conn, error) {
		c := *cCfg
		if c.ServerSelPub == "" {
			c.ServerSelPub = protocol.LearnedSelPub(c.ServerIDPub)
		}
		c.OnServerSelPub = func(selPub string) {
			protocol.RememberSelPub(c.ServerIDPub, selPub)
		}
		presets := fingerprint.PresetCount()
		arm, fragArm, jointArm := -1, -1, -1

		if protocol.JointArmEnabled() {
			a, ok := 0, false
			// A model that keeps learning outranks the frozen one, and both
			// outrank the bandit. Each falls through when its weights were
			// built for a different repertoire.
			if protocol.PolicyOnlineEnabled() {
				a, _, ok = strategy.SelectJointOnline(jointCtx, presets, fragmented)
			}
			if !ok && protocol.PolicyEnabled() {
				a, ok = strategy.SelectJointPolicy(jointCtx, presets, fragmented)
			}
			if !ok {
				a = strategy.SelectJoint(jointCtx, presets, fragmented)
			}
			jointArm = a
			preset, budget := protocol.JointArmParts(a, presets)
			c.HelloID = fingerprint.PresetAt(preset)
			if fragmented {
				c.TCPDialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return fragDialer.DialTCPWithFragments(ctx, network, addr, budget)
				}
			}
		} else {
			arm = strategy.Select(sni, presets)
			c.HelloID = fingerprint.PresetAt(arm)
			if fragmented {
				budget, a := 0, 0
				if protocol.PolicyEnabled() {
					var ok bool
					if budget, a, ok = strategy.SelectFragmentsPolicy(fragCtx); !ok {
						budget, a = strategy.SelectFragments(fragCtx)
					}
				} else {
					budget, a = strategy.SelectFragments(fragCtx)
				}
				fragArm = a
				c.TCPDialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return fragDialer.DialTCPWithFragments(ctx, network, addr, budget)
				}
			}
		}

		shapeUsed := false
		var chosenShape protocol.HelloShape
		if protocol.ShapeSearchEnabled() && fragDialer != nil {
			chosenShape = shapeSearch().Select()
			shapeUsed = true
			c.TCPDialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return fragDialer.DialTCPWithShape(ctx, network, addr, chosenShape.Records, chosenShape.PauseMs)
			}
		}

		splitArm := -1
		if helloSplitEnabled() {
			c.HelloSplitOffset, splitArm = strategy.SelectSplit(splitCtx)
		}

		observe := func(result protocol.HandshakeResult, stage string) {
			strategy.Record(sni, result)
			if shapeUsed && stage == dialStageHandshake {
				shapeSearch().Observe(chosenShape, result == protocol.HandshakeOK)
			}
			// One arm carried both axes, so one context judges it and the
			// per-axis contexts stay out of it entirely.
			if jointArm >= 0 {
				if stage == dialStageHandshake {
					alive := result == protocol.HandshakeOK
					strategy.Observe(jointCtx, jointArm, result)
					strategy.NoteDial(jointCtx, jointArm, alive)
					if protocol.PolicyOnlineEnabled() {
						strategy.NoteJointOnline(jointCtx, jointArm, alive)
					}
					recordDial(jointCtx, jointArm, result, stage)
				}
				return
			}
			if arm >= 0 {
				strategy.Observe(sni, arm, result)
			}
			if splitArm >= 0 {
				strategy.Observe(splitCtx, splitArm, result)
			}
			// Only the handshake judges the budget; a later reset blames the
			// datapath, not the arm that got through the gate.
			if fragArm >= 0 && stage == dialStageHandshake {
				strategy.Observe(fragCtx, fragArm, result)
				strategy.NoteDial(fragCtx, fragArm, result == protocol.HandshakeOK)
				recordDial(fragCtx, fragArm, result, stage)
			}
		}

		// Report the success here too, not through OnLiveOK, or the budget's
		// counter only grows on failures and the controller never converges.
		c.OnHandshake = func(result protocol.HandshakeResult, _ time.Duration) {
			observe(result, dialStageHandshake)
		}
		c.OnLiveReset = func() { observe(protocol.HandshakeResetFast, dialStageLiveReset) }
		c.OnLiveOK = func() { observe(protocol.HandshakeOK, dialStageLiveOK) }
		c.OnLiveEnd = func(dur time.Duration, bytes int64, reset bool) {
			s.shape.note(dur, bytes, reset)
		}
		return protocol.Client(ctx, &c)
	}, true
}

func (s *selector) startDatagramLane() {
	m := s.m
	if !m.config.EnableWhispera || m.config.WhisperaQUICAddr == "" || len(m.config.WhisperaSecret) == 0 {
		return
	}

	s.lane.mu.Lock()
	if s.lane.quicGD != nil || s.lane.dialing {
		s.lane.mu.Unlock()
		return
	}
	s.lane.dialing = true
	s.lane.mu.Unlock()

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
		QUICAddr:      m.config.WhisperaQUICAddr,
		OnQUICConn:    s.adoptDatagramConn,
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), datagramDialTimeout)
		defer cancel()

		if err := protocol.DialRTDatagrams(ctx, cfg); err != nil {
			log.Warn("datagram lane unavailable, UDP stays on the tunnel: %v", err)
		}
		s.lane.mu.Lock()
		s.lane.dialing = false
		s.lane.mu.Unlock()
	}()
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

func (s *selector) yadiskDial() (func(context.Context) (net.Conn, error), bool) {
	m := s.m
	if !m.config.EnableYaDisk || m.config.YaDiskOAuthToken == "" {
		return nil, false
	}
	t, err := yadisk.New(&yadisk.Config{
		OAuthToken: m.config.YaDiskOAuthToken,
		SessionID:  m.config.YaDiskSessionID,
	})
	if err != nil {
		return nil, false
	}
	if err := t.Start(); err != nil {
		return nil, false
	}
	psk := m.config.PSK
	return func(ctx context.Context) (net.Conn, error) {
		conn, err := t.Dial(ctx, "")
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
	if d, ok := s.yadiskDial(); ok {
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
