package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"time"

	"github.com/nekoskin/whispera/core/protocol"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"github.com/nekoskin/whispera/core/protocol/quic"
	"github.com/nekoskin/whispera/core/transport/grpc"

	quicgo "github.com/quic-go/quic-go"
)

func helloSplitEnabled() bool { return os.Getenv("WHISPERA_HELLO_SPLIT") == "1" }

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
			onlineChose := false
			if protocol.PolicyOnlineEnabled() {
				a, _, ok = strategy.SelectJointOnline(jointCtx, presets, fragmented)
				onlineChose = ok
			}
			if !ok && protocol.PolicyEnabled() {
				a, ok = strategy.SelectJointPolicy(jointCtx, presets, fragmented)
			}
			if !ok {
				a = strategy.SelectJoint(jointCtx, presets, fragmented)
			}
			jointArm = a
			preset, budget := protocol.JointArmParts(a, presets)
			if alt, ok := poisonPreset(preset, presets); ok {
				budget, jointArm = 1, -1
				c.HelloID = fingerprint.PresetAt(alt)
			} else {
				c.HelloID = fingerprint.PresetAt(preset)
				if onlineChose && strategy.JointAliveArms(presets, fragmented) > 1 {
					c.HandshakeTimeout = protocol.FastRotateHandshakeTimeout
				}
				if fragmented {
					c.TCPDialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
						return fragDialer.DialTCPWithFragments(ctx, network, addr, budget)
					}
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

		gene, geneUsed := applyGene(&c, fragDialer)

		observe := func(result protocol.HandshakeResult, stage string) {
			if geneUsed && stage == dialStageHandshake {
				observeGene(gene, result == protocol.HandshakeOK)
			}
			strategy.Record(sni, result)
			if shapeUsed && stage == dialStageHandshake {
				shapeSearch().Observe(chosenShape, result == protocol.HandshakeOK)
			}
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
			if fragArm >= 0 && stage == dialStageHandshake {
				strategy.Observe(fragCtx, fragArm, result)
				strategy.NoteDial(fragCtx, fragArm, result == protocol.HandshakeOK)
				recordDial(fragCtx, fragArm, result, stage)
			}
		}

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
