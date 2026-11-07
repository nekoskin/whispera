package protocol

import (
	"context"
	"net"
	"sync"
	"syscall"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	quicgo "github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"

	"github.com/nekoskin/whispera/core/protocol/camo"
)

type ClientConfig struct {
	ServerAddr    string
	ServerName    string
	ServerNames   []string
	SharedSecret  []byte
	ServerCertPin string
	ServerIDPub   string
	ServerSelPub  string
	SessionCache  any
	TCPDialer     func(ctx context.Context, network, addr string) (net.Conn, error)
	Control       func(network, address string, c syscall.RawConn) error

	EnableQUIC bool
	QUICAddr   string
	OnQUICConn func(*quicgo.Conn)

	DropECH          bool
	DropPQ           bool
	Levers           *ConnLevers
	Arm              int
	HelloID          utls.ClientHelloID
	HelloRaw         []byte
	HandshakeTimeout time.Duration
	OnConnected      func(local, remote net.Addr, connect time.Duration)
	OnHelloSent      func()
	OnHandshake      func(result HandshakeResult, symptom Symptom, latency time.Duration)
	OnConnectFail    func(result HandshakeResult, symptom Symptom, latency time.Duration)
	OnServerSelPub   func(selPub string)
	OnLiveReset      func()
	OnLiveOK         func()

	OnLiveEnd func(LiveEnd)
}

type ServerConfig struct {
	ListenAddr       string
	ExtraListenAddrs []string
	BackendH2CAddr   string
	TLSCert          string
	TLSKey           string
	Domain           string
	ACMEDir          string
	DecoyOrigin      string
	DecoyCertDir     string
	AsymBiasRatio    float64
	SharedSecret     []byte

	QUICListenAddr       string
	ExtraQUICListenAddrs []string

	GetUsers     func() []UserEntry
	UsersVersion func() uint64
	OnConn       func(AcceptedConn)
	TargetDialer *net.Dialer

	sessionRegistry
}

type AcceptedConn struct {
	Conn      net.Conn
	UserID    string
	SessionID []byte
	Secret    []byte
}

type sessionRegistry struct {
	proxy *decoyProxy

	seenTokens tokenSeenSet
	selectors  selectorIndex

	helloGuardOnce sync.Once
	helloGuard     *camo.ReplayGuard

	userOnce sync.Once
	users    *lru.Cache[string, knownUser]

	altSvcHeader string
}

func (r *sessionRegistry) userCache() *lru.Cache[string, knownUser] {
	r.userOnce.Do(func() {
		r.users, _ = lru.New[string, knownUser](4096)
	})
	return r.users
}

func (r *sessionRegistry) rememberUser(sessionID []byte, u knownUser) {
	if len(u.psk) != 32 || len(sessionID) == 0 {
		return
	}
	if c := r.userCache(); c != nil {
		c.Add(string(sessionID), u)
	}
}

func (r *sessionRegistry) userHint(sessionID []byte) knownUser {
	c := r.userCache()
	if c == nil {
		return knownUser{}
	}
	u, _ := c.Get(string(sessionID))
	return u
}

const replayWindowSeconds = (2*authWindowTolerance + 1) * authWindowSeconds

func (r *sessionRegistry) consumeToken(token string) bool {
	return r.seenTokens.consume(token, time.Now().Unix())
}

func (r *sessionRegistry) hellos() *camo.ReplayGuard {
	r.helloGuardOnce.Do(func() {
		r.helloGuard = camo.NewReplayGuard(int64(helloReplayMemory.Seconds()))
	})
	return r.helloGuard
}

func (r *sessionRegistry) firstHelloSighting(random []byte, sender string) bool {
	return r.hellos().FirstSighting(random, sender, serverNow().Unix())
}
