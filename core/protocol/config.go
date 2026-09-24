package protocol

import (
	"context"
	"net"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	quicgo "github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
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

	EnableQUIC bool
	QUICAddr   string
	OnQUICConn func(*quicgo.Conn)

	DropECH          bool
	HelloSplitOffset int
	HelloID          utls.ClientHelloID
	HelloRaw         []byte
	OnHandshake      func(result HandshakeResult, latency time.Duration)
	OnServerSelPub   func(selPub string)
	OnLiveReset      func()
	OnLiveOK         func()

	// OnLiveEnd reports a finished connection's lifetime, bytes and whether it
	// ended in a censor-looking reset. OnLiveReset/OnLiveOK cover only its start.
	OnLiveEnd func(dur time.Duration, bytes int64, reset bool)
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

	userOnce sync.Once
	users    *lru.Cache[string, knownUser]

	altSvcHeader string
}

// Resolving a secret walks every key on the server, three HMACs apiece. The
// TCP handshake already learns whose session this is, so the datagram lane,
// which has no camouflage layer to ask, gets the answer from here and verifies
// it with one HMAC instead of a thousand.
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
