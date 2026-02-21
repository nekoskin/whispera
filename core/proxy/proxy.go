package proxy

import (
	"context"
	"net"
	"time"
)


type ProxyType string

const (
	ProxyHTTP   ProxyType = "http"
	ProxySOCKS5 ProxyType = "socks5"
	ProxyMixed  ProxyType = "mixed" 
)


type Config struct {
	Type        ProxyType
	Addr        string
	Username    string
	Password    string
	Timeout     time.Duration
	IdleTimeout time.Duration
	BufferSize  int
	EnableDNS   bool
	EnableIPv6  bool
}


type Proxy interface {
	
	Start(ctx context.Context) error
	
	Stop() error
	
	Addr() net.Addr
	
	Type() ProxyType
}


type Handler interface {
	
	Handle(ctx context.Context, conn net.Conn) error
}


type AuthHandler interface {
	
	Authenticate(username, password string) bool
}


type Manager struct {
	proxies map[ProxyType]Proxy
	config  *Config
}


func NewManager(config *Config) *Manager {
	return &Manager{
		proxies: make(map[ProxyType]Proxy),
		config:  config,
	}
}
func (m *Manager) AddProxy(proxy Proxy) {
	m.proxies[proxy.Type()] = proxy
}


func (m *Manager) GetProxy(proxyType ProxyType) (Proxy, bool) {
	proxy, exists := m.proxies[proxyType]
	return proxy, exists
}


func (m *Manager) Start(ctx context.Context) error {
	for _, proxy := range m.proxies {
		if err := proxy.Start(ctx); err != nil {
			return err
		}
	}
	return nil
}


func (m *Manager) Stop() error {
	var lastErr error
	for _, proxy := range m.proxies {
		if err := proxy.Stop(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}


type Stats struct {
	Connections      int64
	BytesTransferred int64
	Errors           int64
	StartTime        time.Time
}


type StatsProvider interface {
	
	Stats() *Stats
	
	Reset()
}
