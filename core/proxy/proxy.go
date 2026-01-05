package proxy

import (
	"context"
	"net"
	"time"
)

// ProxyType определяет тип прокси
type ProxyType string

const (
	ProxyHTTP   ProxyType = "http"
	ProxySOCKS5 ProxyType = "socks5"
	ProxyMixed  ProxyType = "mixed" // HTTP + SOCKS5 на одном порту
)

// Config содержит конфигурацию прокси
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

// Proxy интерфейс для всех типов прокси
type Proxy interface {
	// Start запускает прокси сервер
	Start(ctx context.Context) error
	// Stop останавливает прокси сервер
	Stop() error
	// Addr возвращает адрес, на котором слушает прокси
	Addr() net.Addr
	// Type возвращает тип прокси
	Type() ProxyType
}

// Handler обрабатывает прокси соединения
type Handler interface {
	// Handle обрабатывает одно соединение
	Handle(ctx context.Context, conn net.Conn) error
}

// AuthHandler обрабатывает аутентификацию
type AuthHandler interface {
	// Authenticate проверяет учетные данные
	Authenticate(username, password string) bool
}

// Manager управляет несколькими прокси серверами
type Manager struct {
	proxies map[ProxyType]Proxy
	config  *Config
}

// NewManager создает новый менеджер прокси
func NewManager(config *Config) *Manager {
	return &Manager{
		proxies: make(map[ProxyType]Proxy),
		config:  config,
	}
}

// AddProxy добавляет прокси в менеджер
func (m *Manager) AddProxy(proxy Proxy) {
	m.proxies[proxy.Type()] = proxy
}

// GetProxy получает прокси по типу
func (m *Manager) GetProxy(proxyType ProxyType) (Proxy, bool) {
	proxy, exists := m.proxies[proxyType]
	return proxy, exists
}

// Start запускает все прокси
func (m *Manager) Start(ctx context.Context) error {
	for _, proxy := range m.proxies {
		if err := proxy.Start(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Stop останавливает все прокси
func (m *Manager) Stop() error {
	var lastErr error
	for _, proxy := range m.proxies {
		if err := proxy.Stop(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// Stats содержит статистику прокси
type Stats struct {
	Connections      int64
	BytesTransferred int64
	Errors           int64
	StartTime        time.Time
}

// StatsProvider предоставляет статистику
type StatsProvider interface {
	// Stats возвращает текущую статистику
	Stats() *Stats
	// Reset сбрасывает статистику
	Reset()
}
