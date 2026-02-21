package transport

import (
	"context"
	"net"
)


type TransportKind string

const (
	TransportUDP   TransportKind = "udp"
	TransportTCP   TransportKind = "tcp"
	TransportWS    TransportKind = "ws"
	TransportWS2   TransportKind = "ws2"
	TransportQUIC  TransportKind = "quic"
	TransportHTTP2 TransportKind = "http2"
	TransportAuto  TransportKind = "auto" 
)


type StreamTransport interface {
	
	WriteRaw(pkt []byte) error
	
	ReadRaw(buf []byte) (int, error)
	
	Close() error
	
	LocalAddr() net.Addr
	
	RemoteAddr() net.Addr
}


type Config struct {
	Kind       TransportKind
	Addr       string
	Timeout    int 
	KeepAlive  bool
	BufferSize int
	Metadata   map[string]string
}


type TransportManager interface {
	
	RegisterTransport(kind TransportKind, transport StreamTransport)

	
	GetTransport(kind TransportKind) (StreamTransport, bool)

	
	ActiveTransport() StreamTransport

	
	SetActiveTransport(kind TransportKind) error

	
	Close() error
}


type TransportSelector interface {
	
	Select(candidates []TransportKind) TransportKind
}


type TransportMiddleware interface {
	
	HandleRead(data []byte, next func([]byte) (int, error)) (int, error)

	
	HandleWrite(data []byte, next func([]byte) error) error
}


type BaseManager struct {
	transports map[TransportKind]StreamTransport
	active     TransportKind
	config     *Config
}


func NewManager(config *Config) *BaseManager {
	return &BaseManager{
		transports: make(map[TransportKind]StreamTransport),
		config:     config,
	}
}


func (m *BaseManager) RegisterTransport(kind TransportKind, transport StreamTransport) {
	m.transports[kind] = transport
	if m.active == "" {
		m.active = kind
	}
}


func (m *BaseManager) GetTransport(kind TransportKind) (StreamTransport, bool) {
	transport, exists := m.transports[kind]
	return transport, exists
}
func (m *BaseManager) ActiveTransport() StreamTransport {
	if m.active == "" {
		return nil
	}
	return m.transports[m.active]
}


func (m *BaseManager) SetActiveTransport(kind TransportKind) error {
	if _, ok := m.transports[kind]; !ok {
		return context.DeadlineExceeded 
	}
	m.active = kind
	return nil
}


func (m *BaseManager) Close() error {
	var lastErr error
	for _, transport := range m.transports {
		if err := transport.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
