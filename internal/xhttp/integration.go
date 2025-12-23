package xhttp

import (
	"context"
	"fmt"
	"net"
	"time"
)

// IntegratedXHTTPServer represents fully integrated XHTTP server
// Combines transport, obfuscation, sessions, and data plane
type IntegratedXHTTPServer struct {
	config         *Config
	listener       net.Listener
	sessionManager *SessionManager
	dataPlane      *PacketUpDataPlane
	multiplexers   map[string]*Multiplexer

	// Statistics
	stats *ServerStats

	// Context
	ctx    context.Context
	cancel context.CancelFunc
}

// ServerStats tracks server statistics
type ServerStats struct {
	StartTime         time.Time
	TotalConnections  int64
	TotalBytes        int64
	TotalErrors       int64
	ActiveConnections int64
	ActiveSessions    int64
	ActiveStreams     int64
}

// NewIntegratedXHTTPServer creates new integrated XHTTP server
func NewIntegratedXHTTPServer(config *Config) (*IntegratedXHTTPServer, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	server := &IntegratedXHTTPServer{
		config: config,
		sessionManager: NewSessionManager(
			config.Session.MaxSessions,
			config.Session.SessionTimeout,
		),
		dataPlane:    NewPacketUpDataPlane(nil),
		multiplexers: make(map[string]*Multiplexer),
		ctx:          ctx,
		cancel:       cancel,
		stats: &ServerStats{
			StartTime: time.Now(),
		},
	}

	return server, nil
}

// Listen starts listening for XHTTP connections
func (s *IntegratedXHTTPServer) Listen() error {
	listener, err := net.Listen("tcp", s.config.Transport.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.Transport.ListenAddr, err)
	}
	defer listener.Close()

	s.listener = listener

	fmt.Printf("[XHTTP] Server listening on %s (mode: %s)\n", s.config.Transport.ListenAddr, s.config.Mode)

	for {
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		default:
		}

		// Accept connection
		conn, err := listener.Accept()
		if err != nil {
			s.stats.TotalErrors++
			continue
		}

		s.stats.TotalConnections++
		s.stats.ActiveConnections++

		// Handle connection in goroutine
		go s.handleConnection(conn)
	}
}

// handleConnection handles individual connection
func (s *IntegratedXHTTPServer) handleConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		s.stats.ActiveConnections--
	}()

	// Set timeouts
	if s.config.ReadTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(s.config.ReadTimeout))
	}
	if s.config.WriteTimeout > 0 {
		conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout))
	}

	// Create multiplexer for this connection
	mux := NewMultiplexer(conn)
	defer mux.Close()

	clientID := conn.RemoteAddr().String()
	s.multiplexers[clientID] = mux
	defer delete(s.multiplexers, clientID)

	// Handle streams from this connection
	s.handleStreams(mux)
}

// handleStreams handles all streams in multiplexer
func (s *IntegratedXHTTPServer) handleStreams(mux *Multiplexer) {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Read from any stream (simplified - in reality would need event loop)
		time.Sleep(100 * time.Millisecond)
	}
}

// Close closes server
func (s *IntegratedXHTTPServer) Close() error {
	s.cancel()
	return s.listener.Close()
}

// GetStats returns current statistics
func (s *IntegratedXHTTPServer) GetStats() ServerStats {
	return ServerStats{
		StartTime:         s.stats.StartTime,
		TotalConnections:  s.stats.TotalConnections,
		TotalBytes:        s.stats.TotalBytes,
		TotalErrors:       s.stats.TotalErrors,
		ActiveConnections: s.stats.ActiveConnections,
		ActiveSessions:    int64(len(s.sessionManager.sessions)),
	}
}

// ServerBuilder provides fluent API for building XHTTP server
type ServerBuilder struct {
	config *Config
	err    error
}

// NewServerBuilder creates new server builder
func NewServerBuilder() *ServerBuilder {
	return &ServerBuilder{
		config: DefaultConfig(),
	}
}

// WithMode sets XHTTP mode
func (sb *ServerBuilder) WithMode(mode string) *ServerBuilder {
	if sb.err != nil {
		return sb
	}
	sb.config.Mode = mode
	return sb
}

// WithListenAddr sets listen address
func (sb *ServerBuilder) WithListenAddr(addr string) *ServerBuilder {
	if sb.err != nil {
		return sb
	}
	sb.config.Transport.ListenAddr = addr
	return sb
}

// WithMaxSessions sets max sessions
func (sb *ServerBuilder) WithMaxSessions(max int) *ServerBuilder {
	if sb.err != nil {
		return sb
	}
	sb.config.Session.MaxSessions = max
	return sb
}

// WithSessionTimeout sets session timeout
func (sb *ServerBuilder) WithSessionTimeout(timeout time.Duration) *ServerBuilder {
	if sb.err != nil {
		return sb
	}
	sb.config.Session.SessionTimeout = timeout
	return sb
}

// WithMaxPostSize sets max packet-up POST size
func (sb *ServerBuilder) WithMaxPostSize(size int64) *ServerBuilder {
	if sb.err != nil {
		return sb
	}
	sb.config.PacketUp.MaxPostSize = size
	return sb
}

// WithMaxBufferedSize sets max packet-up buffered size
func (sb *ServerBuilder) WithMaxBufferedSize(size int64) *ServerBuilder {
	if sb.err != nil {
		return sb
	}
	sb.config.PacketUp.MaxBufferedSize = size
	return sb
}

// Build builds server
func (sb *ServerBuilder) Build() (*IntegratedXHTTPServer, error) {
	if sb.err != nil {
		return nil, sb.err
	}
	return NewIntegratedXHTTPServer(sb.config)
}

// Quick helpers for common configurations

// NewPacketUpServer creates packet-up mode server
func NewPacketUpServer(addr string) *ServerBuilder {
	return NewServerBuilder().
		WithMode("packet-up").
		WithListenAddr(addr)
}

// NewStreamUpServer creates stream-up mode server
func NewStreamUpServer(addr string) *ServerBuilder {
	return NewServerBuilder().
		WithMode("stream-up").
		WithListenAddr(addr)
}

// NewStreamOneServer creates stream-one mode server
func NewStreamOneServer(addr string) *ServerBuilder {
	return NewServerBuilder().
		WithMode("stream-one").
		WithListenAddr(addr)
}
