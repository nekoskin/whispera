package xhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// RealQUICListener implements a real QUIC listener using quic-go
type RealQUICListener struct {
	addr              string
	tlsConfig         *tls.Config
	obfuscationConfig *ServerConfig
	listener          *quic.Listener
	ctx               context.Context
	cancel            context.CancelFunc
	activeConns       map[string]*RealQUICConn
	connMutex         sync.RWMutex
	maxStreamReadSize int64
}

// RealQUICConn wraps a quic-go connection
type RealQUICConn struct {
	quicConn          *quic.Conn
	streams           sync.Map // map[quic.StreamID]quic.Stream
	obfuscationConfig *ServerConfig
	ctx               context.Context
	cancel            context.CancelFunc
	readBuffer        *bytes.Buffer
	mu                sync.Mutex
}

// NewRealQUICListener creates a new real QUIC listener with quic-go
func NewRealQUICListener(addr string, tlsConfig *tls.Config, obfuscationConfig *ServerConfig) (*RealQUICListener, error) {
	if tlsConfig == nil {
		return nil, fmt.Errorf("TLS config is required for QUIC")
	}

	ctx, cancel := context.WithCancel(context.Background())

	listener := &RealQUICListener{
		addr:              addr,
		tlsConfig:         tlsConfig,
		obfuscationConfig: obfuscationConfig,
		ctx:               ctx,
		cancel:            cancel,
		activeConns:       make(map[string]*RealQUICConn),
		maxStreamReadSize: 1024 * 1024, // 1MB per stream read
	}

	return listener, nil
}

// Listen starts the QUIC listener
func (l *RealQUICListener) Listen() error {
	// Resolve UDP address
	addr, err := net.ResolveUDPAddr("udp", l.addr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	// Listen on UDP
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}

	// Create quic-go listener from UDP connection
	listener, err := quic.Listen(udpConn, l.tlsConfig, &quic.Config{
		MaxIdleTimeout:             30 * time.Second,
		MaxStreamReceiveWindow:     10 * 1024 * 1024,
		MaxConnectionReceiveWindow: 50 * 1024 * 1024,
	})
	if err != nil {
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}

	l.listener = listener
	fmt.Printf("[QUIC] Real QUIC listener started on %s\n", l.addr)

	// Accept connections in goroutine
	go func() {
		for {
			select {
			case <-l.ctx.Done():
				return
			default:
			}

			conn, err := listener.Accept(l.ctx)
			if err != nil {
				if l.ctx.Err() == nil {
					fmt.Printf("[QUIC] Accept error: %v\n", err)
				}
				return
			}

			// Handle connection in goroutine
			go l.handleConnection(conn)
		}
	}()

	return nil
}

// handleConnection handles a single QUIC connection
func (l *RealQUICListener) handleConnection(quicConn *quic.Conn) {
	connID := quicConn.RemoteAddr().String()

	conn := &RealQUICConn{
		quicConn:          quicConn,
		obfuscationConfig: l.obfuscationConfig,
		readBuffer:        &bytes.Buffer{},
	}
	conn.ctx, conn.cancel = context.WithCancel(l.ctx)

	l.connMutex.Lock()
	l.activeConns[connID] = conn
	l.connMutex.Unlock()

	defer func() {
		conn.cancel()
		l.connMutex.Lock()
		delete(l.activeConns, connID)
		l.connMutex.Unlock()
		quicConn.CloseWithError(0, "done")
	}()

	// Accept streams from connection
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-conn.ctx.Done():
			return
		default:
		}

		stream, err := quicConn.AcceptStream(conn.ctx)
		if err != nil {
			if conn.ctx.Err() == nil {
				fmt.Printf("[QUIC] Accept stream error: %v\n", err)
			}
			return
		}

		// Handle stream
		go l.handleStream(conn, stream)
	}
}

// handleStream handles a single QUIC stream
func (l *RealQUICListener) handleStream(conn *RealQUICConn, stream *quic.Stream) {
	defer stream.Close()

	// Register stream in connection
	conn.streams.Store(stream.StreamID(), stream)
	defer func() {
		conn.streams.Delete(stream.StreamID())
	}()

	// Read data from stream
	buf := make([]byte, l.maxStreamReadSize)
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-conn.ctx.Done():
			return
		default:
		}

		n, err := stream.Read(buf)
		if err != nil {
			return
		}

		if n > 0 {
			data := buf[:n]

			// Apply de-obfuscation if available
			if l.obfuscationConfig != nil && l.obfuscationConfig.ObfuscationManager != nil {
				processed, _, err := l.obfuscationConfig.ObfuscationManager.ProcessTrafficWithML(
					data, "inbound", "xhttp-quic")
				if err == nil {
					data = processed
				}
			}

			// Write to buffer for application to read
			conn.readBuffer.Write(data)
		}
	}
}

// RealQUICConn methods

// Read reads from the QUIC connection
func (c *RealQUICConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.readBuffer.Len() > 0 {
		return c.readBuffer.Read(b)
	}

	// Wait for data from streams
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	default:
	}

	// This is simplified - proper implementation would use channels
	// to signal data availability
	return 0, nil
}

// Write writes to the QUIC connection
func (c *RealQUICConn) Write(b []byte) (n int, err error) {
	// Find first stream to write
	var stream *quic.Stream
	c.streams.Range(func(key, value interface{}) bool {
		stream = value.(*quic.Stream)
		return false // Break after first
	})

	if stream == nil {
		return 0, fmt.Errorf("no streams available")
	}

	return stream.Write(b)
}

// Close closes the QUIC connection
func (c *RealQUICConn) Close() error {
	c.cancel()

	// Close all streams
	c.streams.Range(func(key, value interface{}) bool {
		stream := value.(*quic.Stream)
		stream.Close()
		return true
	})

	return c.quicConn.CloseWithError(0, "closed")
}

// LocalAddr returns local address
func (c *RealQUICConn) LocalAddr() net.Addr {
	return c.quicConn.LocalAddr()
}

// RemoteAddr returns remote address
func (c *RealQUICConn) RemoteAddr() net.Addr {
	return c.quicConn.RemoteAddr()
}

// SetDeadline sets read/write deadline
func (c *RealQUICConn) SetDeadline(t time.Time) error {
	// QUIC connections don't have traditional deadlines
	// This is a no-op for compatibility
	return nil
}

// SetReadDeadline sets read deadline
func (c *RealQUICConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets write deadline
func (c *RealQUICConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// RealQUICListener net.Listener methods

// Accept returns next connection
func (l *RealQUICListener) Accept() (net.Conn, error) {
	conn, err := l.listener.Accept(l.ctx)
	if err != nil {
		return nil, err
	}

	quicConn := &RealQUICConn{
		quicConn:   conn,
		readBuffer: &bytes.Buffer{},
	}
	quicConn.ctx, quicConn.cancel = context.WithCancel(l.ctx)

	l.connMutex.Lock()
	l.activeConns[conn.RemoteAddr().String()] = quicConn
	l.connMutex.Unlock()

	return quicConn, nil
}

// Close closes the listener
func (l *RealQUICListener) Close() error {
	l.cancel()

	l.connMutex.Lock()
	for _, conn := range l.activeConns {
		conn.Close()
	}
	l.activeConns = make(map[string]*RealQUICConn)
	l.connMutex.Unlock()

	if l.listener != nil {
		return l.listener.Close()
	}
	return nil
}

// Addr returns the listener address
func (l *RealQUICListener) Addr() net.Addr {
	if l.listener != nil {
		return l.listener.Addr()
	}
	return nil
}

// GetActiveConnections returns list of active connections
func (l *RealQUICListener) GetActiveConnections() []*RealQUICConn {
	l.connMutex.RLock()
	defer l.connMutex.RUnlock()

	conns := make([]*RealQUICConn, 0, len(l.activeConns))
	for _, conn := range l.activeConns {
		conns = append(conns, conn)
	}
	return conns
}

// Stats returns listener statistics
func (l *RealQUICListener) Stats() map[string]interface{} {
	l.connMutex.RLock()
	defer l.connMutex.RUnlock()

	return map[string]interface{}{
		"active_connections": len(l.activeConns),
		"listen_addr":        l.addr,
	}
}
