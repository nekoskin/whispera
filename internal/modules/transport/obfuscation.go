// Package transport provides common transport utilities including obfuscation middleware
package transport

import (
	"net"
	"sync"
	"time"

	"whispera/internal/core/interfaces"
)

// ObfuscatedConn wraps a net.Conn with automatic obfuscation
// This ensures all data going through ANY transport is obfuscated
type ObfuscatedConn struct {
	net.Conn
	obfuscator interfaces.Obfuscator
	mu         sync.Mutex
	closed     bool

	// Stats
	bytesRead      uint64
	bytesWritten   uint64
	packetsRead    uint64
	packetsWritten uint64
}

// WrapWithObfuscation wraps any connection with obfuscation middleware
func WrapWithObfuscation(conn net.Conn, obfuscator interfaces.Obfuscator) *ObfuscatedConn {
	return &ObfuscatedConn{
		Conn:       conn,
		obfuscator: obfuscator,
	}
}

// Read reads and deobfuscates data from the connection
func (c *ObfuscatedConn) Read(b []byte) (n int, err error) {
	// Read raw data
	n, err = c.Conn.Read(b)
	if err != nil || n == 0 {
		return n, err
	}

	c.packetsRead++
	c.bytesRead += uint64(n)

	// Deobfuscate if obfuscator is set
	if c.obfuscator != nil {
		data := make([]byte, n)
		copy(data, b[:n])

		deobfuscated, _, err := c.obfuscator.Process(data, interfaces.DirectionInbound)
		if err != nil {
			return n, err
		}

		// Copy deobfuscated data back
		copy(b, deobfuscated)
		return len(deobfuscated), nil
	}

	return n, nil
}

// Write obfuscates and writes data to the connection
func (c *ObfuscatedConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, net.ErrClosed
	}

	dataToWrite := b
	// Obfuscate if obfuscator is set
	if c.obfuscator != nil {
		obfuscated, _, err := c.obfuscator.Process(b, interfaces.DirectionOutbound)
		if err != nil {
			return 0, err
		}
		dataToWrite = obfuscated
	}

	// Apply timing delay for traffic analysis evasion
	// OPTIMIZATION: Removed timing delays for maximum throughput
	// if delay > 0 {
	// 	time.Sleep(delay)
	// }

	// Write obfuscated data
	n, err = c.Conn.Write(dataToWrite)
	if err == nil {
		c.packetsWritten++
		c.bytesWritten += uint64(n)
	}

	return len(b), err // Return original length
}

// Close closes the connection
func (c *ObfuscatedConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.Conn.Close()
}

// Stats returns connection statistics
func (c *ObfuscatedConn) Stats() ConnectionStats {
	return ConnectionStats{
		BytesRead:      c.bytesRead,
		BytesWritten:   c.bytesWritten,
		PacketsRead:    c.packetsRead,
		PacketsWritten: c.packetsWritten,
	}
}

// ConnectionStats holds connection statistics
type ConnectionStats struct {
	BytesRead      uint64
	BytesWritten   uint64
	PacketsRead    uint64
	PacketsWritten uint64
}

// ObfuscatedListener wraps a net.Listener to automatically wrap accepted connections
type ObfuscatedListener struct {
	net.Listener
	obfuscator interfaces.Obfuscator
}

// WrapListenerWithObfuscation wraps a listener with obfuscation
func WrapListenerWithObfuscation(l net.Listener, obfuscator interfaces.Obfuscator) *ObfuscatedListener {
	return &ObfuscatedListener{
		Listener:   l,
		obfuscator: obfuscator,
	}
}

// Accept accepts a connection and wraps it with obfuscation
func (l *ObfuscatedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return WrapWithObfuscation(conn, l.obfuscator), nil
}

// ObfuscatedDialer provides dialing with automatic obfuscation
type ObfuscatedDialer struct {
	Dialer     *net.Dialer
	Obfuscator interfaces.Obfuscator
}

// NewObfuscatedDialer creates a new dialer with obfuscation
func NewObfuscatedDialer(obfuscator interfaces.Obfuscator) *ObfuscatedDialer {
	return &ObfuscatedDialer{
		Dialer:     &net.Dialer{Timeout: 30 * time.Second},
		Obfuscator: obfuscator,
	}
}

// Dial dials a connection and wraps it with obfuscation
func (d *ObfuscatedDialer) Dial(network, address string) (net.Conn, error) {
	conn, err := d.Dialer.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return WrapWithObfuscation(conn, d.Obfuscator), nil
}

// DialContext dials with context and wraps with obfuscation
func (d *ObfuscatedDialer) DialContext(ctx interface{}, network, address string) (net.Conn, error) {
	return d.Dial(network, address)
}
