package transport

import (
	"net"
	"sync"
	"time"

	"whispera/internal/core/interfaces"
)

type ObfuscatedConn struct {
	net.Conn
	obfuscator interfaces.Obfuscator
	mu         sync.Mutex
	closed     bool

	bytesRead      uint64
	bytesWritten   uint64
	packetsRead    uint64
	packetsWritten uint64
}

func WrapWithObfuscation(conn net.Conn, obfuscator interfaces.Obfuscator) *ObfuscatedConn {
	return &ObfuscatedConn{
		Conn:       conn,
		obfuscator: obfuscator,
	}
}

func (c *ObfuscatedConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil || n == 0 {
		return n, err
	}

	c.packetsRead++
	c.bytesRead += uint64(n)

	if c.obfuscator != nil {
		data := make([]byte, n)
		copy(data, b[:n])

		deobfuscated, _, err := c.obfuscator.Process(data, interfaces.DirectionInbound)
		if err != nil {
			return n, err
		}

		copy(b, deobfuscated)
		return len(deobfuscated), nil
	}

	return n, nil
}

func (c *ObfuscatedConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, net.ErrClosed
	}

	dataToWrite := b
	if c.obfuscator != nil {
		obfuscated, _, err := c.obfuscator.Process(b, interfaces.DirectionOutbound)
		if err != nil {
			return 0, err
		}
		dataToWrite = obfuscated
	}


	n, err = c.Conn.Write(dataToWrite)
	if err == nil {
		c.packetsWritten++
		c.bytesWritten += uint64(n)
	}

	return len(b), err
}

func (c *ObfuscatedConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *ObfuscatedConn) Stats() ConnectionStats {
	return ConnectionStats{
		BytesRead:      c.bytesRead,
		BytesWritten:   c.bytesWritten,
		PacketsRead:    c.packetsRead,
		PacketsWritten: c.packetsWritten,
	}
}

type ConnectionStats struct {
	BytesRead      uint64
	BytesWritten   uint64
	PacketsRead    uint64
	PacketsWritten uint64
}

type ObfuscatedListener struct {
	net.Listener
	obfuscator interfaces.Obfuscator
}

func WrapListenerWithObfuscation(l net.Listener, obfuscator interfaces.Obfuscator) *ObfuscatedListener {
	return &ObfuscatedListener{
		Listener:   l,
		obfuscator: obfuscator,
	}
}

func (l *ObfuscatedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return WrapWithObfuscation(conn, l.obfuscator), nil
}

type ObfuscatedDialer struct {
	Dialer     *net.Dialer
	Obfuscator interfaces.Obfuscator
}

func NewObfuscatedDialer(obfuscator interfaces.Obfuscator) *ObfuscatedDialer {
	return &ObfuscatedDialer{
		Dialer:     &net.Dialer{Timeout: 30 * time.Second},
		Obfuscator: obfuscator,
	}
}

func (d *ObfuscatedDialer) Dial(network, address string) (net.Conn, error) {
	conn, err := d.Dialer.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return WrapWithObfuscation(conn, d.Obfuscator), nil
}

func (d *ObfuscatedDialer) DialContext(ctx interface{}, network, address string) (net.Conn, error) {
	return d.Dial(network, address)
}
