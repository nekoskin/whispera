package domainsocket

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"whispera/internal/core/base"
	"whispera/internal/logger"
)

var log = logger.Module("domainsocket")

const (
	ModuleName    = "transport.domainsocket"
	ModuleVersion = "1.0.0"
)

type Config struct {
	Path string

	Type string

	Mode os.FileMode

	RemoveExisting bool

	SendBuffer    int
	ReceiveBuffer int
}

func DefaultConfig() *Config {
	return &Config{
		Type:           "stream",
		Mode:           0600,
		RemoveExisting: true,
		SendBuffer:     1024 * 1024,
		ReceiveBuffer:  1024 * 1024,
	}
}

func (c *Config) Validate() error {
	if c.Path == "" {
		return fmt.Errorf("socket path is required")
	}
	if c.Type != "stream" && c.Type != "seqpacket" {
		c.Type = "stream"
	}
	if runtime.GOOS == "windows" && c.Type == "seqpacket" {
		return fmt.Errorf("seqpacket not supported on Windows")
	}
	return nil
}

type Transport struct {
	*base.Module
	config *Config

	mu       sync.RWMutex
	listener net.Listener
	conns    map[*net.UnixConn]struct{}

	totalConns  uint64
	activeConns int32
	bytesIn     uint64
	bytesOut    uint64
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	t := &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
		conns:  make(map[*net.UnixConn]struct{}),
	}

	return t, nil
}

func (t *Transport) Listen(ctx context.Context) error {
	if t.config.RemoveExisting {
		os.Remove(t.config.Path)
	}

	var network string
	switch t.config.Type {
	case "seqpacket":
		network = "unixpacket"
	default:
		network = "unix"
	}

	addr, err := net.ResolveUnixAddr(network, t.config.Path)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	listener, err := net.ListenUnix(network, addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	if err := os.Chmod(t.config.Path, t.config.Mode); err != nil {
		listener.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	t.mu.Lock()
	t.listener = listener
	t.mu.Unlock()

	log.Info("Domain socket listening on %s", t.config.Path)

	return nil
}

func (t *Transport) Accept() (net.Conn, error) {
	t.mu.RLock()
	listener := t.listener
	t.mu.RUnlock()

	if listener == nil {
		return nil, fmt.Errorf("not listening")
	}

	conn, err := listener.Accept()
	if err != nil {
		return nil, err
	}

	if unixConn, ok := conn.(*net.UnixConn); ok {
		t.mu.Lock()
		t.conns[unixConn] = struct{}{}
		t.mu.Unlock()
	}

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt32(&t.activeConns, 1)

	return &trackedConn{
		Conn:      conn,
		transport: t,
	}, nil
}

func (t *Transport) Dial(ctx context.Context, path string) (net.Conn, error) {
	if path == "" {
		path = t.config.Path
	}

	var network string
	switch t.config.Type {
	case "seqpacket":
		network = "unixpacket"
	default:
		network = "unix"
	}

	addr, err := net.ResolveUnixAddr(network, path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, addr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	return &trackedConn{
		Conn:      conn,
		transport: t,
	}, nil
}

type trackedConn struct {
	net.Conn
	transport *Transport
	closed    atomic.Bool
}

func (c *trackedConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesIn, uint64(n))
	}
	return
}

func (c *trackedConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesOut, uint64(n))
	}
	return
}

func (c *trackedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		atomic.AddInt32(&c.transport.activeConns, -1)
	}
	return c.Conn.Close()
}


func (t *Transport) Init(ctx context.Context) error {
	return nil
}

func (t *Transport) Start(ctx context.Context) error {
	return t.Listen(ctx)
}

func (t *Transport) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for conn := range t.conns {
		conn.Close()
	}
	t.conns = make(map[*net.UnixConn]struct{})

	if t.listener != nil {
		t.listener.Close()
		t.listener = nil
	}

	if t.config.RemoveExisting {
		os.Remove(t.config.Path)
	}

	return nil
}

func (t *Transport) Stats() map[string]interface{} {
	return map[string]interface{}{
		"path":               t.config.Path,
		"type":               t.config.Type,
		"total_connections":  atomic.LoadUint64(&t.totalConns),
		"active_connections": atomic.LoadInt32(&t.activeConns),
		"bytes_in":           atomic.LoadUint64(&t.bytesIn),
		"bytes_out":          atomic.LoadUint64(&t.bytesOut),
	}
}
