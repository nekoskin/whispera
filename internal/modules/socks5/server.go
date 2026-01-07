package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/modules/relay"
	"whispera/internal/proxy"
)

const (
	ModuleName    = "socks5.server"
	ModuleVersion = "1.0.0"
)

// TunnelRelay interface for tunnel communication with frame support
type TunnelRelay interface {
	Send(data []byte) error
	Receive(buf []byte) (int, error)
	IsConnected() bool
}

// Config holds module configuration
type Config struct {
	ListenAddr string
	Username   string
	Password   string
	Debug      bool
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		ListenAddr: "127.0.0.1:10800",
		Debug:      false,
	}
}

// Validate implements interfaces.ModuleConfig
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:10800"
	}
	return nil
}

// pendingConn represents a pending connection waiting for CONNECT_OK
type pendingConn struct {
	conn   net.Conn
	target string
	ready  chan error
	ctx    context.Context
	cancel context.CancelFunc
}

// Server implements the SOCKS5 server module
type Server struct {
	*base.Module
	config *Config

	// SOCKS5 Server
	server   *proxy.SOCKS5Server
	listener net.Listener

	// Dependencies
	tunnel TunnelRelay

	// Stream management (client-side)
	streamIDGen   *relay.StreamIDGenerator
	pendingConns  map[uint16]*pendingConn // streamID -> pending connection
	activeStreams map[uint16]net.Conn     // streamID -> active SOCKS5 client conn
	streamMu      sync.RWMutex

	// Stats
	connectSuccess uint64
	connectFailed  uint64
	bytesRelayed   uint64

	// Process
	cmd *exec.Cmd

	mu sync.RWMutex
}

// New creates a new SOCKS5 server module
func New(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	s := &Server{
		Module:        base.NewModule(ModuleName, ModuleVersion, []string{"tunnel.manager"}),
		config:        cfg,
		streamIDGen:   relay.NewStreamIDGenerator(),
		pendingConns:  make(map[uint16]*pendingConn),
		activeStreams: make(map[uint16]net.Conn),
	}

	return s, nil
}

// Init initializes the module
func (s *Server) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := s.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if socketCfg, ok := cfg.(*Config); ok {
		s.config = socketCfg
	}

	return nil
}

// Start starts the SOCKS5 server
func (s *Server) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	// Initialize SOCKS5 server logic
	s.server = proxy.NewSOCKS5Server(s.config.ListenAddr, s.handleProxyRequest)

	// Optional Auth
	if s.config.Username != "" && s.config.Password != "" {
		s.server.SetAuthHandler(func(u, p string) bool {
			return u == s.config.Username && p == s.config.Password
		})
	}

	// Start listening
	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			s.SetHealthy(false, fmt.Sprintf("Server error: %v", err))
		}
	}()

	// Start frame receiver
	go s.receiveFrames()

	// Start HevTunnel Sidecar
	if err := s.startHevTunnel(); err != nil {
		s.SetHealthy(false, fmt.Sprintf("Failed to start HevTunnel: %v", err))
		fmt.Printf("[SOCKS5] WARNING: Failed to start HevTunnel: %v\n", err)
	}

	s.SetHealthy(true, fmt.Sprintf("Listening on %s", s.config.ListenAddr))
	s.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"addr": s.config.ListenAddr,
	})

	return nil
}

// Stop stops the module
func (s *Server) Stop() error {
	s.stopHevTunnel()

	// Close all pending connections
	s.streamMu.Lock()
	for _, pc := range s.pendingConns {
		pc.cancel()
	}
	for _, conn := range s.activeStreams {
		conn.Close()
	}
	s.pendingConns = make(map[uint16]*pendingConn)
	s.activeStreams = make(map[uint16]net.Conn)
	s.streamMu.Unlock()

	s.PublishEvent(events.EventTypeModuleStopped, nil)
	return s.Module.Stop()
}

// SetTunnel sets the tunnel manager for encrypted traffic relay
func (s *Server) SetTunnel(t TunnelRelay) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunnel = t
}

func (s *Server) startHevTunnel() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd != nil && s.cmd.Process != nil {
		return nil // Already running
	}

	// Locate binary
	cwd, _ := os.Getwd()
	binPath := filepath.Join(cwd, "core", "hev-socks5-tunnel", "hev-socks5-tunnel.exe")
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		binPath = filepath.Join(cwd, "core", "hev-socks5-tunnel.exe")
		if _, err := os.Stat(binPath); os.IsNotExist(err) {
			return fmt.Errorf("hev-socks5-tunnel.exe not found at %s", binPath)
		}
	}

	// Generate config.yml for hev-socks5-tunnel
	configContent := `tunnel:
  name: "Whispera"
  ipv4: "198.18.0.1"
  ipv6: "fc00::1"
  mtu: 8500

socks5:
  port: 10800
  address: "127.0.0.1"
  udp: "udp"

misc:
  log-file: "stdout"
  limit-nofile: 65535
`
	configPath := filepath.Join(cwd, "core", "hev-config.yml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write hev config: %w", err)
	}

	// Start Process
	cmd := exec.Command(binPath, configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = filepath.Dir(binPath)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start process: %w", err)
	}

	s.cmd = cmd
	fmt.Printf("[SOCKS5] HevTunnel started (PID: %d)\n", cmd.Process.Pid)
	return nil
}

func (s *Server) stopHevTunnel() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill()
		s.cmd = nil
	}
}

// handleProxyRequest is the callback from the SOCKS5 server when a connection is made
func (s *Server) handleProxyRequest(conn net.Conn, targetAddr string, targetPort uint16) error {
	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)

	// Check if tunnel is available and connected
	s.mu.RLock()
	tunnel := s.tunnel
	s.mu.RUnlock()

	if tunnel != nil && tunnel.IsConnected() {
		// Route through encrypted tunnel using relay protocol
		if s.config.Debug {
			fmt.Printf("[SOCKS5] Relaying %s through encrypted tunnel\n", target)
		}
		return s.relayThroughTunnel(conn, targetAddr, targetPort)
	}

	// Direct connection (fallback or no tunnel configured)
	if s.config.Debug {
		fmt.Printf("[SOCKS5] Direct connection to %s\n", target)
	}
	return s.directConnect(conn, target)
}

// relayThroughTunnel sends traffic through the encrypted VPN tunnel using relay protocol
func (s *Server) relayThroughTunnel(conn net.Conn, targetAddr string, targetPort uint16) error {
	// Generate stream ID
	streamID := s.streamIDGen.Next()

	// Determine address type
	var addrType uint8
	ip := net.ParseIP(targetAddr)
	if ip != nil {
		if ip.To4() != nil {
			addrType = relay.AddrTypeIPv4
		} else {
			addrType = relay.AddrTypeIPv6
		}
	} else {
		addrType = relay.AddrTypeDomain
	}

	// Create CONNECT frame
	frame := relay.NewConnectFrame(streamID, relay.ProtoTCP, addrType, targetAddr, targetPort, relay.ProfileBalanced)
	frameData, err := frame.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode frame: %w", err)
	}

	// Register pending connection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	pc := &pendingConn{
		conn:   conn,
		target: fmt.Sprintf("%s:%d", targetAddr, targetPort),
		ready:  make(chan error, 1),
		ctx:    ctx,
		cancel: cancel,
	}

	s.streamMu.Lock()
	s.pendingConns[streamID] = pc
	s.streamMu.Unlock()

	defer func() {
		s.streamMu.Lock()
		delete(s.pendingConns, streamID)
		s.streamMu.Unlock()
		cancel()
	}()

	// Send CONNECT frame
	if err := s.tunnel.Send(frameData); err != nil {
		atomic.AddUint64(&s.connectFailed, 1)
		return fmt.Errorf("failed to send CONNECT frame: %w", err)
	}

	if s.config.Debug {
		fmt.Printf("[SOCKS5] Sent CONNECT frame streamID=%d to %s:%d\n", streamID, targetAddr, targetPort)
	}

	// Wait for CONNECT_OK or CONNECT_FAIL
	select {
	case err := <-pc.ready:
		if err != nil {
			atomic.AddUint64(&s.connectFailed, 1)
			return err
		}
	case <-ctx.Done():
		atomic.AddUint64(&s.connectFailed, 1)
		return fmt.Errorf("connection timeout")
	}

	atomic.AddUint64(&s.connectSuccess, 1)

	if s.config.Debug {
		fmt.Printf("[SOCKS5] Connection established streamID=%d\n", streamID)
	}

	// Register active stream
	s.streamMu.Lock()
	s.activeStreams[streamID] = conn
	s.streamMu.Unlock()

	defer func() {
		s.streamMu.Lock()
		delete(s.activeStreams, streamID)
		s.streamMu.Unlock()

		// Send CLOSE frame
		closeFrame := relay.NewCloseFrame(streamID)
		if data, err := closeFrame.Encode(); err == nil {
			s.tunnel.Send(data)
		}
	}()

	// Start bidirectional relay
	var wg sync.WaitGroup
	wg.Add(1)

	// Client -> Tunnel (send DATA frames)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}

			// Create DATA frame
			dataFrame := relay.NewDataFrame(streamID, buf[:n])
			frameData, err := dataFrame.Encode()
			if err != nil {
				return
			}

			if err := s.tunnel.Send(frameData); err != nil {
				return
			}

			atomic.AddUint64(&s.bytesRelayed, uint64(n))
		}
	}()

	// Tunnel -> Client is handled by receiveFrames goroutine

	wg.Wait()
	return nil
}

// receiveFrames continuously receives frames from the tunnel and dispatches them
func (s *Server) receiveFrames() {
	buf := make([]byte, 65535+relay.HeaderSize)

	for s.IsRunning() {
		s.mu.RLock()
		tunnel := s.tunnel
		s.mu.RUnlock()

		if tunnel == nil || !tunnel.IsConnected() {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		n, err := tunnel.Receive(buf)
		if err != nil {
			if err != io.EOF {
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}

		if n < relay.HeaderSize {
			continue
		}

		// Decode frame
		frame, err := relay.Decode(buf[:n])
		if err != nil {
			if s.config.Debug {
				fmt.Printf("[SOCKS5] Failed to decode frame: %v\n", err)
			}
			continue
		}

		// Handle frame
		s.handleIncomingFrame(frame)
	}
}

// handleIncomingFrame processes frames received from the tunnel
func (s *Server) handleIncomingFrame(frame *relay.Frame) {
	switch frame.Type {
	case relay.FrameConnectOK:
		s.handleConnectOK(frame)
	case relay.FrameConnectFail:
		s.handleConnectFail(frame)
	case relay.FrameData:
		s.handleData(frame)
	case relay.FrameClose:
		s.handleClose(frame)
	case relay.FramePong:
		// Keep-alive response, ignore
	default:
		if s.config.Debug {
			fmt.Printf("[SOCKS5] Unknown frame type: %s\n", relay.FrameTypeName(frame.Type))
		}
	}
}

// handleConnectOK processes CONNECT_OK frame
func (s *Server) handleConnectOK(frame *relay.Frame) {
	s.streamMu.RLock()
	pc, ok := s.pendingConns[frame.StreamID]
	s.streamMu.RUnlock()

	if ok && pc != nil {
		select {
		case pc.ready <- nil:
		default:
		}
	}
}

// handleConnectFail processes CONNECT_FAIL frame
func (s *Server) handleConnectFail(frame *relay.Frame) {
	s.streamMu.RLock()
	pc, ok := s.pendingConns[frame.StreamID]
	s.streamMu.RUnlock()

	if ok && pc != nil {
		reason := string(frame.Payload)
		select {
		case pc.ready <- fmt.Errorf("connection failed: %s", reason):
		default:
		}
	}
}

// handleData processes DATA frame - writes data to SOCKS5 client
func (s *Server) handleData(frame *relay.Frame) {
	s.streamMu.RLock()
	conn, ok := s.activeStreams[frame.StreamID]
	s.streamMu.RUnlock()

	if ok && conn != nil {
		_, err := conn.Write(frame.Payload)
		if err != nil {
			if s.config.Debug {
				fmt.Printf("[SOCKS5] Failed to write to client streamID=%d: %v\n", frame.StreamID, err)
			}
		} else {
			atomic.AddUint64(&s.bytesRelayed, uint64(len(frame.Payload)))
		}
	}
}

// handleClose processes CLOSE frame
func (s *Server) handleClose(frame *relay.Frame) {
	s.streamMu.Lock()
	conn, ok := s.activeStreams[frame.StreamID]
	if ok {
		delete(s.activeStreams, frame.StreamID)
	}
	s.streamMu.Unlock()

	if conn != nil {
		conn.Close()
	}

	if s.config.Debug {
		fmt.Printf("[SOCKS5] Stream closed by server streamID=%d\n", frame.StreamID)
	}
}

// directConnect makes a direct TCP connection to the target
func (s *Server) directConnect(conn net.Conn, target string) error {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	targetConn, err := dialer.Dial("tcp", target)
	if err != nil {
		fmt.Printf("[SOCKS5] Failed to connect to %s: %v\n", target, err)
		return err
	}
	defer targetConn.Close()

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Target
	go func() {
		defer wg.Done()
		io.Copy(targetConn, conn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// Target -> Client
	go func() {
		defer wg.Done()
		io.Copy(conn, targetConn)
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
	return nil
}

// HealthCheck returns health status
func (s *Server) HealthCheck() interfaces.HealthStatus {
	status := s.Module.HealthCheck()

	s.streamMu.RLock()
	status.Details["pending_streams"] = len(s.pendingConns)
	status.Details["active_streams"] = len(s.activeStreams)
	s.streamMu.RUnlock()

	status.Details["connect_success"] = atomic.LoadUint64(&s.connectSuccess)
	status.Details["connect_failed"] = atomic.LoadUint64(&s.connectFailed)
	status.Details["bytes_relayed"] = atomic.LoadUint64(&s.bytesRelayed)

	return status
}
