// Package relay provides the server-side relay module for internet access
package relay

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/logger"

	"golang.org/x/net/proxy"
)

const (
	ModuleName    = "relay.server"
	ModuleVersion = "1.0.0"
)

// Config holds relay module configuration
type Config struct {
	MaxStreams    int    // Maximum concurrent streams
	EnableTCP     bool   // Enable TCP relay
	EnableUDP     bool   // Enable UDP relay
	Debug         bool   // Enable debug logging
	SafeMode      bool   // Force safe profiles (disable Aggressive)
	UpstreamProxy string // Upstream proxy URL (socks5://...)
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		MaxStreams: 10000,
		EnableTCP:  true,
		EnableUDP:  true,
		Debug:      false,
		SafeMode:   true, // Default to Safe Mode
	}
}

// Validate validates configuration
func (c *Config) Validate() error {
	if c.MaxStreams <= 0 {
		c.MaxStreams = 10000
	}
	return nil
}

// Server implements the relay server module
type Server struct {
	*base.Module
	config *Config

	// Stream management
	streamManager *StreamManager
	proxyDialer   proxy.Dialer

	// Transport callback for sending frames to client
	sendFrame func(data []byte, addr net.Addr) error

	// Session to address mapping
	sessionAddrs   map[uint32]net.Addr
	sessionAddrsMu sync.RWMutex

	// Raw packet tracking (packetID -> clientAddr for response routing)
	rawPackets   map[uint32]net.Addr
	rawPacketsMu sync.RWMutex

	// Stats
	framesIn       uint64
	framesOut      uint64
	bytesRelayed   uint64
	activeStreams  uint64
	connectSuccess uint64
	connectFailed  uint64

	log *logger.Logger
	mu  sync.RWMutex
}

// New creates a new relay server
func New(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	s := &Server{
		Module:       base.NewModule(ModuleName, ModuleVersion, []string{"transport.udp"}),
		config:       cfg,
		sessionAddrs: make(map[uint32]net.Addr),
		rawPackets:   make(map[uint32]net.Addr),
		log:          logger.Module("relay"),
	}

	return s, nil
}

// Init initializes the relay server
func (s *Server) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := s.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if relayCfg, ok := cfg.(*Config); ok {
		s.config = relayCfg
	}

	return nil
}

// Start starts the relay server
func (s *Server) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	// Setup upstream proxy if configured
	if s.config.UpstreamProxy != "" {
		u, err := url.Parse(s.config.UpstreamProxy)
		if err != nil {
			s.log.Error("Invalid upstream proxy URL: %v", err)
			return fmt.Errorf("invalid upstream proxy URL: %v", err)
		}

		dialer, err := proxy.FromURL(u, proxy.Direct)
		if err != nil {
			s.log.Error("Failed to create proxy dialer: %v", err)
			return fmt.Errorf("failed to create proxy dialer: %v", err)
		}
		s.proxyDialer = dialer
		s.log.Info("Enabled upstream proxy: %s", u.Redacted())
	}

	// Create stream manager with callback to send frames (with address)
	s.streamManager = NewStreamManager(s.sendFrameToAddrDirect, s.proxyDialer)

	// Start health monitoring loop
	go s.healthLoop()

	s.SetHealthy(true, "relay server running")
	s.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"max_streams": s.config.MaxStreams,
		"tcp_enabled": s.config.EnableTCP,
		"udp_enabled": s.config.EnableUDP,
	})

	s.log.Info("Server started (max streams: %d)", s.config.MaxStreams)
	return nil
}

// Stop stops the relay server
func (s *Server) Stop() error {
	if s.streamManager != nil {
		s.streamManager.Close()
	}

	s.PublishEvent(events.EventTypeModuleStopped, nil)
	s.log.Info("Server stopped")
	return s.Module.Stop()
}

// SetTransport sets the transport callback for sending data back to client
func (s *Server) SetTransport(sendFunc func(data []byte, addr net.Addr) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendFrame = sendFunc
}

// RegisterSession registers a session address for response routing
func (s *Server) RegisterSession(sessionID uint32, addr net.Addr) {
	s.sessionAddrsMu.Lock()
	defer s.sessionAddrsMu.Unlock()
	s.sessionAddrs[sessionID] = addr
}

// UnregisterSession removes a session
func (s *Server) UnregisterSession(sessionID uint32) {
	s.sessionAddrsMu.Lock()
	defer s.sessionAddrsMu.Unlock()
	delete(s.sessionAddrs, sessionID)
}

// ProcessFrame processes an incoming frame from client
func (s *Server) ProcessFrame(data []byte, session interfaces.Session, addr net.Addr) error {
	atomic.AddUint64(&s.framesIn, 1)

	// Register session address for responses
	if session != nil {
		s.RegisterSession(session.ID(), addr)
	}

	// Decode frame
	frame, err := Decode(data)
	if err != nil {
		if s.config.Debug {
			s.log.Debug("Failed to decode frame: %v", err)
		}
		return err
	}

	if s.config.Debug {
		s.log.Debug("Received frame: type=%s streamID=%d len=%d",
			FrameTypeName(frame.Type), frame.StreamID, len(frame.Payload))
	}

	// Handle frame by type
	switch frame.Type {
	case FrameConnect:
		return s.handleConnect(frame, addr)
	case FrameData:
		return s.handleData(frame)
	case FrameClose:
		s.handleClose(frame)
		return nil
	case FramePing:
		return s.handlePing(addr)
	case FrameUDPData:
		return s.handleUDPData(frame)
	case FrameRawPacket:
		return s.handleRawPacket(frame, addr)
	default:
		if s.config.Debug {
			s.log.Debug("Unknown frame type: %d", frame.Type)
		}
		return nil
	}
}

// handleConnect handles CONNECT frame - establishes connection to target
func (s *Server) handleConnect(frame *Frame, addr net.Addr) error {
	payload, err := DecodeConnectPayload(frame.Payload)
	if err != nil {
		atomic.AddUint64(&s.connectFailed, 1)
		s.sendFrameToAddr(NewConnectFailFrame(frame.StreamID, "connection refused"), addr)
		return err
	}

	// Safe Mode Enforcement
	if s.config.SafeMode && payload.Profile == ProfileAggressive {
		if s.config.Debug {
			s.log.Debug("SafeMode: Downgrading stream %d from Aggressive to Personal", frame.StreamID)
		}
		payload.Profile = ProfilePersonal
	}

	// Check protocol support
	if payload.Protocol == ProtoTCP && !s.config.EnableTCP {
		atomic.AddUint64(&s.connectFailed, 1)
		s.sendFrameToAddr(NewConnectFailFrame(frame.StreamID, "connection refused"), addr)
		return fmt.Errorf("TCP relay not enabled")
	}
	if payload.Protocol == ProtoUDP && !s.config.EnableUDP {
		atomic.AddUint64(&s.connectFailed, 1)
		s.sendFrameToAddr(NewConnectFailFrame(frame.StreamID, "connection refused"), addr)
		return fmt.Errorf("UDP relay not enabled")
	}

	if s.config.Debug {
		protoName := "TCP"
		if payload.Protocol == ProtoUDP {
			protoName = "UDP"
		}
		s.log.Debug("CONNECT streamID=%d %s -> %s:%d",
			frame.StreamID, protoName, payload.Addr, payload.Port)
	}

	// Handle connect in stream manager (async)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Silently recover from panic
			}
		}()

		if err := s.streamManager.HandleConnect(frame.StreamID, payload, addr); err != nil {
			atomic.AddUint64(&s.connectFailed, 1)
			if s.config.Debug {
				s.log.Debug("Connect failed streamID=%d: %v", frame.StreamID, err)
			}
		} else {
			atomic.AddUint64(&s.connectSuccess, 1)
			atomic.AddUint64(&s.activeStreams, 1)
			if s.config.Debug {
				s.log.Debug("Connect success streamID=%d", frame.StreamID)
			}
		}
	}()

	return nil
}

// handleData handles DATA frame - forwards data to target
func (s *Server) handleData(frame *Frame) error {
	if err := s.streamManager.HandleData(frame.StreamID, frame.Payload); err != nil {
		if s.config.Debug {
			s.log.Debug("Data forward failed streamID=%d: %v", frame.StreamID, err)
		}
		return err
	}

	atomic.AddUint64(&s.bytesRelayed, uint64(len(frame.Payload)))
	return nil
}

// handleClose handles CLOSE frame
func (s *Server) handleClose(frame *Frame) {
	s.streamManager.HandleClose(frame.StreamID)
	atomic.AddUint64(&s.activeStreams, ^uint64(0)) // Decrement

	if s.config.Debug {
		s.log.Debug("Stream closed streamID=%d", frame.StreamID)
	}
}

// handlePing handles PING frame
func (s *Server) handlePing(addr net.Addr) error {
	return s.sendFrameToAddr(NewPongFrame(), addr)
}

// handleUDPData handles UDP_DATA frame for stateless UDP relay
func (s *Server) handleUDPData(frame *Frame) error {
	// Parse UDP data payload: [AddrType:1][Addr:N][Port:2][Data:N]
	if len(frame.Payload) < 4 {
		return ErrInvalidFrame
	}

	addrType := frame.Payload[0]
	offset := 1
	var targetAddr string
	var targetPort uint16

	switch addrType {
	case AddrTypeIPv4:
		if len(frame.Payload) < offset+4+2+1 {
			return ErrInvalidFrame
		}
		targetAddr = fmt.Sprintf("%d.%d.%d.%d",
			frame.Payload[offset], frame.Payload[offset+1],
			frame.Payload[offset+2], frame.Payload[offset+3])
		offset += 4
	case AddrTypeDomain:
		domainLen := int(frame.Payload[offset])
		offset++
		if len(frame.Payload) < offset+domainLen+2+1 {
			return ErrInvalidFrame
		}
		targetAddr = string(frame.Payload[offset : offset+domainLen])
		offset += domainLen
	default:
		return ErrInvalidFrame
	}

	targetPort = uint16(frame.Payload[offset])<<8 | uint16(frame.Payload[offset+1])
	offset += 2

	data := frame.Payload[offset:]

	// Send UDP packet
	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if s.config.Debug {
		s.log.Debug("UDP sent to %s (%d bytes)", target, len(data))
	}

	atomic.AddUint64(&s.bytesRelayed, uint64(len(data)))
	return err
}

// HandleOutgoingFrame is called when stream has data to send back to client
func (s *Server) HandleOutgoingFrame(frame *Frame) error {
	s.mu.RLock()
	sendFunc := s.sendFrame
	s.mu.RUnlock()

	if sendFunc == nil {
		return fmt.Errorf("transport not set")
	}

	// Encode frame
	data, err := frame.Encode()
	if err != nil {
		return err
	}

	atomic.AddUint64(&s.framesOut, 1)
	atomic.AddUint64(&s.bytesRelayed, uint64(len(frame.Payload)))

	// Get any active session address (simplified - in production would track per-stream)
	s.sessionAddrsMu.RLock()
	var addr net.Addr
	for _, a := range s.sessionAddrs {
		addr = a
		break
	}
	s.sessionAddrsMu.RUnlock()

	if addr == nil {
		return fmt.Errorf("no session address available")
	}

	if s.config.Debug {
		s.log.Debug("Sending frame: type=%s streamID=%d len=%d",
			FrameTypeName(frame.Type), frame.StreamID, len(frame.Payload))
	}

	return sendFunc(data, addr)
}

// sendFrameToAddr sends a frame to a specific address
func (s *Server) sendFrameToAddr(frame *Frame, addr net.Addr) error {
	s.mu.RLock()
	sendFunc := s.sendFrame
	s.mu.RUnlock()

	if sendFunc == nil {
		return fmt.Errorf("transport not set")
	}

	data, err := frame.Encode()
	if err != nil {
		return err
	}

	atomic.AddUint64(&s.framesOut, 1)
	return sendFunc(data, addr)
}

// sendFrameToAddrDirect is a callback for StreamManager that sends frames directly to client address
func (s *Server) sendFrameToAddrDirect(frame *Frame, addr net.Addr) error {
	if s.config.Debug {
		s.log.Debug("Sending frame: type=%s streamID=%d len=%d",
			FrameTypeName(frame.Type), frame.StreamID, len(frame.Payload))
	}
	return s.sendFrameToAddr(frame, addr)
}

// HealthCheck returns health status
func (s *Server) HealthCheck() interfaces.HealthStatus {
	status := s.Module.HealthCheck()

	status.Details["frames_in"] = atomic.LoadUint64(&s.framesIn)
	status.Details["frames_out"] = atomic.LoadUint64(&s.framesOut)
	status.Details["bytes_relayed"] = atomic.LoadUint64(&s.bytesRelayed)
	status.Details["active_streams"] = atomic.LoadUint64(&s.activeStreams)
	status.Details["connect_success"] = atomic.LoadUint64(&s.connectSuccess)
	status.Details["connect_failed"] = atomic.LoadUint64(&s.connectFailed)

	if s.streamManager != nil {
		active, bytesIn, bytesOut := s.streamManager.Stats()
		status.Details["stream_count"] = active
		status.Details["stream_bytes_in"] = bytesIn
		status.Details["stream_bytes_out"] = bytesOut
	}

	return status
}

// Factory creates relay server modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}

// handleRawPacket handles RAW_PACKET frames from client
// These are full IP packets (TCP/UDP/ICMP/etc) from TUN interface
func (s *Server) handleRawPacket(frame *Frame, addr net.Addr) error {
	// Parse raw packet frame
	packetID, rawPacket, err := ParseRawPacketFrame(frame)
	if err != nil {
		if s.config.Debug {
			s.log.Debug("Failed to parse raw packet frame: %v", err)
		}
		return err
	}

	if len(rawPacket) < 20 {
		return fmt.Errorf("raw packet too small: %d bytes", len(rawPacket))
	}

	// Parse IPv4 header (basic validation)
	version := rawPacket[0] >> 4
	if version != 4 {
		// IPv6 or other - could be supported later
		if s.config.Debug {
			s.log.Debug("Raw packet has unsupported IP version: %d", version)
		}
		return nil
	}

	srcIP := net.IPv4(rawPacket[12], rawPacket[13], rawPacket[14], rawPacket[15])
	dstIP := net.IPv4(rawPacket[16], rawPacket[17], rawPacket[18], rawPacket[19])
	protocol := rawPacket[9]

	if s.config.Debug {
		s.log.Debug("Raw packet: ID=%d proto=%d %s->%s len=%d",
			packetID, protocol, srcIP, dstIP, len(rawPacket))
	}

	// Track packet ID -> client address for response routing
	// This allows us to send response packets back to the originating client
	s.rawPacketsMu.Lock()
	s.rawPackets[packetID] = addr
	s.rawPacketsMu.Unlock()

	// Handle specific packet types if possible (e.g., ICMP echo)
	// Protocol: 1=ICMP, 6=TCP, 17=UDP
	if protocol == 1 && len(rawPacket) >= 20+8 {
		// ICMP packet - try to handle echo request
		s.handleICMPPacket(packetID, rawPacket, srcIP, dstIP, addr)
	}

	// TODO: Implement packet injection/forwarding
	// This is where we would:
	// 1. Inject the packet into the system's network stack
	// 2. Or use raw socket API to forward it
	// 3. When response comes back, use SendRawPacketToAddr to send it back to client

	atomic.AddUint64(&s.bytesRelayed, uint64(len(rawPacket)))

	return nil
}

// SendRawPacket sends a raw IP packet to a client through the tunnel
// Used by server-side components to send response packets back to clients
// Note: This is meant to be called by handlers that need to send packets back,
// not by TUN handlers directly - see SendRawPacketToAddr for that
func (s *Server) SendRawPacket(packetID uint32, data []byte) error {
	// For direct SendRawPacket without explicit client address,
	// we would need to track client addresses. For now, use the
	// SendRawPacketToAddr variant which is more explicit.
	s.log.Warn("SendRawPacket called without client address - use SendRawPacketToAddr instead")
	return fmt.Errorf("SendRawPacket requires client address context")
}

// SendRawPacketToAddr sends a raw IP packet to a specific client through the tunnel
// This is the primary method for sending response packets to clients
func (s *Server) SendRawPacketToAddr(packetID uint32, data []byte, addr net.Addr) error {
	if addr == nil {
		return fmt.Errorf("invalid client address for raw packet response")
	}

	frame := NewRawPacketFrame(packetID, data)
	if frame == nil {
		return fmt.Errorf("failed to create raw packet frame")
	}

	if s.config.Debug {
		s.log.Debug("Sending raw packet response: ID=%d len=%d to %s",
			packetID, len(data), addr)
	}

	// Clean up packet tracking after sending response
	defer func() {
		s.rawPacketsMu.Lock()
		delete(s.rawPackets, packetID)
		s.rawPacketsMu.Unlock()
	}()

	return s.sendFrameToAddr(frame, addr)
}

// SendResponsePacket sends a response packet to the original client
// Uses packetID to look up which client to send to
func (s *Server) SendResponsePacket(packetID uint32, data []byte) error {
	// Get client address from tracking
	clientAddr := s.GetRawPacketClientAddr(packetID)
	if clientAddr == nil {
		return fmt.Errorf("client address not found for packet ID %d", packetID)
	}

	return s.SendRawPacketToAddr(packetID, data, clientAddr)
}

// GetRawPacketClientAddr retrieves the client address for a given packet ID
// Used when we receive response packets and need to route them back to the client
func (s *Server) GetRawPacketClientAddr(packetID uint32) net.Addr {
	s.rawPacketsMu.RLock()
	defer s.rawPacketsMu.RUnlock()
	return s.rawPackets[packetID]
}

// handleICMPPacket handles ICMP packets (primarily echo requests)
// Returns ICMP echo reply for testing purposes
func (s *Server) handleICMPPacket(packetID uint32, rawPacket []byte, srcIP, dstIP net.IP, addr net.Addr) {
	if len(rawPacket) < 20+8 {
		return // Too small for ICMP header
	}

	icmpType := rawPacket[20]
	_ = rawPacket[21] // icmpCode - unused for now

	if icmpType == 8 { // Echo request
		// Create echo reply (type 0)
		replyPacket := make([]byte, len(rawPacket))
		copy(replyPacket, rawPacket)

		// Swap IP addresses
		copy(replyPacket[12:16], dstIP.To4())
		copy(replyPacket[16:20], srcIP.To4())

		// Change ICMP type to echo reply (0)
		replyPacket[20] = 0

		// Recalculate ICMP checksum (simplified - just zero it for now)
		// Proper checksum calculation would be needed for production
		replyPacket[22] = 0
		replyPacket[23] = 0

		// Recalculate IPv4 checksum
		// Zero the checksum field first
		replyPacket[10] = 0
		replyPacket[11] = 0

		// Calculate new checksum (simplified)
		checksum := calculateIPChecksum(replyPacket[:20])
		replyPacket[10] = byte(checksum >> 8)
		replyPacket[11] = byte(checksum)

		// Send reply back to client
		if s.config.Debug {
			s.log.Debug("Sending ICMP echo reply: %s->%s (ID=%d)", srcIP, dstIP, packetID)
		}

		s.SendRawPacketToAddr(packetID, replyPacket, addr)
	}
}

// calculateIPChecksum calculates IPv4 header checksum
func calculateIPChecksum(header []byte) uint16 {
	if len(header) < 20 {
		return 0
	}

	sum := uint32(0)

	// Sum all 16-bit words
	for i := 0; i < 20; i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}

	// Fold back carries
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// Return one's complement
	return ^uint16(sum)
}

// healthLoop runs periodic health checks
func (s *Server) healthLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.Context().Done():
			return
		case <-ticker.C:
			// Collect stats
			activeStreams := atomic.LoadUint64(&s.activeStreams)
			bytesRelayed := atomic.LoadUint64(&s.bytesRelayed)

			// Check thresholds
			if activeStreams > uint64(s.config.MaxStreams) {
				s.log.Warn("Active streams (%d) exceeds max (%d)",
					activeStreams, s.config.MaxStreams)
			}

			if s.config.Debug {
				s.log.Debug("Health: Streams=%d, Bytes=%d", activeStreams, bytesRelayed)
			}

			// Run FSM self-checks on streams
			if s.streamManager != nil {
				// Could iterate streams and call fsm.SelfCheck()
			}
		}
	}
}
