// Package tun_handler manages raw IP packet handling for TUN interface.
package tun_handler

import (
	"fmt"
	stdlog "log"
	"net"
	"os"
	"sync"
	"time"

	"whispera/internal/logger"
)

var log = logger.Module("tun_handler")

// RelayClient interface for sending packets through tunnel
type RelayClient interface {
	SendRawPacket(packetID uint32, data []byte) error
}

// Config for TUN handler
type Config struct {
	TUNInterface string        // Interface name (e.g., "Whispera")
	TUNAddr      string        // TUN IP address (e.g., "10.0.85.1")
	BufferSize   int           // Read buffer size
	MTU          int           // MTU size
	PacketChan   chan []byte   // Channel to send packets
	SendTimeout  time.Duration // Timeout for sending packets
}

// Handler manages TUN interface packet reading/writing
type Handler struct {
	config       *Config
	mu           sync.RWMutex
	file         *os.File
	packets      chan *Packet
	stop         chan struct{}
	wg           sync.WaitGroup
	running      bool
	tunName      string
	relay        RelayClient // Client to send packets through tunnel
	packetID     uint32
	idMu         sync.Mutex
	onPacketRecv func(*Packet) // Callback for received packets

	// WinTun device integration
	tunDevice   *WinTunDevice           // WinTun device for packet I/O
	injector    *PacketInjector         // Packet injector for responses
	icmpHandler *ICMPHandler            // ICMP echo handler for testing
	simCapture  *SimulatedPacketCapture // Simulated capture for testing
}

// Packet represents a TUN packet
type Packet struct {
	ID       uint32    // Unique packet ID
	Data     []byte    // Raw packet data
	Received time.Time // When received
	SrcIP    net.IP    // Source IP (parsed)
	DstIP    net.IP    // Destination IP (parsed)
	Protocol uint8     // Protocol number (TCP=6, UDP=17, ICMP=1)
}

// New creates a new TUN handler
func New(cfg *Config) (*Handler, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config required")
	}

	if cfg.BufferSize == 0 {
		cfg.BufferSize = 4096
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}
	if cfg.SendTimeout == 0 {
		cfg.SendTimeout = 5 * time.Second
	}

	h := &Handler{
		config:  cfg,
		packets: make(chan *Packet, 100),
		stop:    make(chan struct{}),
		tunName: cfg.TUNInterface,
	}

	return h, nil
}

// Start begins reading from TUN interface
func (h *Handler) Start() error {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return fmt.Errorf("handler already running")
	}
	h.running = true
	h.mu.Unlock()

	stdlog.Printf("[TUN Handler] Starting TUN handler for interface: %s\n", h.tunName)
	log.Info("Starting TUN handler for interface: %s", h.tunName)

	// Initialize WinTun Device
	if err := h.InitializeWinTunDevice(); err != nil {
		log.Warn("Failed to initialize WinTun device: %v. Falling back...", err)
	} else {
		if err := h.tunDevice.Open(); err != nil {
			log.Error("Failed to open WinTun device: %v", err)
			return err
		}
		if err := h.tunDevice.ReadPackets(); err != nil {
			log.Error("Failed to start reading packets: %v", err)
			return err
		}
	}

	// Start packet reader goroutine
	h.wg.Add(1)
	go h.readLoop()

	return nil
}

// Stop stops the TUN handler
func (h *Handler) Stop() error {
	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return nil
	}
	h.running = false
	h.mu.Unlock()

	close(h.stop)
	h.wg.Wait()

	if h.tunDevice != nil {
		h.tunDevice.Close()
	}

	stdlog.Printf("[TUN Handler] TUN handler stopped\n")
	log.Info("TUN handler stopped")
	return nil
}

// SetRelayClient sets the relay client for sending packets
func (h *Handler) SetRelayClient(client RelayClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.relay = client
	stdlog.Printf("[TUN Handler] Relay client set\n")
}

// SetPacketRecvCallback sets callback for received packets
// This is used for response packets coming from server
func (h *Handler) SetPacketRecvCallback(fn func(*Packet)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onPacketRecv = fn
	stdlog.Printf("[TUN Handler] Packet receive callback set\n")
}

// GetNextPacketID returns next packet ID
func (h *Handler) GetNextPacketID() uint32 {
	h.idMu.Lock()
	defer h.idMu.Unlock()
	h.packetID++
	return h.packetID
}

// readLoop reads packets from TUN interface
func (h *Handler) readLoop() {
	defer h.wg.Done()

	// Prioritize WinTun reading
	if h.tunDevice != nil && h.tunDevice.IsRunning() {
		h.readWinTunPackets()
		return
	}

	// Fall back to simulated packet capture for testing
	if h.simCapture != nil {
		h.simCapture.Start()
		h.readSimulatedPackets()
		h.simCapture.Stop()
		return
	}
}

// readWinTunPackets reads packets from WinTun device
func (h *Handler) readWinTunPackets() {
	packetChan := h.tunDevice.GetPacketChannel()

	for {
		select {
		case <-h.stop:
			return
		case data := <-packetChan:
			if data != nil {
				h.HandleIncomingPacket(data)
			}
		}
	}
}

// readSimulatedPackets reads packets from simulated capture
func (h *Handler) readSimulatedPackets() {
	packetChan := h.simCapture.GetChannel()

	for {
		select {
		case <-h.stop:
			return
		case packet := <-packetChan:
			if packet != nil {
				h.HandleIncomingPacket(packet)
			}
		}
	}
}

// WritePacket writes a packet to TUN interface (for response traffic)
func (h *Handler) WritePacket(pkt *Packet) error {
	if pkt == nil || len(pkt.Data) == 0 {
		return fmt.Errorf("invalid packet")
	}

	h.mu.RLock()
	running := h.running
	device := h.tunDevice
	h.mu.RUnlock()

	if !running {
		return fmt.Errorf("handler not running")
	}

	// Write packet back to TUN via WinTunDevice
	if device != nil {
		return device.WritePacket(pkt.Data)
	}

	return nil
}

// ReceiveResponsePacket processes a response packet from server
// This is called when the relay layer receives a response packet from the server
// and needs to deliver it to the TUN interface
func (h *Handler) ReceiveResponsePacket(packetID uint32, data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("response packet too small: %d bytes", len(data))
	}

	// Parse IP header from response
	version := data[0] >> 4
	if version != 4 {
		return fmt.Errorf("unsupported IP version: %d", version)
	}

	srcIP := net.IPv4(data[12], data[13], data[14], data[15])
	dstIP := net.IPv4(data[16], data[17], data[18], data[19])
	protocol := data[9]

	pkt := &Packet{
		ID:       packetID,
		Data:     data,
		Received: time.Now(),
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: protocol,
	}

	log.Debug("Response packet received: ID=%d %s->%s proto=%d", packetID, srcIP, dstIP, protocol)

	// Call receive callback if set
	h.mu.RLock()
	callback := h.onPacketRecv
	h.mu.RUnlock()

	if callback != nil {
		callback(pkt)
	}

	// Write to TUN interface
	return h.WritePacket(pkt)
}

// HandleIncomingPacket processes an incoming packet from TUN
// This is called by the packet reader
func (h *Handler) HandleIncomingPacket(data []byte) error {
	// Send through relay if available
	h.mu.RLock()
	relayClient := h.relay
	h.mu.RUnlock()

	if relayClient != nil {
		// Use packet ID 0 for new packets (or generate one)
		// For simple relaying, just send raw data
		// But Handler struct has packet ID logic
		pid := h.GetNextPacketID()

		// Optimization: avoid full Packet struct creation if just relaying
		// unless logging needs it.
		// For now, let's keep it simple and fast.
		return relayClient.SendRawPacket(pid, data)
	}

	return nil
}

// InitializeWinTunDevice initializes WinTun device for packet I/O
func (h *Handler) InitializeWinTunDevice() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.tunDevice != nil {
		return fmt.Errorf("WinTun device already initialized")
	}

	// Create WinTun device
	// Buffer size 100 for channel
	device := NewWinTunDevice(h.config.TUNInterface, 100)
	h.tunDevice = device

	stdlog.Printf("[TUN Handler] WinTun device created for interface: %s\n", h.config.TUNInterface)
	return nil
}

// InitializePacketInjector initializes packet injector for responses
func (h *Handler) InitializePacketInjector() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.injector != nil {
		return fmt.Errorf("packet injector already initialized")
	}

	injector := NewPacketInjector(h.config.TUNInterface)
	if err := injector.Initialize(); err != nil {
		stdlog.Printf("[TUN Handler] Packet injector initialization failed: %v (non-critical)\n", err)
		// Don't fail - we can still work without injection
	}

	h.injector = injector
	return nil
}

// InitializeICMPHandler initializes ICMP echo handler for testing
func (h *Handler) InitializeICMPHandler() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.icmpHandler != nil {
		return fmt.Errorf("ICMP handler already initialized")
	}

	h.icmpHandler = NewICMPHandler()
	stdlog.Printf("[TUN Handler] ICMP handler initialized\n")
	return nil
}

// InitializeSimulatedCapture initializes simulated packet capture for testing
func (h *Handler) InitializeSimulatedCapture() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.simCapture != nil {
		return fmt.Errorf("simulated capture already initialized")
	}

	h.simCapture = NewSimulatedPacketCapture(h.config.BufferSize)
	stdlog.Printf("[TUN Handler] Simulated packet capture initialized\n")
	return nil
}

// HealthCheck returns handler status
func (h *Handler) HealthCheck() error {
	h.mu.RLock()
	running := h.running
	device := h.tunDevice
	h.mu.RUnlock()

	if !running {
		return fmt.Errorf("handler not running")
	}

	if device != nil && !device.IsRunning() {
		return fmt.Errorf("WinTun device not running")
	}

	return nil
}
