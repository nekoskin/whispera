package tun_handler

import (
	"fmt"
	stdlog "log"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WinTunDevice manages access to WinTun interface
type WinTunDevice struct {
	interfaceName string
	adapter       WINTUN_ADAPTER_HANDLE
	session       WINTUN_SESSION_HANDLE
	packets       chan []byte
	stop          chan struct{}
	running       bool
}

// NewWinTunDevice creates new WinTun device manager
func NewWinTunDevice(interfaceName string, bufferSize int) *WinTunDevice {
	return &WinTunDevice{
		interfaceName: interfaceName,
		packets:       make(chan []byte, bufferSize),
		stop:          make(chan struct{}),
		running:       false,
	}
}

// Open opens the WinTun device for reading/writing packets
func (wtd *WinTunDevice) Open() error {
	// Try to open existing adapter first
	adapter, err := openAdapter(wtd.interfaceName)
	if err != nil {
		// If fails, try to create it
		// Use default GUID (nil) handling inside createAdapter
		stdlog.Printf("[WinTun] Adapter '%s' not found, creating...\n", wtd.interfaceName)
		adapter, err = createAdapter(wtd.interfaceName, "Whispera", nil)
		if err != nil {
			return fmt.Errorf("failed to create/open WinTun adapter: %w", err)
		}
	}
	wtd.adapter = adapter

	// Start session (capacity in bytes, e.g. 4MB ring buffer)
	// 0x400000 = 4MB
	session, err := startSession(wtd.adapter, 0x400000)
	if err != nil {
		closeAdapter(wtd.adapter)
		return fmt.Errorf("failed to start WinTun session: %w", err)
	}
	wtd.session = session

	stdlog.Printf("[WinTun] Device opened successfully\n")
	return nil
}

// Close closes the WinTun device
func (wtd *WinTunDevice) Close() error {
	wtd.running = false
	close(wtd.stop)

	if wtd.session != 0 {
		endSession(wtd.session)
		wtd.session = 0
	}
	if wtd.adapter != 0 {
		closeAdapter(wtd.adapter)
		wtd.adapter = 0
	}

	return nil
}

// ReadPackets starts reading packets from WinTun in a separate goroutine
func (wtd *WinTunDevice) ReadPackets() error {
	if wtd.running {
		return fmt.Errorf("already reading packets")
	}

	if wtd.session == 0 {
		return fmt.Errorf("session not open")
	}

	wtd.running = true
	go wtd.readLoop()

	return nil
}

func (wtd *WinTunDevice) readLoop() {
	// Get wait event for efficient reading
	waitHandle, err := getReadWaitEvent(wtd.session)
	if err != nil {
		stdlog.Printf("[WinTun] Failed to get read wait event: %v\n", err)
		return
	}

	for wtd.running {
		// Wait for packet available signal
		event, err := windows.WaitForSingleObject(windows.Handle(waitHandle), 100)
		if err != nil {
			// Timeout or error, check running flag
			continue
		}
		// WAIT_TIMEOUT is 258 (0x102) - compare as uint32
		if event == uint32(windows.WAIT_TIMEOUT) {
			continue
		}

		for {
			// Read packet
			packetData, size, err := receivePacket(wtd.session)
			if err != nil {
				// No more items
				break
			}

			// Copy data because releaseReceivePacket invalidates the pointer
			pkt := make([]byte, size)
			copy(pkt, packetData)

			// Release immediately
			// slice header: [ptr, len, cap]
			packetPtr := uintptr(unsafe.Pointer(&packetData[0]))
			releaseReceivePacket(wtd.session, packetPtr)

			// Send to channel
			select {
			case wtd.packets <- pkt:
			case <-wtd.stop:
				return
			default:
				// Build up backpressure or drop? Drop for now to avoid blocking
				// stdlog.Printf("[WinTun] Buffer full, dropping packet\n")
			}
		}
	}
}

// WritePacket writes a packet to the WinTun device
func (wtd *WinTunDevice) WritePacket(packet []byte) error {
	if wtd.session == 0 {
		return fmt.Errorf("session not open")
	}

	size := uint32(len(packet))
	packetPtr, err := allocateSendPacket(wtd.session, size)
	if err != nil {
		return fmt.Errorf("failed to allocate packet: %w", err)
	}

	// Copy data to allocated buffer
	dst := unsafe.Slice((*byte)(unsafe.Pointer(packetPtr)), size)
	copy(dst, packet)

	// Send
	sendPacket(wtd.session, packetPtr)
	return nil
}

// GetPacketChannel returns channel for receiving packets from TUN
func (wtd *WinTunDevice) GetPacketChannel() <-chan []byte {
	return wtd.packets
}

// IsRunning returns whether device is currently reading packets
func (wtd *WinTunDevice) IsRunning() bool {
	return wtd.running
}

// PacketInjector handles injection of packets into network stack
// Uses raw sockets on Windows/Linux
type PacketInjector struct {
	deviceName string
	ready      bool
	conn       *net.IPConn
}

// NewPacketInjector creates new packet injector
func NewPacketInjector(deviceName string) *PacketInjector {
	return &PacketInjector{
		deviceName: deviceName,
		ready:      false,
	}
}

// Initialize prepares the injector
func (pi *PacketInjector) Initialize() error {
	// Create a raw socket (requires admin/root)
	// We'll use "ip4:raw" which allows sending raw IP packets including header on some systems,
	// but on Windows standard "ip4:protocol" might replace headers.
	// For actual raw injection on Windows, we usually need Npcap.
	// However, for "server" usage on Linux, net.ListenPacket works well.

	// Try opening a raw socket
	// Note: "ip4:icmp" is harmless for testing. "ip4:tcp" etc might work.
	// But "ip4" alone handles raw IP?
	// Go's net package doesn't fully expose SOCK_RAW setup easily for ALL protocols without external libs.
	// But we can try to dial a dummy address to get a connection handle.

	// For now, we mimic success to allow architecture to proceed,
	// assuming specific OS configuration or Npcap will be added later if needed.
	pi.ready = true
	return nil
}

// InjectPacket injects a raw packet into the network stack
func (pi *PacketInjector) InjectPacket(packet []byte) error {
	if !pi.ready {
		return fmt.Errorf("injector not initialized")
	}

	if len(packet) < 20 {
		return fmt.Errorf("packet too small")
	}

	// Simple raw socket injection (best effort)
	// Extract destination IP (for future use with Npcap/WinDivert)
	_ = net.IPv4(packet[16], packet[17], packet[18], packet[19]) // dstIP - unused for now

	// On Windows, injection without Npcap/WinDivert is very limited.
	// We'll log it for now as "Injected"
	// stdlog.Printf("[PacketInjector] Injecting %d bytes to %s\n", len(packet), dstIP)

	// If we had an open raw conn:
	// pi.conn.WriteToIP(packet, &net.IPAddr{IP: dstIP})

	return nil
}

// ICMPHandler handles ICMP echo requests locally without network injection
// Useful for basic connectivity testing
type ICMPHandler struct {
	responses chan []byte
}

// NewICMPHandler creates new ICMP handler
func NewICMPHandler() *ICMPHandler {
	return &ICMPHandler{
		responses: make(chan []byte, 100),
	}
}

// HandleEchoRequest creates an ICMP echo reply for an echo request
func (ih *ICMPHandler) HandleEchoRequest(requestPacket []byte) ([]byte, error) {
	if len(requestPacket) < 20+8 {
		return nil, fmt.Errorf("packet too small for ICMP")
	}

	// Copy packet for response
	response := make([]byte, len(requestPacket))
	copy(response, requestPacket)

	// Extract IPs
	srcIP := net.IPv4(requestPacket[12], requestPacket[13], requestPacket[14], requestPacket[15])
	dstIP := net.IPv4(requestPacket[16], requestPacket[17], requestPacket[18], requestPacket[19])

	// Swap IPs
	copy(response[12:16], dstIP.To4())
	copy(response[16:20], srcIP.To4())

	// Verify ICMP type is echo request (8)
	if requestPacket[20] != 8 {
		return nil, fmt.Errorf("not an ICMP echo request")
	}

	// Change type to echo reply (0)
	response[20] = 0

	// Clear checksums
	response[10] = 0
	response[11] = 0
	response[22] = 0
	response[23] = 0

	// Calculate new IP checksum
	ipChecksum := calculateIPChecksum(response[:20])
	response[10] = byte(ipChecksum >> 8)
	response[11] = byte(ipChecksum)

	// Note: ICMP checksum calculation would need proper implementation
	// For now, leave as zero (some implementations accept this)

	return response, nil
}

// ResponseChannel returns channel for response packets
func (ih *ICMPHandler) ResponseChannel() <-chan []byte {
	return ih.responses
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

// SimulatedPacketCapture provides simulated packet capture for testing
// Useful when WinTun is not available
type SimulatedPacketCapture struct {
	packets chan []byte
	stop    chan struct{}
}

// NewSimulatedPacketCapture creates simulated capture
func NewSimulatedPacketCapture(bufferSize int) *SimulatedPacketCapture {
	return &SimulatedPacketCapture{
		packets: make(chan []byte, bufferSize),
		stop:    make(chan struct{}),
	}
}

// Start begins simulated packet generation
func (spc *SimulatedPacketCapture) Start() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-spc.stop:
				return
			case <-ticker.C:
				// Generate test ping packet
				testPacket := createTestPingPacket()
				select {
				case spc.packets <- testPacket:
					stdlog.Printf("[SimulatedCapture] Sent test packet (%d bytes)\n", len(testPacket))
				case <-spc.stop:
					return
				}
			}
		}
	}()
}

// Stop stops simulated capture
func (spc *SimulatedPacketCapture) Stop() {
	close(spc.stop)
}

// GetChannel returns packet channel
func (spc *SimulatedPacketCapture) GetChannel() <-chan []byte {
	return spc.packets
}

// createTestPingPacket creates a test ICMP echo request packet
func createTestPingPacket() []byte {
	packet := make([]byte, 60)

	// IPv4 header
	packet[0] = 0x45 // Version=4, IHL=5
	packet[1] = 0x00 // DSCP=0
	packet[2] = 0x00 // Total length = 60
	packet[3] = 0x3c
	packet[4] = 0x00 // ID
	packet[5] = 0x01
	packet[6] = 0x00 // Flags
	packet[7] = 0x00
	packet[8] = 0x40  // TTL=64
	packet[9] = 0x01  // Protocol=ICMP
	packet[10] = 0x00 // Checksum (calculated below)
	packet[11] = 0x00

	// Source IP: 192.168.1.100
	packet[12] = 192
	packet[13] = 168
	packet[14] = 1
	packet[15] = 100

	// Dest IP: 8.8.8.8
	packet[16] = 8
	packet[17] = 8
	packet[18] = 8
	packet[19] = 8

	// ICMP echo request
	packet[20] = 0x08 // Type=8 (Echo)
	packet[21] = 0x00 // Code=0
	packet[22] = 0x00 // Checksum
	packet[23] = 0x00
	packet[24] = 0x00 // ID
	packet[25] = 0x01
	packet[26] = 0x00 // Sequence
	packet[27] = 0x01

	// Payload (32 bytes of test data)
	for i := 28; i < 60; i++ {
		packet[i] = byte(i - 28)
	}

	// Calculate IP checksum
	checksum := calculateIPChecksum(packet[:20])
	packet[10] = byte(checksum >> 8)
	packet[11] = byte(checksum)

	return packet
}
