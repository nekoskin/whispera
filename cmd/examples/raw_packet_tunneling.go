package main

import (
	"fmt"
	"log"

	"whispera/internal/modules/relay"
	"whispera/internal/modules/tun_handler"
)

// ExampleRawPacketTunneling demonstrates raw packet tunneling system
func ExampleRawPacketTunneling() {
	fmt.Println("=== Raw Packet Tunneling System Example ===\n")

	// Step 1: Create TUN handler
	fmt.Println("1. Creating TUN handler...")
	cfg := &tun_handler.Config{
		TUNInterface: "Whispera",
		TUNAddr:      "10.0.85.1",
		MTU:          1280,
		BufferSize:   1024,
	}

	handler, err := tun_handler.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create handler: %v", err)
	}
	fmt.Println("   ✓ Handler created\n")

	// Step 2: Initialize simulated capture for demo
	fmt.Println("2. Initializing simulated packet capture...")
	if err := handler.InitializeSimulatedCapture(); err != nil {
		log.Fatalf("Failed to initialize capture: %v", err)
	}
	fmt.Println("   ✓ Simulated capture ready\n")

	// Step 3: Demonstrate frame creation
	fmt.Println("3. Creating test ICMP echo packet...")
	testPacket := []byte{
		// IPv4 header
		0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00,
		0x40, 0x01, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x64,
		0x08, 0x08, 0x08, 0x08,
		// ICMP echo request
		0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
		// Payload (32 bytes)
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	fmt.Printf("   ✓ Test packet created: %d bytes\n\n", len(testPacket))

	// Step 4: Process packet through handler
	fmt.Println("4. Processing packet through handler...")
	if err := handler.HandleIncomingPacket(testPacket); err != nil {
		log.Fatalf("Failed to handle packet: %v", err)
	}
	fmt.Println("   ✓ Packet processed\n")

	// Step 5: Demonstrate frame encoding/decoding
	fmt.Println("5. Demonstrating RawPacketFrame encoding...")
	packetID := uint32(12345)
	frame := relay.NewRawPacketFrame(packetID, testPacket)
	if frame == nil {
		log.Fatal("Failed to create frame")
	}
	fmt.Printf("   ✓ Frame created: type=0x%02x, payload=%d bytes\n\n", frame.Type, len(frame.Payload))

	// Step 6: Encode frame
	fmt.Println("6. Encoding frame to binary...")
	encoded, err := frame.Encode()
	if err != nil {
		log.Fatalf("Failed to encode: %v", err)
	}
	fmt.Printf("   ✓ Frame encoded: %d bytes total\n", len(encoded))
	fmt.Printf("   Header: %d bytes, Payload: %d bytes\n\n", relay.HeaderSize, len(frame.Payload))

	// Step 7: Decode frame
	fmt.Println("7. Decoding frame from binary...")
	decoded, err := relay.Decode(encoded)
	if err != nil {
		log.Fatalf("Failed to decode: %v", err)
	}
	fmt.Printf("   ✓ Frame decoded: type=0x%02x\n\n", decoded.Type)

	// Step 8: Parse raw packet
	fmt.Println("8. Parsing raw packet from frame...")
	decodedID, rawPacket, err := relay.ParseRawPacketFrame(decoded)
	if err != nil {
		log.Fatalf("Failed to parse: %v", err)
	}
	fmt.Printf("   ✓ Packet parsed:\n")
	fmt.Printf("     - Packet ID: %d (expected %d)\n", decodedID, packetID)
	fmt.Printf("     - Packet size: %d bytes\n", len(rawPacket))

	// Verify packet
	if decodedID == packetID && len(rawPacket) == len(testPacket) {
		fmt.Println("     - Data integrity: OK\n")
	} else {
		log.Fatal("Data integrity check failed")
	}

	// Step 9: Parse IP header
	fmt.Println("9. Parsing IPv4 header...")
	version := rawPacket[0] >> 4
	srcIP := fmt.Sprintf("%d.%d.%d.%d", rawPacket[12], rawPacket[13], rawPacket[14], rawPacket[15])
	dstIP := fmt.Sprintf("%d.%d.%d.%d", rawPacket[16], rawPacket[17], rawPacket[18], rawPacket[19])
	protocol := rawPacket[9]

	fmt.Printf("   ✓ IPv4 packet:\n")
	fmt.Printf("     - Version: %d\n", version)
	fmt.Printf("     - Source: %s\n", srcIP)
	fmt.Printf("     - Destination: %s\n", dstIP)
	fmt.Printf("     - Protocol: %d (ICMP)\n\n", protocol)

	// Step 10: Handle ICMP
	if protocol == 1 {
		fmt.Println("10. Handling ICMP echo request...")
		
		// Create ICMP handler
		icmpHandler := tun_handler.NewICMPHandler()
		
		// Generate echo reply
		response, err := icmpHandler.HandleEchoRequest(rawPacket)
		if err != nil {
			log.Fatalf("Failed to handle ICMP: %v", err)
		}
		
		fmt.Printf("    ✓ ICMP echo reply created: %d bytes\n", len(response))
		
		// Parse response
		respSrcIP := fmt.Sprintf("%d.%d.%d.%d", response[12], response[13], response[14], response[15])
		respDstIP := fmt.Sprintf("%d.%d.%d.%d", response[16], response[17], response[18], response[19])
		respType := response[20]
		
		fmt.Printf("    - Source: %s -> %s\n", srcIP, respSrcIP)
		fmt.Printf("    - Destination: %s -> %s\n", dstIP, respDstIP)
		fmt.Printf("    - Type: 8 (Echo Request) -> %d (Echo Reply)\n\n", respType)
	}

	fmt.Println("=== Example Complete ===")
	fmt.Println("\nKey Components:")
	fmt.Println("  • TUN Handler: Reads packets from TUN interface")
	fmt.Println("  • RawPacketFrame: Encapsulates any IP packet")
	fmt.Println("  • Relay Protocol: Transmits through encrypted tunnel")
	fmt.Println("  • ICMP Handler: Generates echo replies for ping")
	fmt.Println("  • Packet Injector: Delivers responses to network")
}

// ExampleDataFlow demonstrates the complete data flow
func ExampleDataFlow() {
	fmt.Println("\n=== Data Flow Example ===\n")

	fmt.Println("Outbound Traffic (App -> TUN -> Tunnel -> Server -> Internet):")
	fmt.Println("  1. Application creates packet (e.g., ping 8.8.8.8)")
	fmt.Println("  2. Route points to TUN interface (10.0.85.1)")
	fmt.Println("  3. TUN Handler captures packet")
	fmt.Println("  4. Parses IP header (source, dest, protocol)")
	fmt.Println("  5. Creates RawPacketFrame with packet ID")
	fmt.Println("  6. Sends through encrypted VPN tunnel")
	fmt.Println("  7. Server receives and injects into network")
	fmt.Println("  8. Internet destination receives packet\n")

	fmt.Println("Inbound Traffic (Internet -> Server -> Tunnel -> TUN -> App):")
	fmt.Println("  1. Internet sends response packet")
	fmt.Println("  2. Server identifies originating request")
	fmt.Println("  3. Creates response RawPacketFrame")
	fmt.Println("  4. Sends through encrypted VPN tunnel")
	fmt.Println("  5. Client receives RawPacketFrame")
	fmt.Println("  6. TUN Handler injects to TUN interface")
	fmt.Println("  7. Application receives response\n")
}

func main() {
	ExampleRawPacketTunneling()
	ExampleDataFlow()
}
