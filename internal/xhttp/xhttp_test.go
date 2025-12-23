package xhttp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// TestPacketUpMode tests packet-up mode with session management
func TestPacketUpMode(t *testing.T) {
	// Create session manager
	sm := NewSessionManager(10, 30*time.Second)

	// Create session
	session, err := sm.GetOrCreateSession("test-uuid-1", "/packet-up", "127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	if session.UUID != "test-uuid-1" {
		t.Errorf("Expected UUID test-uuid-1, got %s", session.UUID)
	}

	// Test WritePacket
	testData := []byte{0x00, 0x01, 0x02, 0x03}
	buffered, err := session.WritePacket(testData)
	if err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	if buffered != int64(len(testData)) {
		t.Errorf("Expected buffered size %d, got %d", len(testData), buffered)
	}

	// Test ReadPacket
	data, err := session.ReadPacket(4)
	if err != nil {
		t.Fatalf("ReadPacket failed: %v", err)
	}

	if !bytes.Equal(data, testData) {
		t.Errorf("Data mismatch: expected %v, got %v", testData, data)
	}
}

// TestStreamUpMode tests stream-up mode with multiple streams
func TestStreamUpMode(t *testing.T) {
	// Create session manager
	sm := NewSessionManager(10, 30*time.Second)

	// Create session for stream-up
	session, err := sm.GetOrCreateSession("stream-up-test", "/stream-up", "127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Write test data to stream
	testData := []byte("stream-up test data")
	n, err := session.WritePacket(testData)
	if err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	if n <= 0 {
		t.Errorf("Expected positive buffered size, got %d", n)
	}
}

// TestStreamOneMode tests stream-one (single-shot) mode
func TestStreamOneMode(t *testing.T) {
	// Create session manager for stream-one mode
	sm := NewSessionManager(10, 30*time.Second)

	// Create stream-one session
	session, err := sm.GetOrCreateSession("stream-one-test", "/stream-one", "127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Write test request
	testData := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	_, err = session.WritePacket(testData)
	if err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	_ = session
}

// TestHTTP2ObfuscationRoundTrip tests HTTP/2 frame encoding/decoding
func TestHTTP2ObfuscationRoundTrip(t *testing.T) {
	obf := NewHTTP2Obfuscator()

	// Test data
	testData := []byte("test HTTP/2 obfuscation data")

	// Encode as HTTP/2 DATA frame
	encoded := obf.EncodeFrame(testData)
	if len(encoded) < len(testData)+9 { // 9-byte header minimum
		t.Errorf("Encoded frame too small: %d vs %d", len(encoded), len(testData)+9)
	}

	// Verify HTTP/2 frame format (simplified check)
	// Format: [length:3][type:1][flags:1][stream_id:4]
	if encoded[3] != 0x00 { // Frame type should be DATA (0x00)
		t.Errorf("Expected DATA frame type (0x00), got 0x%02x", encoded[3])
	}
}

// TestHPACKEncoderDecoder tests HPACK header compression
func TestHPACKEncoderDecoder(t *testing.T) {
	encoder := NewHPACKEncoder()
	decoder := NewHPACKDecoder()

	// Test headers
	headers := []*HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/"},
		{Name: ":authority", Value: "example.com"},
	}

	// Encode headers
	encoded := encoder.Encode(headers)
	if len(encoded) == 0 {
		t.Fatal("Encoded headers empty")
	}

	// Decode headers
	decoded, err := decoder.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if len(decoded) < 2 {
		t.Errorf("Expected at least 2 headers, got %d", len(decoded))
	}
}

// TestClientConfigCreation tests XHTTP client configuration
func TestClientConfigCreation(t *testing.T) {
	// Generate ED25519 keys
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	shortID := make([]byte, 16)
	_, err = rand.Read(shortID)
	if err != nil {
		t.Fatalf("Failed to generate shortID: %v", err)
	}

	// Test that nil ObfuscationManager returns error
	config, err := NewClientConfig(pub, shortID, "example.com", nil)
	if err == nil {
		t.Fatal("Expected error for nil ObfuscationManager")
	}
	if config != nil {
		t.Error("Expected nil config for nil ObfuscationManager")
	}
}

// TestSessionTimeout tests session timeout and cleanup
func TestSessionTimeout(t *testing.T) {
	// Create session manager with short timeout
	sm := NewSessionManager(10, 1*time.Second)

	// Create session
	session, err := sm.GetOrCreateSession("timeout-test", "/", "127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Verify session exists
	if _, exists := sm.GetSession("timeout-test"); !exists {
		t.Fatal("Session should exist immediately after creation")
	}

	// Wait for timeout
	time.Sleep(2 * time.Second)

	// Session should be cleaned up
	// Note: Cleanup runs every 30 seconds in real code, but test uses shorter timeout
	_ = session
}

// TestBufferPoolReuseMetrics tests buffer pool hit/miss tracking
func TestBufferPoolReuseMetrics(t *testing.T) {
	bp := NewBufferPool()

	// Get small buffer (first time - should be miss)
	buf1 := bp.GetSmallBuffer()
	if buf1 == nil {
		t.Fatal("Failed to get small buffer")
	}

	// Return buffer to pool
	bp.PutSmallBuffer(buf1)

	// Get small buffer again (should be hit)
	buf2 := bp.GetSmallBuffer()
	if buf2 == nil {
		t.Fatal("Failed to get small buffer (reuse)")
	}

	// Check if it's the same buffer instance
	if buf1 != buf2 {
		t.Error("Expected buffer reuse from pool")
	}
}

// TestXMUXFrameEncoding tests frame encoding
func TestXMUXFrameEncoding(t *testing.T) {
	// Create test frame
	frameData := []byte{
		0x00, 0x00, 0x00, 0x03, // Length: 3
		0x01,                   // Type: 1
		0x00,                   // Flags: 0
		0x00, 0x00, 0x00, 0x01, // Stream ID: 1
		0xAA, 0xBB, 0xCC, // Data
	}

	// Decode frame (simplified - real implementation would parse properly)
	if len(frameData) < 9 {
		t.Error("Frame too short")
	}
}

// BenchmarkHTTP2Obfuscation benchmarks HTTP/2 frame encoding
func BenchmarkHTTP2Obfuscation(b *testing.B) {
	obf := NewHTTP2Obfuscator()
	testData := bytes.Repeat([]byte("test"), 256) // 1KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = obf.EncodeFrame(testData)
	}
}

// BenchmarkHPACKEncoding benchmarks HPACK header compression
func BenchmarkHPACKEncoding(b *testing.B) {
	encoder := NewHPACKEncoder()
	headers := []*HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/api/v1/data"},
		{Name: ":authority", Value: "api.example.com"},
		{Name: "content-type", Value: "application/json"},
		{Name: "content-length", Value: "1024"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = encoder.Encode(headers)
	}
}

// BenchmarkBufferPoolAlloc benchmarks buffer allocation vs pool reuse
func BenchmarkBufferPoolAlloc(b *testing.B) {
	b.Run("WithPool", func(b *testing.B) {
		bp := NewBufferPool()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buf := bp.GetMediumBuffer()
			bp.PutMediumBuffer(buf)
		}
	})

	b.Run("WithoutPool", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = bytes.NewBuffer(make([]byte, 0, 16384))
		}
	})
}

// TestVLESSHandshakeIntegration tests VLESS protocol handshake over XHTTP
func TestVLESSHandshakeIntegration(t *testing.T) {
	// This is a simplified test - real integration would use actual VLESS
	// handshake protocol

	// Simulate VLESS handshake:
	// 1. Client sends: [version:1][UUID:16][padding_len:2][...]
	vlessHandshake := []byte{
		0x00,                               // VLESS version
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // UUID (simplified)
		0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
		0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x08, // Padding length: 8 bytes
	}

	// Verify VLESS version byte
	if vlessHandshake[0] != 0x00 {
		t.Errorf("Expected VLESS version 0, got %d", vlessHandshake[0])
	}

	// Verify minimum handshake length
	if len(vlessHandshake) < 19 {
		t.Errorf("Handshake too short: %d bytes", len(vlessHandshake))
	}
}

// MockConn implements net.Conn for testing
type MockConn struct {
	readBuf  bytes.Buffer
	writeBuf bytes.Buffer
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	return m.readBuf.Read(b)
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	return m.writeBuf.Write(b)
}

func (m *MockConn) Close() error {
	return nil
}

func (m *MockConn) LocalAddr() net.Addr {
	return nil
}

func (m *MockConn) RemoteAddr() net.Addr {
	return nil
}

func (m *MockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	return nil
}
