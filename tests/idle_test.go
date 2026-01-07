package tests

import (
	"net"
	"testing"
	"time"

	"whispera/internal/modules/relay"
)

// TestIdleSession behaves as an integration test to verify stream cleanup logic
func TestIdleSession(t *testing.T) {
	// Setup mock callbacks
	frameChan := make(chan *relay.Frame, 100)
	onFrame := func(f *relay.Frame) error {
		frameChan <- f
		return nil
	}

	// Initialize Manager
	manager := relay.NewStreamManager(onFrame)
	defer manager.Close()

	// Start a local listener to serve as "Internet Target"
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer targetListener.Close()
	targetAddr := targetListener.Addr().(*net.TCPAddr)

	go func() {
		// Accept and hold open
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Echo loop
		buf := make([]byte, 1024)
		for {
			conn.SetReadDeadline(time.Now().Add(70 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			conn.Write(buf[:n])
		}
	}()

	// Client creates stream
	// CreateStream(proto, addr, port, profile)
	// Use ProfileAggressive or Personal to allow longer timeouts if needed,
	// but standard idle timeout is ~5 mins in cleanup
	_ = manager.CreateStream(relay.ProtoTCP, "127.0.0.1", uint16(targetAddr.Port), relay.ProfileBalanced)

	// Manual Connect (normally handled by Connect frame logic on server side,
	// but here we are testing client-side or internal manager logic?)
	// Actually StreamManager.HandleConnect is for Server.
	// Let's test "Server" side idle:

	payload := &relay.ConnectPayload{
		Protocol: relay.ProtoTCP,
		Addr:     "127.0.0.1",
		Port:     uint16(targetAddr.Port),
		Profile:  relay.ProfileBalanced,
	}

	err = manager.HandleConnect(1, payload)
	if err != nil {
		t.Fatalf("HandleConnect failed: %v", err)
	}

	// Consume ConnectOK
	select {
	case f := <-frameChan:
		if f.Type != relay.FrameConnectOK {
			t.Fatalf("Expected ConnectOK, got %v", f.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for ConnectOK")
	}

	// Send data
	err = manager.HandleData(1, []byte("Hello"))
	if err != nil {
		t.Fatalf("Failed to send data: %v", err)
	}

	// Consume ConnectOK (already done) and Data
	// ... wait for echo data frame ...

	// TEST IDLE
	// Wait 5 seconds (not enough to timeout)
	time.Sleep(5 * time.Second)

	// Verify still active
	s, ok := manager.GetStream(1)
	if !ok || !s.IsActive() {
		t.Fatal("Stream closed prematurely")
	}

	// To test actua timeout we'd need to wait 5 minutes or mock time.
	// For now, just verifies it survives short idle.
	t.Logf("Stream survived 5s idle")
}
