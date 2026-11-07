package tcp

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTransportAcceptDial(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}
	_ = tr.Init(context.Background(), nil)
	if err := tr.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer tr.Stop()

	addr := tr.listener.Addr().String()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := tr.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	clientConn, err := tr.Dial(ctx, addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	select {
	case serverConn := <-accepted:
		defer serverConn.Close()
		msg := []byte("hello")
		clientConn.Write(msg)
		buf := make([]byte, 16)
		n, err := serverConn.Read(buf)
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
		if string(buf[:n]) != "hello" {
			t.Errorf("expected 'hello', got %q", string(buf[:n]))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for accept")
	}
}
