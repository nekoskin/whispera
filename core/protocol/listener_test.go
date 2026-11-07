package protocol

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func perflowPreamble(secret, sessionID []byte) []byte {
	keys := DeriveKeys(secret)
	token := AuthToken(keys.Auth, time.Now().Unix()/authWindowSeconds, sessionID)
	b := []byte{perflowMagic}
	b = append(b, sessionID...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(token)))
	b = append(b, token...)
	return b
}

func TestPerflowMuxAuthenticatesAndPositionsStream(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	crand.Read(secret)

	type call struct {
		userID string
		tail   []byte
	}
	got := make(chan call, 1)
	cfg := &ServerConfig{
		SharedSecret: secret,
		OnConn: func(ac AcceptedConn) {
			tail := make([]byte, 4)
			_, _ = io.ReadFull(ac.Conn, tail)
			got <- call{ac.UserID, tail}
			ac.Conn.Close()
		},
	}
	mux := newPerflowMux(ln, cfg)
	defer mux.Close()

	sessionID := make([]byte, 16)
	crand.Read(sessionID)
	c, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(perflowPreamble(secret, sessionID))
	c.Write([]byte("PING"))

	select {
	case r := <-got:
		if r.userID != "default" {
			t.Errorf("userID = %q, want default", r.userID)
		}
		if !bytes.Equal(r.tail, []byte("PING")) {
			t.Errorf("stream tail = %q, want PING — preamble not consumed exactly", r.tail)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OnConn not called for valid preamble")
	}
}

func TestPerflowMuxBadTokenGoesToDecoy(t *testing.T) {
	ln, _ := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	secret := make([]byte, 32)
	crand.Read(secret)
	called := make(chan struct{}, 1)
	cfg := &ServerConfig{SharedSecret: secret, OnConn: func(AcceptedConn) { called <- struct{}{} }}
	mux := newPerflowMux(ln, cfg)
	defer mux.Close()

	sessionID := make([]byte, 16)
	crand.Read(sessionID)
	tok := "not-a-valid-token"
	bad := []byte{perflowMagic}
	bad = append(bad, sessionID...)
	bad = binary.BigEndian.AppendUint16(bad, uint16(len(tok)))
	bad = append(bad, tok...)
	c, _ := (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	defer c.Close()
	c.Write(bad)

	res := make(chan net.Conn, 1)
	go func() { conn, _ := mux.Accept(); res <- conn }()

	select {
	case conn := <-res:
		if conn == nil {
			t.Fatal("bad token not forwarded to the decoy")
		}
		defer conn.Close()
		got := make([]byte, len(bad))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("reading the decoy side: %v", err)
		}
		if !bytes.Equal(got, bad) {
			t.Error("decoy did not see the original preamble bytes")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bad token neither reset nor sent to the decoy")
	}
	select {
	case <-called:
		t.Fatal("OnConn called for an invalid token")
	default:
	}
}

func TestPerflowMuxForwardsNonMagicToAccept(t *testing.T) {
	ln, _ := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	mux := newPerflowMux(ln, &ServerConfig{})
	defer mux.Close()

	c, _ := (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	defer c.Close()
	c.Write([]byte("GET / HTTP/1.1\r\n"))

	type acc struct {
		conn net.Conn
		err  error
	}
	res := make(chan acc, 1)
	go func() {
		conn, err := mux.Accept()
		res <- acc{conn, err}
	}()

	select {
	case a := <-res:
		if a.err != nil {
			t.Fatal(a.err)
		}
		defer a.conn.Close()
		head := make([]byte, 3)
		_, _ = io.ReadFull(a.conn, head)
		if string(head) != "GET" {
			t.Errorf("first bytes = %q, want GET — prefix byte lost", head)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("non-magic conn not forwarded to Accept")
	}
}
