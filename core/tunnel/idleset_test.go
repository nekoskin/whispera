package tunnel

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func newFakeConn() *fakeConn { return &fakeConn{closed: make(chan struct{})} }

func (c *fakeConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *fakeConn) SetReadDeadline(time.Time) error { return nil }

func TestIdleSetCapsPool(t *testing.T) {
	var s idleSet
	conns := make([]*fakeConn, 40)
	for i := range conns {
		conns[i] = newFakeConn()
		s.put(conns[i])
	}

	s.mu.Lock()
	held := len(s.conns)
	s.mu.Unlock()

	if held > idleMax {
		t.Fatalf("pool holds %d connections, cap is %d", held, idleMax)
	}

	closed := 0
	for _, c := range conns {
		if c.isClosed() {
			closed++
		}
	}
	if closed != len(conns)-held {
		t.Fatalf("evicted %d but closed %d", len(conns)-held, closed)
	}
}

func TestIdleSetPutClosesWhenShut(t *testing.T) {
	var s idleSet
	s.closeAll()

	c := newFakeConn()
	s.put(c)
	if !c.isClosed() {
		t.Fatal("connection was not closed on a shut pool")
	}
}

func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
		}
		accepted <- c
	}()
	client, err = (&net.Dialer{}).DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server = <-accepted
	if server == nil {
		t.FailNow()
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

func pooled(s *idleSet) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

func TestIdleSetDropsConnectionClosedByServer(t *testing.T) {
	client, server := tcpPair(t)
	var s idleSet
	defer s.closeAll()

	s.put(client)
	_ = server.Close()

	deadline := time.Now().Add(2 * time.Second)
	for pooled(&s) > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if c := s.take(); c != nil {
		t.Fatal("took a connection the server had already closed: the next stream on it ends in a reset")
	}
}

func TestIdleSetHandsBackLiveConnectionIntact(t *testing.T) {
	client, server := tcpPair(t)
	var s idleSet
	defer s.closeAll()

	s.put(client)
	time.Sleep(20 * time.Millisecond)
	c := s.take()
	if c == nil {
		t.Fatal("live parked connection was dropped")
	}

	if _, err := server.Write([]byte("next")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read after take: %v", err)
	}
	if string(got) != "next" {
		t.Fatalf("read %q, want %q: the liveness check ate the stream's bytes", got, "next")
	}
}

func TestIdleSetTakeDoesNotHangWithoutDeadlines(t *testing.T) {
	var s idleSet
	defer s.closeAll()

	s.put(newFakeConn())
	took := make(chan net.Conn, 1)
	go func() { took <- s.take() }()

	select {
	case c := <-took:
		if c != nil {
			t.Fatal("handed out a connection whose liveness could not be checked")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("take() hung on a transport that ignores read deadlines")
	}
}
