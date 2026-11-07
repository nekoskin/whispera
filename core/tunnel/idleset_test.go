package tunnel

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
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

func (c *fakeConn) SetReadDeadline(time.Time) error { return nil }

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

var takeAny = func(net.Conn) bool { return true }

type leveredConn struct {
	net.Conn
	levers protocol.ConnLevers
}

func (c leveredConn) Levers() (protocol.ConnLevers, bool) { return c.levers, true }

func TestIdleSetSkipsAConnectionDialedUnderLeversTheNetLeft(t *testing.T) {
	plain, _ := tcpPair(t)
	migrating, _ := tcpPair(t)
	var s idleSet
	defer s.closeAll()
	var sel selector
	sel.wanted.Store(&protocol.ConnLevers{Migrate: true})

	s.put(leveredConn{Conn: migrating, levers: protocol.ConnLevers{Migrate: true}})
	s.put(leveredConn{Conn: plain})
	time.Sleep(20 * time.Millisecond)

	c := s.take(sel.leversFit)
	if c == nil {
		t.Fatal("no connection handed out although one matches the net's levers")
	}
	if got, _ := protocol.LeversOf(c); !got.Migrate {
		t.Fatal("handed out a connection without migration after the net switched to it: the next big download freezes again")
	}
	if pooled(&s) != 0 {
		t.Fatal("the stale connection is still parked")
	}
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
	if c := s.take(takeAny); c != nil {
		t.Fatal("took a connection the server had already closed: the next stream on it ends in a reset")
	}
}

func TestIdleSetHandsBackLiveConnectionIntact(t *testing.T) {
	client, server := tcpPair(t)
	var s idleSet
	defer s.closeAll()

	s.put(client)
	time.Sleep(20 * time.Millisecond)
	c := s.take(takeAny)
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
	go func() { took <- s.take(takeAny) }()

	select {
	case c := <-took:
		if c != nil {
			t.Fatal("handed out a connection whose liveness could not be checked")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("take() hung on a transport that ignores read deadlines")
	}
}
