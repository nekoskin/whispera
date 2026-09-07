package tunnel

import (
	"net"
	"sync"
	"testing"
	"time"
)

type fakeConn struct {
	net.Conn
	mu     sync.Mutex
	closed bool
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *fakeConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *fakeConn) SetReadDeadline(time.Time) error { return nil }

func TestIdleSetCapsPool(t *testing.T) {
	var s idleSet
	conns := make([]*fakeConn, 40)
	for i := range conns {
		conns[i] = &fakeConn{}
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

	c := &fakeConn{}
	s.put(c)
	if !c.isClosed() {
		t.Fatal("connection was not closed on a shut pool")
	}
}
