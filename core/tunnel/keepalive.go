package tunnel

import (
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nekoskin/whispera/common/buf"
	"github.com/nekoskin/whispera/core/protocol"
)

const (
	drainWait   = 250 * time.Millisecond
	reclaimWait = 100 * time.Millisecond
	idleMax     = 8
	drainLimit  = 64 << 10
)

type idleSet struct {
	mu      sync.Mutex
	conns   []*parkedConn
	closed  bool
	filling atomic.Bool
}

type parkedConn struct {
	net.Conn
	alive chan bool
}

func (s *idleSet) fillLoop() {
	defer s.filling.Store(false)
	for {
		_, intervalMs, _, _ := protocol.Shape.Filler()
		wait := time.Second
		if intervalMs > 0 {
			wait = time.Duration(intervalMs) * time.Millisecond
		}
		time.Sleep(wait)

		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		for _, c := range s.conns {
			pad, ok := protocol.FillerPad()
			if !ok {
				break
			}
			if err := protocol.WriteFillerRecord(c, pad); err != nil {
				continue
			}
		}
		s.mu.Unlock()
	}
}

func (s *idleSet) watch(c *parkedConn) {
	var probe [1]byte
	_, err := c.Read(probe[:])
	alive := errors.Is(err, os.ErrDeadlineExceeded)
	c.alive <- alive
	if !alive && s.remove(c) {
		c.Close()
	}
}

func (s *idleSet) remove(c *parkedConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.Index(s.conns, c)
	if i < 0 {
		return false
	}
	s.conns = slices.Delete(s.conns, i, i+1)
	return true
}

func (c *parkedConn) reclaim() bool {
	if err := c.SetReadDeadline(time.Now()); err != nil {
		return false
	}
	select {
	case alive := <-c.alive:
		return alive && c.SetReadDeadline(time.Time{}) == nil
	case <-time.After(reclaimWait):
		return false
	}
}

func (s *idleSet) take() net.Conn {
	for {
		s.mu.Lock()
		if len(s.conns) == 0 {
			s.mu.Unlock()
			return nil
		}
		last := len(s.conns) - 1
		c := s.conns[last]
		s.conns = s.conns[:last]
		s.mu.Unlock()

		if c.reclaim() {
			return c.Conn
		}
		c.Close()
	}
}

func (s *idleSet) put(c net.Conn) {
	if s.filling.CompareAndSwap(false, true) {
		go s.fillLoop()
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		c.Close()
		return
	}
	p := &parkedConn{Conn: c, alive: make(chan bool, 1)}
	s.conns = append(s.conns, p)
	var evict []*parkedConn
	if over := len(s.conns) - idleMax; over > 0 {
		evict = append(evict, s.conns[:over]...)
		s.conns = s.conns[over:]
	}
	s.mu.Unlock()
	go s.watch(p)
	for _, e := range evict {
		e.Close()
	}
}

func (s *idleSet) reopen() {
	s.mu.Lock()
	s.closed = false
	s.mu.Unlock()
}

func (s *idleSet) closeAll() {
	s.mu.Lock()
	conns := s.conns
	s.conns = nil
	s.closed = true
	s.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

type keepAliveStream struct {
	net.Conn
	up   *protocol.FramedConn
	down *protocol.FramedConn
	m    *Manager
	base net.Conn
	raw  net.Conn
	once sync.Once
}

func (c *keepAliveStream) Write(b []byte) (int, error) { return c.up.Write(b) }

func (c *keepAliveStream) Read(b []byte) (int, error) { return c.down.Read(b) }

func (c *keepAliveStream) SpliceTo(dst net.Conn) (int64, error) {
	n, err := buf.Copy(buf.NewReader(c.down), buf.NewWriter(dst))
	if !errors.Is(err, protocol.ErrSwitchRaw) {
		return n, err
	}
	src := c.raw
	if src == nil {
		src = c.base
	}
	if d, s := buf.RawTCP(dst), buf.RawTCP(src); d != nil && s != nil {
		m, rerr := d.ReadFrom(s)
		return n + m, rerr
	}
	m, rerr := io.Copy(dst, src)
	return n + m, rerr
}

func drainToEnd(base net.Conn, down *protocol.FramedConn) bool {
	if down.StreamDone() {
		return true
	}
	if err := base.SetReadDeadline(time.Now().Add(drainWait)); err != nil {
		return false
	}
	defer base.SetReadDeadline(time.Time{})

	discard := make([]byte, 16<<10)
	for left := drainLimit; left > 0; {
		n, err := down.Read(discard)
		if err != nil {
			return errors.Is(err, io.EOF) && down.StreamDone()
		}
		left -= n
	}
	return false
}

func (c *keepAliveStream) Close() error {
	var err error
	c.once.Do(func() {
		if err = c.base.SetDeadline(time.Time{}); err == nil {
			err = c.up.EndStream()
		}
		if err != nil || c.down.SwitchedRaw() {
			c.base.Close()
			return
		}
		base, down := c.base, c.down
		go func() {
			if drainToEnd(base, down) {
				c.m.idle.put(base)
				return
			}
			base.Close()
		}()
	})
	return err
}
