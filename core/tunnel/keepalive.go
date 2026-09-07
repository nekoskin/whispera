package tunnel

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nekoskin/whispera/common/buf"
	"github.com/nekoskin/whispera/core/protocol"
)

const (
	drainWait  = 250 * time.Millisecond
	idleMax    = 8
	drainLimit = 64 << 10
)

type idleSet struct {
	mu      sync.Mutex
	conns   []net.Conn
	closed  bool
	filling atomic.Bool
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

func idleAlive(c net.Conn) bool {
	if err := c.SetReadDeadline(time.Now()); err != nil {
		return false
	}
	var probe [1]byte
	_, err := c.Read(probe[:])
	if rerr := c.SetReadDeadline(time.Time{}); rerr != nil {
		return false
	}
	return errors.Is(err, os.ErrDeadlineExceeded)
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

		if idleAlive(c) {
			return c
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
	s.conns = append(s.conns, c)
	var evict []net.Conn
	if over := len(s.conns) - idleMax; over > 0 {
		evict = append(evict, s.conns[:over]...)
		s.conns = s.conns[over:]
	}
	s.mu.Unlock()
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
		err = c.up.EndStream()
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
