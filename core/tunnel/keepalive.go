package tunnel

import (
	"context"
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
	drainWait       = 250 * time.Millisecond
	reclaimWait     = 100 * time.Millisecond
	fillerWriteWait = 500 * time.Millisecond
	idleMax         = 8
	drainLimit      = 64 << 10
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
			_ = c.SetWriteDeadline(time.Now().Add(fillerWriteWait))
			_ = protocol.WriteFillerRecord(c, pad)
			_ = c.SetWriteDeadline(time.Time{})
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
	t := time.NewTimer(reclaimWait)
	defer t.Stop()
	select {
	case alive := <-c.alive:
		return alive && c.SetReadDeadline(time.Time{}) == nil
	case <-t.C:
		return false
	}
}

func (s *idleSet) take(fits func(net.Conn) bool) net.Conn {
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

		if c.reclaim() && fits(c.Conn) {
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

	lastRead atomic.Int64
	sawEnd   atomic.Bool

	swapMu     sync.Mutex
	pad        *protocol.ShapeBudget
	token      []byte
	ctx        context.Context
	resumeDial func(context.Context) (net.Conn, error)
}

func (c *keepAliveStream) Write(b []byte) (int, error) {
	c.swapMu.Lock()
	up := c.up
	c.swapMu.Unlock()
	return up.Write(b)
}

func (c *keepAliveStream) Read(b []byte) (int, error) {
	for {
		c.swapMu.Lock()
		down := c.down
		c.swapMu.Unlock()
		n, err := down.Read(b)
		if n > 0 {
			c.lastRead.Store(time.Now().UnixNano())
		}
		if errors.Is(err, io.EOF) {
			c.sawEnd.Store(true)
		}
		if errors.Is(err, protocol.ErrMigrate) {
			if merr := c.migrate(); merr != nil {
				return 0, merr
			}
			continue
		}
		return n, err
	}
}

func (c *keepAliveStream) silentFor(d time.Duration) bool {
	return !c.sawEnd.Load() && time.Since(time.Unix(0, c.lastRead.Load())) >= d
}

func (c *keepAliveStream) migrate() error {
	if c.resumeDial == nil || len(c.token) == 0 {
		return errors.New("whispera: migrate without a resume dialer")
	}
	conn, err := c.resumeDial(c.ctx)
	if err != nil {
		return err
	}
	hdr := make([]byte, 0, 3+len(c.token))
	hdr = append(hdr, protocol.KeepAliveProtoBit|protocol.MigrateProtoBit, 0x00, 0x00)
	hdr = append(hdr, c.token...)
	if _, err := conn.Write(hdr); err != nil {
		conn.Close()
		return err
	}
	base := newDecoyLeaveConn(conn)
	up := protocol.NewFramedConnFilling(base, c.pad)
	if levers, ok := protocol.LeversOf(conn); ok {
		up.ShapeRecords(levers.Shaped)
	}

	c.swapMu.Lock()
	old := c.base
	c.base, c.up, c.down = base, up, up
	c.swapMu.Unlock()
	old.Close()
	return nil
}

func (c *keepAliveStream) SpliceTo(dst net.Conn) (int64, error) {
	var total int64
	for {
		c.swapMu.Lock()
		down := c.down
		c.swapMu.Unlock()
		n, err := buf.Copy(buf.NewReader(down), buf.NewWriter(dst))
		total += n
		if errors.Is(err, protocol.ErrMigrate) {
			if merr := c.migrate(); merr != nil {
				return total, merr
			}
			continue
		}
		if !errors.Is(err, protocol.ErrSwitchRaw) {
			return total, err
		}
		src := c.raw
		if src == nil {
			src = c.base
		}
		if d, s := buf.RawTCP(dst), buf.RawTCP(src); d != nil && s != nil {
			m, rerr := d.ReadFrom(s)
			return total + m, rerr
		}
		m, rerr := io.Copy(dst, src)
		return total + m, rerr
	}
}

func drainToEnd(base net.Conn, down *protocol.FramedConn) (done, silent bool) {
	if down.StreamDone() {
		return true, false
	}
	if err := base.SetReadDeadline(time.Now().Add(drainWait)); err != nil {
		return false, false
	}
	defer base.SetReadDeadline(time.Time{})

	discard := make([]byte, 16<<10)
	read := 0
	for left := drainLimit; left > 0; {
		n, err := down.Read(discard)
		read += n
		if err != nil {
			done = errors.Is(err, io.EOF) && down.StreamDone()
			return done, !done && read == 0
		}
		left -= n
	}
	return false, false
}

func (c *keepAliveStream) Close() error {
	var err error
	c.once.Do(func() {
		quiet := c.silentFor(protocol.StreamStallSilence)
		if err = c.base.SetDeadline(time.Time{}); err == nil {
			err = c.up.EndStream()
		}
		if err != nil || c.down.SwitchedRaw() {
			c.base.Close()
			return
		}
		base, down := c.base, c.down
		hot := false
		if d, ok := base.(*decoyLeaveConn); ok && d.acct != nil {
			hot = d.acct.down.Add(down.RxWire()) >= downstreamCapBytes
		}
		if quiet {
			base.SetReadDeadline(time.Now().Add(drainWait))
		}
		go func() {
			if !hot || quiet {
				done, silent := drainToEnd(base, down)
				if done && !hot {
					c.m.idle.put(base)
					return
				}
				if quiet && silent {
					protocol.NoteStall(base)
				}
			}
			base.Close()
		}()
	})
	return err
}
