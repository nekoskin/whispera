package protocol

import (
	"errors"
	"net"
	"testing"
	"time"
)

// stubConn is a connection that neither blocks nor talks to anything: the
// verdict under test depends on what crossed the wrapper, not on a peer.
type stubConn struct {
	readErr error
}

func (s *stubConn) Read(b []byte) (int, error) {
	if s.readErr != nil {
		return 0, s.readErr
	}
	return len(b), nil
}
func (s *stubConn) Write(b []byte) (int, error) { return len(b), nil }
func (s *stubConn) Close() error                { return nil }
func (s *stubConn) LocalAddr() net.Addr         { return nil }
func (s *stubConn) RemoteAddr() net.Addr        { return nil }
func (s *stubConn) SetDeadline(time.Time) error { return nil }
func (s *stubConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (s *stubConn) SetWriteDeadline(t time.Time) error { return nil }

type verdict struct {
	calls int
	dur   time.Duration
	bytes int64
	reset bool
}

func newLive(t *testing.T, v *verdict, readErr error) *livenessConn {
	t.Helper()
	c := &livenessConn{
		Conn:    &stubConn{readErr: readErr},
		onReset: func() {},
		onEnd: func(e LiveEnd) {
			v.calls++
			v.dur, v.bytes, v.reset = e.Dur, e.Moved, e.Reset
		},
	}
	c.markEstablished()
	return c
}

func TestLiveEndReportsAResetOnce(t *testing.T) {
	var v verdict
	c := newLive(t, &v, errors.New("read: connection reset by peer"))
	if _, err := c.Read(make([]byte, 10)); err == nil {
		t.Fatal("expected the read to fail")
	}
	c.Close()

	if v.calls != 1 {
		t.Fatalf("got %d verdicts, want exactly one", v.calls)
	}
	if !v.reset {
		t.Error("a censor-looking reset was not reported as one")
	}
}
