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
		onEnd: func(dur time.Duration, bytes int64, reset bool) {
			v.calls++
			v.dur, v.bytes, v.reset = dur, bytes, reset
		},
	}
	c.markEstablished()
	return c
}

func TestLiveEndReportsBytesOnClose(t *testing.T) {
	var v verdict
	c := newLive(t, &v, nil)
	if _, err := c.Write(make([]byte, 1500)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 500)); err != nil {
		t.Fatal(err)
	}
	c.Close()

	if v.calls != 1 {
		t.Fatalf("got %d verdicts, want exactly one", v.calls)
	}
	if v.bytes != 2000 {
		t.Errorf("verdict counted %d bytes, want 2000", v.bytes)
	}
	if v.reset {
		t.Error("a connection we closed ourselves was reported as reset")
	}
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

func TestLiveEndStaysQuietBeforeEstablished(t *testing.T) {
	var v verdict
	c := &livenessConn{
		Conn: &stubConn{},
		onEnd: func(time.Duration, int64, bool) {
			v.calls++
		},
	}
	c.Close()
	if v.calls != 0 {
		t.Errorf("a connection that never came up reported %d verdicts", v.calls)
	}
}
