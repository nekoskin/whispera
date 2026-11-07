package protocol

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestHelloRetryWorthwhile(t *testing.T) {
	if helloRetryWorthwhile(context.Background(), &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}) {
		t.Fatal("timed-out handshake must not be redialed (bursts feed DPI rate-throttle)")
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if helloRetryWorthwhile(canceled, errors.New("read: software caused connection abort")) {
		t.Fatal("canceled attempt must not be redialed")
	}

	if !helloRetryWorthwhile(context.Background(), errors.New("tls: handshake failure")) {
		t.Fatal("plain handshake rejection must still fall back to the built-in fingerprint")
	}
}

func TestClassifyHandshake(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		latency time.Duration
		want    HandshakeResult
	}{
		{"success", nil, 50 * time.Millisecond, HandshakeOK},
		{"reset_fast", errors.New("read tcp 1.2.3.4:443: connection reset by peer"), 5 * time.Millisecond, HandshakeResetFast},
		{"reset_slow", errors.New("connection reset by peer"), 200 * time.Millisecond, HandshakeError},
		{"decode", errors.New("remote error: tls: error decoding message"), 40 * time.Millisecond, HandshakeRejected},
		{"bad_cert", errors.New("tls: bad certificate"), 60 * time.Millisecond, HandshakeRejected},
		{"deadline", errors.New("context deadline exceeded"), 4 * time.Second, HandshakeIncomplete},
		{"io_timeout", errors.New("read tcp: i/o timeout"), 4 * time.Second, HandshakeIncomplete},
		{"other", errors.New("some unknown failure"), 100 * time.Millisecond, HandshakeError},
		{"aborted_windows", errors.New("read tcp4 10.0.0.2:5000->1.2.3.4:443: wsarecv: An established connection was aborted by the software in your host machine."), 900 * time.Millisecond, HandshakeLocal},
		{"aborted_linux", errors.New("read tcp 10.0.0.2:5000->1.2.3.4:443: read: software caused connection abort"), 900 * time.Millisecond, HandshakeLocal},
		{"unreachable", errors.New("write tcp 10.0.0.2:5000->1.2.3.4:443: write: network is unreachable"), 10 * time.Millisecond, HandshakeLocal},
		{"canceled", errors.New("context canceled"), 300 * time.Millisecond, HandshakeLocal},
	}
	for _, c := range cases {
		if got := classifyHandshake(c.err, c.latency); got != c.want {
			t.Errorf("%s: classifyHandshake = %v, want %v", c.name, got, c.want)
		}
	}
}

type errConn struct {
	net.Conn
	err error
}

func (c errConn) Read([]byte) (int, error)  { return 0, c.err }
func (c errConn) Write([]byte) (int, error) { return 0, c.err }
func (c errConn) Close() error              { return nil }

func newLiveConn(errText string, fired *int) *livenessConn {
	return &livenessConn{Conn: errConn{err: errors.New(errText)}, onReset: func() { *fired++ }}
}

func TestLivenessConnFiresOnceOnEarlyReset(t *testing.T) {
	fired := 0
	lc := newLiveConn("read tcp: connection reset by peer", &fired)
	lc.markEstablished()
	_, _ = lc.Read(make([]byte, 1))
	_, _ = lc.Read(make([]byte, 1))
	if fired != 1 {
		t.Fatalf("early reset on a live tunnel must fire exactly once, got %d", fired)
	}
}

func TestLivenessConnIgnoresLateReset(t *testing.T) {
	fired := 0
	lc := newLiveConn("connection reset by peer", &fired)
	lc.markEstablished()
	lc.mu.Lock()
	lc.establishedAt = time.Now().Add(-liveResetWindow - time.Second)
	lc.mu.Unlock()
	_, _ = lc.Read(make([]byte, 1))
	if fired != 0 {
		t.Fatalf("a reset after a long healthy life is normal churn, got %d", fired)
	}
}

func TestClassifyDecoyIsNotArmFault(t *testing.T) {
	err := errors.New("whispera: utls handshake: whispera: the server served the decoy site instead of the tunnel — it did not recognize this key")
	if got := classifyHandshake(err, 90*time.Millisecond); got != HandshakeLocal {
		t.Fatalf("decoy classified as %v, want HandshakeLocal (not the arm's fault)", got)
	}
	if HandshakeBlocked(HandshakeLocal) {
		t.Fatal("HandshakeLocal must not count as the censor blocking the arm")
	}
}
