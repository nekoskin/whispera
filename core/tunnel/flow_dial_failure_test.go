package tunnel

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func closedLocalAddr(t *testing.T) string {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func TestFailedFlowDialKeepsTunnelUp(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableWhispera = true
	cfg.WhisperaSecret = make([]byte, 32)
	cfg.WhisperaAddr = closedLocalAddr(t)
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	m.setState(StateConnected)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := m.openStreamPerFlow(ctx, 0, "example.com", 443); err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
	if !m.IsConnected() {
		t.Fatalf("one failed flow dial took the tunnel down: state %v", m.GetState())
	}
}

var errCensorReset = errors.New("hello reset by the censor")

func TestFlowDialRetriesUntilATacticGetsThrough(t *testing.T) {
	calls := 0
	dial := func(context.Context) (net.Conn, error) {
		calls++
		if calls < flowDialAttempts {
			return nil, errCensorReset
		}
		client, server := net.Pipe()
		server.Close()
		return client, nil
	}
	conn, err := dialWithRetry(context.Background(), dial)
	if err != nil {
		t.Fatalf("flow failed although attempt %d got through: %v", flowDialAttempts, err)
	}
	conn.Close()
	if calls != flowDialAttempts {
		t.Fatalf("dialed %d times, want %d", calls, flowDialAttempts)
	}
}

func TestFlowDialGivesUpAfterItsAttempts(t *testing.T) {
	calls := 0
	dial := func(context.Context) (net.Conn, error) {
		calls++
		return nil, errCensorReset
	}
	if _, err := dialWithRetry(context.Background(), dial); !errors.Is(err, errCensorReset) {
		t.Fatalf("err = %v, want the last dial error", err)
	}
	if calls != flowDialAttempts {
		t.Fatalf("dialed %d times, want %d", calls, flowDialAttempts)
	}
}

func TestFlowDialStopsOnceTheRequestIsGone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	dial := func(context.Context) (net.Conn, error) {
		calls++
		cancel()
		return nil, context.Canceled
	}
	if _, err := dialWithRetry(ctx, dial); err == nil {
		t.Fatal("dial succeeded after the request was canceled")
	}
	if calls != 1 {
		t.Fatalf("dialed %d times after the request was canceled, want 1", calls)
	}
}
