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

func withFlowDialBackoff(d time.Duration) func() {
	prev := flowDialBackoff
	flowDialBackoff = d
	return func() { flowDialBackoff = prev }
}

func TestFlowDialRetriesUntilATacticGetsThrough(t *testing.T) {
	defer withFlowDialBackoff(time.Millisecond)()
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
	defer withFlowDialBackoff(time.Millisecond)()
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

func TestFlowDialPausesLongerAfterEachFailure(t *testing.T) {
	const step = 20 * time.Millisecond
	defer withFlowDialBackoff(step)()
	var at []time.Time
	dial := func(context.Context) (net.Conn, error) {
		at = append(at, time.Now())
		return nil, errCensorReset
	}
	if _, err := dialWithRetry(context.Background(), dial); err == nil {
		t.Fatal("dial succeeded although every attempt failed")
	}
	for i := 1; i < len(at); i++ {
		if gap, want := at[i].Sub(at[i-1]), time.Duration(i-1)*step; gap < want {
			t.Fatalf("pause before attempt %d = %v, want at least %v", i+1, gap, want)
		}
	}
}

func TestFlowDialDoesNotPauseAfterASlowFailure(t *testing.T) {
	const step = 50 * time.Millisecond
	const dialTime = (flowDialAttempts - 1) * step
	defer withFlowDialBackoff(step)()
	dial := func(context.Context) (net.Conn, error) {
		time.Sleep(dialTime)
		return nil, errCensorReset
	}
	start := time.Now()
	if _, err := dialWithRetry(context.Background(), dial); err == nil {
		t.Fatal("dial succeeded although every attempt failed")
	}
	if took, limit := time.Since(start), flowDialAttempts*dialTime+3*step; took > limit {
		t.Fatalf("took %v, want under %v: paused after attempts that already ran longer than the pause", took, limit)
	}
}

func TestReconnectWaitsTheConfiguredIntervalFirst(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ReconnectInterval = 2 * time.Second
	cfg.ReconnectMaxDelay = 10 * time.Second
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	st := &reconnectState{delay: cfg.ReconnectInterval}
	for i, want := range []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second} {
		if got := m.nextBackoff(st); got != want {
			t.Fatalf("wait %d = %v, want %v", i+1, got, want)
		}
	}
}

func TestFlowDialStopsPausingOnceTheRequestIsGone(t *testing.T) {
	defer withFlowDialBackoff(time.Hour)()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	calls := 0
	dial := func(context.Context) (net.Conn, error) {
		calls++
		return nil, errCensorReset
	}
	start := time.Now()
	if _, err := dialWithRetry(ctx, dial); !errors.Is(err, errCensorReset) {
		t.Fatalf("err = %v, want the last dial error", err)
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Fatalf("kept pausing for %v after the request was gone", waited)
	}
	if calls != 2 {
		t.Fatalf("dialed %d times, want 2 before the long pause", calls)
	}
}
