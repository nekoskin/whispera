package tunnel

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
)

func TestFreezeNeedsDistinctArmsGoingQuiet(t *testing.T) {
	g := newFreezeGate()
	now := time.Now()
	g.now = func() time.Time { return now }
	for i := 0; i < freezeDistinctArms-1; i++ {
		if g.silent("net", i) {
			t.Fatalf("one arm short of the threshold should not look frozen (arm %d)", i)
		}
	}
	if !g.silent("net", freezeDistinctArms-1) {
		t.Fatal("the arm that completes the distinct set should trip the freeze")
	}
}

func TestFreezeIgnoresTheSameArmRepeating(t *testing.T) {
	g := newFreezeGate()
	now := time.Now()
	g.now = func() time.Time { return now }
	for i := 0; i < freezeDistinctArms+2; i++ {
		if g.silent("net", 0) {
			t.Fatal("one arm failing over and over is the arm's fault, not a freeze")
		}
	}
}

func TestFreezeForgetsStaleMarks(t *testing.T) {
	g := newFreezeGate()
	now := time.Now()
	g.now = func() time.Time { return now }
	g.silent("net", 0)
	g.silent("net", 1)
	now = now.Add(freezeWindow + time.Second)
	if g.silent("net", 2) {
		t.Fatal("marks older than the window should not add up to a freeze")
	}
}

func TestFreezeIsPerNetwork(t *testing.T) {
	g := newFreezeGate()
	now := time.Now()
	g.now = func() time.Time { return now }
	for i := 0; i < freezeDistinctArms; i++ {
		g.silent("home", i)
	}
	if g.silent("cafe", 0) {
		t.Fatal("a freeze on one network must not freeze another")
	}
}

func TestDialWaitsOutTheFreeze(t *testing.T) {
	defer withFreezeHold(300 * time.Millisecond)()
	g := newFreezeGate()
	for i := 0; i < freezeDistinctArms; i++ {
		g.silent("net", i)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.waitOutFreeze(ctx, "net") }()
	select {
	case <-done:
		t.Fatal("a dial went ahead while the network was still frozen")
	case <-time.After(freezeHold / 2):
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a dial should go ahead once the freeze lifts: %v", err)
		}
	case <-time.After(2 * freezeHold):
		t.Fatal("a dial still waited after the freeze lifted")
	}
}

func withFreezeHold(d time.Duration) func() {
	prev := freezeHold
	freezeHold = d
	return func() { freezeHold = prev }
}

func TestFreezeSilentOnlyOnTimeouts(t *testing.T) {
	if !freezeSilent(protocol.HandshakeIncomplete) {
		t.Fatal("a timeout is the signature of a freeze")
	}
	for _, r := range []protocol.HandshakeResult{
		protocol.HandshakeOK, protocol.HandshakeResetFast, protocol.HandshakeRejected,
		protocol.HandshakeError, protocol.HandshakeLocal,
	} {
		if freezeSilent(r) {
			t.Fatalf("%v is not the silence of a freeze", r)
		}
	}
}

func TestBurstOfDialsIsNotThrottledOutsideAFreeze(t *testing.T) {
	const burst = 200
	g := newFreezeGate()
	errs := make(chan error, burst)
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- g.waitOutFreeze(context.Background(), "net")
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("%d dials on a healthy network took %s to get through", burst, elapsed)
	}
}
