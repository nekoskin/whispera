package tunnel

import (
	"context"
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

func TestAdmitHoldsUntilTheFreezeLifts(t *testing.T) {
	defer withFreezeHold(300 * time.Millisecond)()
	g := newFreezeGate()
	for i := 0; i < freezeDistinctArms; i++ {
		g.silent("net", i)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		release, err := g.admit(ctx, "net")
		if release != nil {
			release()
		}
		done <- err
	}()
	select {
	case <-done:
		t.Fatal("admit returned while the network was still frozen")
	case <-time.After(freezeHold / 2):
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("admit should clear once the freeze lifts: %v", err)
		}
	case <-time.After(2 * freezeHold):
		t.Fatal("admit did not clear after the freeze lifted")
	}
}

func withFreezeHold(d time.Duration) func() {
	prev := freezeHold
	freezeHold = d
	return func() { freezeHold = prev }
}

func TestAdmitCapsConcurrentDials(t *testing.T) {
	g := newFreezeGate()
	releases := make([]func(), 0, maxConcurrentDials)
	for i := 0; i < maxConcurrentDials; i++ {
		release, err := g.admit(context.Background(), "net")
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := g.admit(ctx, "net"); err == nil {
		t.Fatal("a dial past the concurrency cap should wait for a slot")
	}
	releases[0]()
	release, err := g.admit(context.Background(), "net")
	if err != nil {
		t.Fatalf("a freed slot should admit the next dial: %v", err)
	}
	release()
	for _, r := range releases[1:] {
		r()
	}
}

func TestAdmitSpacesDialStarts(t *testing.T) {
	g := newFreezeGate()
	start := time.Now()
	r1, err := g.admit(context.Background(), "net")
	if err != nil {
		t.Fatal(err)
	}
	r1()
	r2, err := g.admit(context.Background(), "net")
	if err != nil {
		t.Fatal(err)
	}
	r2()
	if elapsed := time.Since(start); elapsed < dialGap {
		t.Fatalf("two dials started %s apart, want at least %s", elapsed, dialGap)
	}
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
