package tunnel

import (
	"testing"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
)

// restoreShape puts the global padding back, since an arm is process-wide and a
// test that leaves one in force would be changing the next test's datapath.
func restoreShape(t *testing.T) {
	t.Helper()
	records, min, max := protocol.Shape.Get()
	t.Cleanup(func() {
		if err := protocol.Shape.Set(records, min, max); err != nil {
			t.Errorf("restoring the shape: %v", err)
		}
	})
}

func newTestShape(t *testing.T) *shapeController {
	t.Helper()
	restoreShape(t)
	return &shapeController{
		strategy: protocol.NewHandshakeStrategy(),
		ctx:      "origin|shape",
		started:  time.Now(),
	}
}

func TestShapeIgnoresAnIdleConnectionThatEndedByItself(t *testing.T) {
	c := newTestShape(t)
	c.note(time.Minute, shapeMinBytes-1, false)
	if c.good != 0 || c.bad != 0 {
		t.Fatalf("an idle connection was counted as evidence: good %d, bad %d", c.good, c.bad)
	}
}

func TestShapeCountsAnIdleConnectionThatWasKilled(t *testing.T) {
	// A reset counts even below the traffic floor: it is the only evidence.
	c := newTestShape(t)
	c.note(time.Second, 1, true)
	if c.bad != 1 {
		t.Fatalf("a reset was discarded for carrying too little: good %d, bad %d", c.good, c.bad)
	}
}

func TestShapeCountsLifeAndDeath(t *testing.T) {
	c := newTestShape(t)
	// 8 MB in a second is a working tunnel.
	c.note(time.Second, 8<<20, false)
	if c.good != 1 || c.bad != 0 {
		t.Errorf("a fast connection: good %d, bad %d", c.good, c.bad)
	}
	c.note(time.Second, 8<<20, true)
	if c.bad != 1 {
		t.Errorf("a reset was not counted against the arm: bad %d", c.bad)
	}
}

func TestShapeCountsAFastShortTransferAsGood(t *testing.T) {
	// The duration proxy marked this a failure; rate clears it.
	c := newTestShape(t)
	c.note(200*time.Millisecond, 2<<20, false)
	if c.good != 1 || c.bad != 0 {
		t.Errorf("a fast short transfer must count as good: good %d, bad %d", c.good, c.bad)
	}
}

func TestShapeCatchesThrottling(t *testing.T) {
	// Up and carrying traffic, but at a crawl: 64 KB over ten seconds.
	c := newTestShape(t)
	c.note(10*time.Second, shapeMinBytes, false)
	if c.bad != 1 || c.good != 0 {
		t.Errorf("a throttled connection was not caught: good %d, bad %d", c.good, c.bad)
	}
}

func TestShapeRollsOverAtTheEndOfAnEpoch(t *testing.T) {
	c := newTestShape(t)
	c.good, c.bad = 3, 1
	c.started = time.Now().Add(-shapeEpoch - time.Second)

	c.note(time.Second, 8<<20, false)

	if c.good != 0 || c.bad != 0 {
		t.Errorf("the tally survived the roll-over: good %d, bad %d", c.good, c.bad)
	}
	if time.Since(c.started) > time.Second {
		t.Error("the epoch clock was not restarted")
	}
	if c.arm < 0 || c.arm >= protocol.ShapeArmCount() {
		t.Errorf("arm %d is outside the repertoire", c.arm)
	}
}

func TestShapeControllerIsOffUnlessAsked(t *testing.T) {
	t.Setenv("WHISPERA_SHAPE_CONTROL", "")
	if newShapeController(protocol.NewHandshakeStrategy(), "origin") != nil {
		t.Error("the datapath controller must stay off by default")
	}
	t.Setenv("WHISPERA_SHAPE_CONTROL", "1")
	restoreShape(t)
	if newShapeController(protocol.NewHandshakeStrategy(), "origin") == nil {
		t.Error("asked for, it should start")
	}
}

func TestShapeNoteOnNilIsHarmless(t *testing.T) {
	var c *shapeController
	c.note(time.Minute, 1<<20, false)
}
