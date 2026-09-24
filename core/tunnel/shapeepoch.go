package tunnel

import (
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
)

// Shape is process-wide and read at the point of use, so a padding arm cannot be
// chosen per dial like a hello budget: it is held for an epoch across every flow
// and judged by the connections that ended while it was in force. Off unless
// WHISPERA_SHAPE_CONTROL=1.
const (
	shapeEpoch = 45 * time.Second

	// A connection that ended by itself under this carried nothing to judge.
	// A reset ignores the floor, see note.
	shapeMinBytes = 64 << 10

	// Below this a connection that carried traffic was being throttled.
	shapeThroughputFloor = 128 << 10 // bytes per second
	shapeMinDuration     = 100 * time.Millisecond
)

func shapeControlEnabled() bool { return os.Getenv("WHISPERA_SHAPE_CONTROL") == "1" }

func shapeEpochLen() time.Duration {
	if v := os.Getenv("WHISPERA_SHAPE_EPOCH_S"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
		log.Warn("shape: %q is not a length in seconds, keeping %s", v, shapeEpoch)
	}
	return shapeEpoch
}

type shapeController struct {
	strategy *protocol.HandshakeStrategy
	ctx      string

	mu      sync.Mutex
	arm     int
	started time.Time
	good    int
	bad     int
}

func newShapeController(strategy *protocol.HandshakeStrategy, sni string) *shapeController {
	if !shapeControlEnabled() || strategy == nil {
		return nil
	}
	c := &shapeController{strategy: strategy, ctx: sni + "|shape"}
	c.take()
	return c
}

func (c *shapeController) take() {
	arm := c.strategy.Select(c.ctx, protocol.ShapeArmCount())
	if err := protocol.ApplyShapeArm(arm); err != nil {
		log.Warn("shape arm %d rejected, keeping the previous one: %v", arm, err)
		return
	}
	c.arm = arm
	c.started = time.Now()
	c.good, c.bad = 0, 0
	log.Debug("shape: holding %q for %s", protocol.ShapeArmName(arm), shapeEpochLen())
}

func (c *shapeController) throttled(dur time.Duration, bytes int64) bool {
	if dur < shapeMinDuration {
		return false
	}
	return float64(bytes)/dur.Seconds() < float64(shapeThroughputFloor)
}

func (c *shapeController) note(dur time.Duration, bytes int64, reset bool) {
	if c == nil {
		return
	}
	if !reset && bytes < shapeMinBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case reset:
		c.bad++
	case c.throttled(dur, bytes):
		c.bad++
	default:
		c.good++
	}
	if time.Since(c.started) < shapeEpochLen() {
		return
	}
	result := protocol.HandshakeResetFast
	if c.good > c.bad {
		result = protocol.HandshakeOK
	}
	log.Debug("shape: %q ends with %d good, %d bad", protocol.ShapeArmName(c.arm), c.good, c.bad)
	c.strategy.Observe(c.ctx, c.arm, result)
	c.take()
}
