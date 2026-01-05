// Package metrics provides Prometheus-style metrics for Whispera
package metrics

import "sync/atomic"

// Counter is a simple atomic counter
type Counter struct {
	value int64
}

// Inc increments the counter by 1
func (c *Counter) Inc() {
	atomic.AddInt64(&c.value, 1)
}

// Add adds the given value to the counter
func (c *Counter) Add(v float64) {
	atomic.AddInt64(&c.value, int64(v))
}

// Value returns the current counter value
func (c *Counter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}

// CounterVec is a counter vector with labels
type CounterVec struct {
	counters map[string]*Counter
}

// NewCounterVec creates a new counter vector
func NewCounterVec() *CounterVec {
	return &CounterVec{
		counters: make(map[string]*Counter),
	}
}

// WithLabelValues returns a counter for the given label values
func (cv *CounterVec) WithLabelValues(labels ...string) *Counter {
	key := ""
	for _, l := range labels {
		key += l + ":"
	}
	if c, ok := cv.counters[key]; ok {
		return c
	}
	c := &Counter{}
	cv.counters[key] = c
	return c
}

// Global metrics
var (
	PacketsRx            = &Counter{}
	PacketsTx            = &Counter{}
	BytesRx              = &Counter{}
	BytesTx              = &Counter{}
	PacketsRxByTransport = NewCounterVec()
	PacketsTxByTransport = NewCounterVec()
	BytesRxByTransport   = NewCounterVec()
	BytesTxByTransport   = NewCounterVec()

	// XHTTP metrics
	XHTTPStreamsCreated   = &Counter{}
	XHTTPSessionsCreated  = &Counter{}
	XHTTPSessionsActive   = &Gauge{}
	XHTTPSessionDuration  = &Histogram{}
	XHTTPSessionsTimeout  = &Counter{}
	XHTTPBufferPoolHits   = &Counter{}
	XHTTPBufferPoolMisses = &Counter{}
)

// Gauge is a simple gauge that can go up and down
type Gauge struct {
	value int64
}

// Inc increments the gauge by 1
func (g *Gauge) Inc() {
	atomic.AddInt64(&g.value, 1)
}

// Dec decrements the gauge by 1
func (g *Gauge) Dec() {
	atomic.AddInt64(&g.value, -1)
}

// Set sets the gauge value
func (g *Gauge) Set(v float64) {
	atomic.StoreInt64(&g.value, int64(v))
}

// Value returns the current gauge value
func (g *Gauge) Value() int64 {
	return atomic.LoadInt64(&g.value)
}

// Histogram collects observations
type Histogram struct {
	count int64
	sum   int64
}

// Observe adds an observation
func (h *Histogram) Observe(v float64) {
	atomic.AddInt64(&h.count, 1)
	atomic.AddInt64(&h.sum, int64(v))
}
