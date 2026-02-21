package marionette

import (
	"crypto/rand"
	"math"
	"math/big"
	"sync"
	"time"
	"whispera/internal/util"
)

var _ = []interface{}{
	(*Marionette).checkCircuitBreaker,
	(*Marionette).recordMLFailure,
	(*Marionette).recordMLSuccess,
	(*Marionette).cleanupMemory,
	(*Marionette).selectWeightedSize,
	(*Marionette).generateRealisticTiming,
	getBufferFromPool,
}


func (m *Marionette) checkCircuitBreaker() bool {
	now := util.GetGlobalTimeCache().Now()
	switch m.CircuitBreaker.State {
	case "closed":
		return true
	case "open":
		if now.Sub(m.CircuitBreaker.LastFailureTime) > m.CircuitBreaker.Timeout {
			m.CircuitBreaker.State = "half-open"
			return true
		}
		return false
	case "half-open":
		return true
	default:
		return false
	}
}

func (m *Marionette) recordMLFailure() {
	m.CircuitBreaker.FailureCount++
	m.CircuitBreaker.LastFailureTime = util.GetGlobalTimeCache().Now()
	m.Metrics.MLFailures++
	if m.CircuitBreaker.FailureCount >= m.CircuitBreaker.Threshold {
		m.CircuitBreaker.State = "open"
		m.FallbackMode = true
		m.Metrics.CircuitBreakerTrips++
	}
}

func (m *Marionette) recordMLSuccess() {
	if m.CircuitBreaker.State == "half-open" {
		m.CircuitBreaker.State = "closed"
		m.CircuitBreaker.FailureCount = 0
		m.disableFallbackMode()
	}
	m.Metrics.MLPredictions++
}


func (m *Marionette) cleanupMemory() {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	now := util.GetGlobalTimeCache().Now()
	if now.Sub(m.State.LastCleanup) < m.State.CleanupInterval {
		return
	}

	if len(m.State.PacketSizes) > m.State.MaxHistorySize {
		m.State.PacketSizes = m.State.PacketSizes[len(m.State.PacketSizes)-m.State.MaxHistorySize/2:]
	}
	if len(m.State.Intervals) > m.State.MaxHistorySize {
		m.State.Intervals = m.State.Intervals[len(m.State.Intervals)-m.State.MaxHistorySize/2:]
	}

	if m.getCoverTrafficSize() > 0 && now.Sub(m.State.LastCleanup) > 10*time.Minute {
		m.clearCoverTraffic()
	}
	m.State.LastCleanup = now
	m.Metrics.LastCleanup = now
}


func (m *Marionette) selectWeightedSize(sizes []int, weights []float64) int {
	const maxSafeMTU = 1400
	if len(sizes) != len(weights) {
		if sizes[0] > maxSafeMTU {
			return maxSafeMTU
		}
		return sizes[0]
	}
	total := 0.0
	for _, w := range weights {
		total += w
	}
	val := float64(m.generateRealisticRandom(10000)) / 10000.0 * total
	cum := 0.0
	for i, w := range weights {
		cum += w
		if val <= cum {
			if sizes[i] > maxSafeMTU {
				return maxSafeMTU
			}
			return sizes[i]
		}
	}
	res := sizes[len(sizes)-1]
	if res > maxSafeMTU {
		return maxSafeMTU
	}
	return res
}

func (m *Marionette) generateRealisticRandom(max int) int {
	if max <= 0 {
		return 0
	}
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	return m.Rand.Intn(max)
}

func (m *Marionette) generateRealisticTiming(baseDelay int, variance float64) time.Duration {
	delay := float64(baseDelay) * (1.0 + variance)
	delay += m.generateHumanThinkTime()
	delay += m.generateNetworkJitter()
	if delay < 10 {
		delay = 10
	}
	return time.Duration(delay) * time.Millisecond
}

func (m *Marionette) generateHumanThinkTime() float64 {
	u := float64(m.generateRealisticRandom(10000)) / 10000.0
	if u == 0 {
		u = 0.0001
	}
	thinkTime := -math.Log(u) / 0.3
	if thinkTime < 0.1 {
		thinkTime = 0.1
	}
	if thinkTime > 30.0 {
		thinkTime = 30.0
	}
	return thinkTime * 1000
}

func (m *Marionette) generateNetworkJitter() float64 {
	u1 := float64(m.generateRealisticRandom(10000)) / 10000.0
	u2 := float64(m.generateRealisticRandom(10000)) / 10000.0
	if u1 == 0 {
		u1 = 0.0001
	}
	z0 := math.Sqrt(-2.0*math.Log(u1)) * math.Cos(2.0*math.Pi*u2)
	jitter := 10.0 + 5.0*z0
	if jitter < 0 {
		jitter = 0
	}
	return jitter
}

func (m *Marionette) generateRandomFloat() float64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(10000))
	return float64(n.Int64()) / 10000.0
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func (m *Marionette) resizeToTarget(data []byte, targetSize int) []byte {
	if len(data) == targetSize {
		return data
	}
	if len(data) > targetSize {
		return data[:targetSize]
	}
	padding := make([]byte, targetSize-len(data))
	for i := range padding {
		padding[i] = byte(m.generateRealisticRandom(256))
	}
	res := make([]byte, targetSize)
	copy(res, data)
	copy(res[len(data):], padding)
	return res
}


var (
	smallBufferPool = sync.Pool{
		New: func() interface{} { return make([]byte, 0, 8) },
	}
	mediumBufferPool = sync.Pool{
		New: func() interface{} { return make([]byte, 0, 64) },
	}
	largeBufferPool = sync.Pool{
		New: func() interface{} { return make([]byte, 0, 512) },
	}
	extraLargeBufferPool = sync.Pool{
		New: func() interface{} { return make([]byte, 0, 2048) },
	}
	mlResultChanPool = sync.Pool{
		New: func() interface{} { return make(chan []byte, 1) },
	}
	mlErrorChanPool = sync.Pool{
		New: func() interface{} { return make(chan error, 1) },
	}
)

func getBufferFromPool(size int) []byte {
	var pool *sync.Pool
	if size <= 8 {
		pool = &smallBufferPool
	} else if size <= 64 {
		pool = &mediumBufferPool
	} else if size <= 512 {
		pool = &largeBufferPool
	} else {
		pool = &extraLargeBufferPool
	}
	buf := pool.Get().([]byte)
	if cap(buf) < size {
		return make([]byte, 0, size)
	}
	return buf[:0]
}

func putBufferToPool(buf []byte) {
	if cap(buf) == 0 {
		return
	}
	var pool *sync.Pool
	cs := cap(buf)
	if cs <= 8 {
		pool = &smallBufferPool
	} else if cs <= 64 {
		pool = &mediumBufferPool
	} else if cs <= 512 {
		pool = &largeBufferPool
	} else if cs <= 2048 {
		pool = &extraLargeBufferPool
	} else {
		return
	}
	pool.Put(buf[:0])
}

func (m *Marionette) processWithTimeout(data []byte, processor func([]byte) ([]byte, error), timeout time.Duration) ([]byte, error) {
	resultChan := mlResultChanPool.Get().(chan []byte)
	errorChan := mlErrorChanPool.Get().(chan error)
	defer mlResultChanPool.Put(resultChan)
	defer mlErrorChanPool.Put(errorChan)

	go func() {
		result, err := processor(data)
		select {
		case resultChan <- result:
		default:
		}
		select {
		case errorChan <- err:
		default:
		}
	}()

	select {
	case result := <-resultChan:
		err := <-errorChan
		return result, err
	case <-time.After(timeout):
		return data, nil
	}
}

func (m *Marionette) processWithBufferReuse(data []byte, transform func([]byte)) []byte {
	buf := getBufferFromPool(len(data))
	buf = append(buf, data...)

	transform(buf)

	result := make([]byte, len(buf))
	copy(result, buf)

	putBufferToPool(buf)

	return result
}
