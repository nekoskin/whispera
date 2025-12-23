package xhttp

import (
	"bytes"
	"sync"

	metr "whispera/internal/metrics"
)

// BufferPool manages reusable byte buffers to reduce GC pressure
type BufferPool struct {
	small  sync.Pool // 4KB buffers
	medium sync.Pool // 16KB buffers
	large  sync.Pool // 64KB buffers
	xlarge sync.Pool // 256KB buffers

	stats BufferPoolStats
	mu    sync.RWMutex
}

// BufferPoolStats tracks buffer pool statistics
type BufferPoolStats struct {
	AllocatedSmall  uint64
	AllocatedMedium uint64
	AllocatedLarge  uint64
	AllocatedXLarge uint64
	ReleasedSmall   uint64
	ReleasedMedium  uint64
	ReleasedLarge   uint64
	ReleasedXLarge  uint64
	ReusedSmall     uint64
	ReusedMedium    uint64
	ReusedLarge     uint64
	ReusedXLarge    uint64
}

const (
	bufferSizeSmall  = 4096   // 4KB
	bufferSizeMedium = 16384  // 16KB
	bufferSizeLarge  = 65536  // 64KB
	bufferSizeXLarge = 262144 // 256KB
)

// NewBufferPool creates new buffer pool
func NewBufferPool() *BufferPool {
	return &BufferPool{
		stats: BufferPoolStats{},
	}
}

// GetSmallBuffer gets a 4KB buffer from pool
func (bp *BufferPool) GetSmallBuffer() *bytes.Buffer {
	b := bp.small.Get()
	if b == nil {
		bp.mu.Lock()
		bp.stats.AllocatedSmall++
		bp.mu.Unlock()
		metr.XHTTPBufferPoolMisses.Inc()
		return bytes.NewBuffer(make([]byte, 0, bufferSizeSmall))
	}

	bp.mu.Lock()
	bp.stats.ReusedSmall++
	bp.mu.Unlock()

	metr.XHTTPBufferPoolHits.Inc()
	return b.(*bytes.Buffer)
}

// GetMediumBuffer gets a 16KB buffer from pool
func (bp *BufferPool) GetMediumBuffer() *bytes.Buffer {
	b := bp.medium.Get()
	if b == nil {
		bp.mu.Lock()
		bp.stats.AllocatedMedium++
		bp.mu.Unlock()
		metr.XHTTPBufferPoolMisses.Inc()
		return bytes.NewBuffer(make([]byte, 0, bufferSizeMedium))
	}

	bp.mu.Lock()
	bp.stats.ReusedMedium++
	bp.mu.Unlock()

	metr.XHTTPBufferPoolHits.Inc()
	return b.(*bytes.Buffer)
}

// GetLargeBuffer gets a 64KB buffer from pool
func (bp *BufferPool) GetLargeBuffer() *bytes.Buffer {
	b := bp.large.Get()
	if b == nil {
		bp.mu.Lock()
		bp.stats.AllocatedLarge++
		bp.mu.Unlock()
		return bytes.NewBuffer(make([]byte, 0, bufferSizeLarge))
	}

	bp.mu.Lock()
	bp.stats.ReusedLarge++
	bp.mu.Unlock()

	return b.(*bytes.Buffer)
}

// GetXLargeBuffer gets a 256KB buffer from pool
func (bp *BufferPool) GetXLargeBuffer() *bytes.Buffer {
	b := bp.xlarge.Get()
	if b == nil {
		bp.mu.Lock()
		bp.stats.AllocatedXLarge++
		bp.mu.Unlock()
		return bytes.NewBuffer(make([]byte, 0, bufferSizeXLarge))
	}

	bp.mu.Lock()
	bp.stats.ReusedXLarge++
	bp.mu.Unlock()

	return b.(*bytes.Buffer)
}

// GetBufferForSize gets appropriate buffer for given size
func (bp *BufferPool) GetBufferForSize(size int) *bytes.Buffer {
	if size <= bufferSizeSmall {
		return bp.GetSmallBuffer()
	} else if size <= bufferSizeMedium {
		return bp.GetMediumBuffer()
	} else if size <= bufferSizeLarge {
		return bp.GetLargeBuffer()
	} else {
		return bp.GetXLargeBuffer()
	}
}

// PutSmallBuffer returns buffer to pool
func (bp *BufferPool) PutSmallBuffer(b *bytes.Buffer) {
	b.Reset()
	bp.mu.Lock()
	bp.stats.ReleasedSmall++
	bp.mu.Unlock()
	bp.small.Put(b)
}

// PutMediumBuffer returns buffer to pool
func (bp *BufferPool) PutMediumBuffer(b *bytes.Buffer) {
	b.Reset()
	bp.mu.Lock()
	bp.stats.ReleasedMedium++
	bp.mu.Unlock()
	bp.medium.Put(b)
}

// PutLargeBuffer returns buffer to pool
func (bp *BufferPool) PutLargeBuffer(b *bytes.Buffer) {
	b.Reset()
	bp.mu.Lock()
	bp.stats.ReleasedLarge++
	bp.mu.Unlock()
	bp.large.Put(b)
}

// PutXLargeBuffer returns buffer to pool
func (bp *BufferPool) PutXLargeBuffer(b *bytes.Buffer) {
	b.Reset()
	bp.mu.Lock()
	bp.stats.ReleasedXLarge++
	bp.mu.Unlock()
	bp.xlarge.Put(b)
}

// PutBuffer returns buffer to appropriate pool based on capacity
func (bp *BufferPool) PutBuffer(b *bytes.Buffer) {
	if b == nil {
		return
	}

	cap := b.Cap()
	if cap <= bufferSizeSmall {
		bp.PutSmallBuffer(b)
	} else if cap <= bufferSizeMedium {
		bp.PutMediumBuffer(b)
	} else if cap <= bufferSizeLarge {
		bp.PutLargeBuffer(b)
	} else {
		bp.PutXLargeBuffer(b)
	}
}

// GetStats returns buffer pool statistics
func (bp *BufferPool) GetStats() BufferPoolStats {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	return bp.stats
}

// ConnectionPool manages reusable connection resources
type ConnectionPool struct {
	mu              sync.RWMutex
	availableConns  map[string][]*PooledConnection
	maxPerHost      int
	cleanupInterval uint
	stats           ConnectionPoolStats
}

// PooledConnection represents a pooled connection
type PooledConnection struct {
	ID        string
	Host      string
	CreatedAt int64
	LastUsed  int64
	Reused    uint
	Conn      interface{} // Generic connection (can be net.Conn, etc)
}

// ConnectionPoolStats tracks connection pool statistics
type ConnectionPoolStats struct {
	TotalCreated  uint64
	TotalReused   uint64
	TotalEvicted  uint64
	CurrentPooled uint64
	EvictionCount uint64
}

// NewConnectionPool creates new connection pool
func NewConnectionPool(maxPerHost int) *ConnectionPool {
	return &ConnectionPool{
		availableConns: make(map[string][]*PooledConnection),
		maxPerHost:     maxPerHost,
		stats:          ConnectionPoolStats{},
	}
}

// GetConnection gets a connection from pool for host
func (cp *ConnectionPool) GetConnection(host string) *PooledConnection {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	conns := cp.availableConns[host]
	if len(conns) > 0 {
		// Get last connection (LIFO)
		conn := conns[len(conns)-1]
		cp.availableConns[host] = conns[:len(conns)-1]

		conn.LastUsed = now()
		conn.Reused++

		cp.stats.TotalReused++
		cp.stats.CurrentPooled--

		return conn
	}

	return nil
}

// PutConnection returns connection to pool
func (cp *ConnectionPool) PutConnection(conn *PooledConnection) bool {
	if conn == nil {
		return false
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()

	conns := cp.availableConns[conn.Host]
	if len(conns) >= cp.maxPerHost {
		// Pool full, don't add
		cp.stats.TotalEvicted++
		cp.stats.EvictionCount++
		return false
	}

	cp.availableConns[conn.Host] = append(conns, conn)
	cp.stats.CurrentPooled++
	return true
}

// Clear clears all pooled connections
func (cp *ConnectionPool) Clear() {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	for host := range cp.availableConns {
		delete(cp.availableConns, host)
	}
	cp.stats.CurrentPooled = 0
}

// GetStats returns connection pool statistics
func (cp *ConnectionPool) GetStats() ConnectionPoolStats {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	return cp.stats
}

// FrameEncoderPool manages reusable frame encoders
type FrameEncoderPool struct {
	encoders  sync.Pool
	stats     sync.Mutex
	allocated uint64
	reused    uint64
}

// FrameEncoder encodes XMUX frames
type FrameEncoder struct {
	buffer *bytes.Buffer
}

// NewFrameEncoderPool creates new frame encoder pool
func NewFrameEncoderPool() *FrameEncoderPool {
	return &FrameEncoderPool{}
}

// Get gets a frame encoder from pool
func (fep *FrameEncoderPool) Get() *FrameEncoder {
	fe := fep.encoders.Get()
	if fe == nil {
		fep.stats.Lock()
		fep.allocated++
		fep.stats.Unlock()
		return &FrameEncoder{
			buffer: bytes.NewBuffer(make([]byte, 0, 4096)),
		}
	}

	fep.stats.Lock()
	fep.reused++
	fep.stats.Unlock()

	encoder := fe.(*FrameEncoder)
	encoder.buffer.Reset()
	return encoder
}

// Put returns frame encoder to pool
func (fep *FrameEncoderPool) Put(fe *FrameEncoder) {
	if fe == nil {
		return
	}
	fe.buffer.Reset()
	fep.encoders.Put(fe)
}

// GetStats returns pool statistics
func (fep *FrameEncoderPool) GetStats() (allocated, reused uint64) {
	fep.stats.Lock()
	defer fep.stats.Unlock()
	return fep.allocated, fep.reused
}

// PerformanceOptimizer combines all optimization strategies
type PerformanceOptimizer struct {
	bufferPool       *BufferPool
	connPool         *ConnectionPool
	frameEncoderPool *FrameEncoderPool
}

// NewPerformanceOptimizer creates new performance optimizer
func NewPerformanceOptimizer() *PerformanceOptimizer {
	return &PerformanceOptimizer{
		bufferPool:       NewBufferPool(),
		connPool:         NewConnectionPool(10), // 10 connections per host
		frameEncoderPool: NewFrameEncoderPool(),
	}
}

// GetBufferPool returns buffer pool
func (po *PerformanceOptimizer) GetBufferPool() *BufferPool {
	return po.bufferPool
}

// GetConnectionPool returns connection pool
func (po *PerformanceOptimizer) GetConnectionPool() *ConnectionPool {
	return po.connPool
}

// GetFrameEncoderPool returns frame encoder pool
func (po *PerformanceOptimizer) GetFrameEncoderPool() *FrameEncoderPool {
	return po.frameEncoderPool
}

// GetPerformanceMetrics returns comprehensive performance metrics
func (po *PerformanceOptimizer) GetPerformanceMetrics() map[string]interface{} {
	return map[string]interface{}{
		"buffer_pool":     po.bufferPool.GetStats(),
		"connection_pool": po.connPool.GetStats(),
		"frame_encoder": map[string]uint64{
			"allocated": func() uint64 {
				a, _ := po.frameEncoderPool.GetStats()
				return a
			}(),
			"reused": func() uint64 {
				_, r := po.frameEncoderPool.GetStats()
				return r
			}(),
		},
	}
}

// Helper function for current timestamp
func now() int64 {
	return 0 // Placeholder - in real implementation use time.Now().Unix()
}
