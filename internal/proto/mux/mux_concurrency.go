package mux

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/proto/multi"
	"whispera/internal/util"
)

type StreamMultiplexer = multi.StreamMultiplexer
type Stream = multi.Stream

func NewStreamMultiplexer() *StreamMultiplexer {
	return multi.NewStreamMultiplexer()
}

type StreamPriority int

const (
	PriorityLow StreamPriority = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical
)

type StreamProcessor struct {
	streamID    uint16
	priority    StreamPriority
	dataChan    chan []byte
	ctx         context.Context
	cancel      context.CancelFunc
	processed   int64
	errors      int64
	lastProcess time.Time
	mu          sync.RWMutex
}

type ConcurrentStreamMultiplexer struct {
	*StreamMultiplexer
	processors     map[uint16]*StreamProcessor
	processorMu    sync.RWMutex
	maxConcurrency int
	currentWorkers int32
	workerPool     chan struct{}
	priorityQueue  *PriorityQueue
	padding        *MuxPadding
	shutdown       chan struct{}
	wg             sync.WaitGroup
}

type PriorityQueue struct {
	queues map[StreamPriority][]*StreamProcessor
	mu     sync.Mutex
	cond   *sync.Cond
}

func NewPriorityQueue() *PriorityQueue {
	pq := &PriorityQueue{
		queues: make(map[StreamPriority][]*StreamProcessor),
	}
	pq.cond = sync.NewCond(&pq.mu)
	return pq
}

func (pq *PriorityQueue) Push(processor *StreamProcessor) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	priority := processor.priority
	if pq.queues[priority] == nil {
		pq.queues[priority] = make([]*StreamProcessor, 0)
	}
	pq.queues[priority] = append(pq.queues[priority], processor)
	pq.cond.Signal()
}

func (pq *PriorityQueue) Pop() *StreamProcessor {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	for priority := PriorityCritical; priority >= PriorityLow; priority-- {
		if queue, exists := pq.queues[priority]; exists && len(queue) > 0 {
			processor := queue[0]
			pq.queues[priority] = queue[1:]
			return processor
		}
	}
	return nil
}

func (pq *PriorityQueue) Wait(ctx context.Context) *StreamProcessor {
	for {
		pq.mu.Lock()
		processor := pq.Pop()
		if processor != nil {
			pq.mu.Unlock()
			return processor
		}

		done := make(chan struct{})
		go func() {
			pq.cond.Wait()
			close(done)
		}()
		pq.mu.Unlock()

		select {
		case <-done:
			continue
		case <-ctx.Done():
			return nil
		}
	}
}

func NewConcurrentStreamMultiplexer(maxConcurrency int) *ConcurrentStreamMultiplexer {
	if maxConcurrency <= 0 {
		maxConcurrency = 100
	}

	csm := &ConcurrentStreamMultiplexer{
		StreamMultiplexer: multi.NewStreamMultiplexer(),
		processors:        make(map[uint16]*StreamProcessor),
		maxConcurrency:    maxConcurrency,
		workerPool:        make(chan struct{}, maxConcurrency),
		priorityQueue:     NewPriorityQueue(),
		padding:           NewMuxPadding(DefaultMuxPaddingConfig()),
		shutdown:          make(chan struct{}),
	}

	csm.startWorkerPool()

	return csm
}

func NewConcurrentStreamMultiplexerWithPadding(maxConcurrency int, paddingConfig *MuxPaddingConfig) *ConcurrentStreamMultiplexer {
	if maxConcurrency <= 0 {
		maxConcurrency = 100
	}

	csm := &ConcurrentStreamMultiplexer{
		StreamMultiplexer: multi.NewStreamMultiplexer(),
		processors:        make(map[uint16]*StreamProcessor),
		maxConcurrency:    maxConcurrency,
		workerPool:        make(chan struct{}, maxConcurrency),
		priorityQueue:     NewPriorityQueue(),
		padding:           NewMuxPadding(paddingConfig),
		shutdown:          make(chan struct{}),
	}

	csm.startWorkerPool()

	return csm
}

func (csm *ConcurrentStreamMultiplexer) SetPaddingConfig(config *MuxPaddingConfig) {
	if csm.padding != nil {
		csm.padding.SetConfig(config)
	}
}

func (csm *ConcurrentStreamMultiplexer) SetMaxConcurrency(newMax int) {
	if newMax <= 0 {
		newMax = 100
	}

	csm.processorMu.Lock()
	csm.maxConcurrency = newMax

	select {
	case <-csm.shutdown:
	default:
		close(csm.workerPool)
	}
	csm.workerPool = make(chan struct{}, newMax)
	csm.processorMu.Unlock()
}

func (csm *ConcurrentStreamMultiplexer) GetPaddingConfig() *MuxPaddingConfig {
	if csm.padding != nil {
		return csm.padding.GetConfig()
	}
	return DefaultMuxPaddingConfig()
}

func (csm *ConcurrentStreamMultiplexer) startWorkerPool() {
	ctx, cancel := context.WithCancel(context.Background())

	numWorkers := csm.maxConcurrency
	if numWorkers > 100 {
		numWorkers = 100
	}

	for i := 0; i < numWorkers; i++ {
		csm.wg.Add(1)
		go csm.worker(ctx)
	}

	go func() {
		<-csm.shutdown
		cancel()
		csm.wg.Wait()
	}()
}

func (csm *ConcurrentStreamMultiplexer) worker(ctx context.Context) {
	defer csm.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			processor := csm.priorityQueue.Wait(ctx)
			if processor == nil {
				continue
			}

			csm.processStream(processor)
		}
	}
}

func (csm *ConcurrentStreamMultiplexer) processStream(processor *StreamProcessor) {
	select {
	case csm.workerPool <- struct{}{}:
		atomic.AddInt32(&csm.currentWorkers, 1)
		defer func() {
			<-csm.workerPool
			atomic.AddInt32(&csm.currentWorkers, -1)
		}()
	default:
		csm.priorityQueue.Push(processor)
		return
	}

	for {
		select {
		case data, ok := <-processor.dataChan:
			if !ok {
				return
			}

			if csm.padding != nil && csm.padding.HasPadding(data) {
				data = csm.padding.RemovePadding(data)
			}

			processor.mu.Lock()
			processor.processed++
			timeCache := util.GetGlobalTimeCache()
			processor.lastProcess = timeCache.Now()
			processor.mu.Unlock()

			_ = data

		case <-processor.ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
			return
		}
	}
}

func (csm *ConcurrentStreamMultiplexer) RegisterStreamProcessor(streamID uint16, priority StreamPriority, bufferSize int) *StreamProcessor {
	csm.processorMu.Lock()
	defer csm.processorMu.Unlock()

	if processor, exists := csm.processors[streamID]; exists {
		return processor
	}

	ctx, cancel := context.WithCancel(context.Background())

	timeCache := util.GetGlobalTimeCache()
	processor := &StreamProcessor{
		streamID:    streamID,
		priority:    priority,
		dataChan:    make(chan []byte, bufferSize),
		ctx:         ctx,
		cancel:      cancel,
		lastProcess: timeCache.Now(),
	}

	csm.processors[streamID] = processor

	csm.priorityQueue.Push(processor)

	return processor
}

func (csm *ConcurrentStreamMultiplexer) SendToStream(streamID uint16, data []byte) error {
	csm.processorMu.RLock()
	processor, exists := csm.processors[streamID]
	csm.processorMu.RUnlock()

	if !exists {
		processor = csm.RegisterStreamProcessor(streamID, PriorityNormal, 100)
	}

	if csm.padding != nil {
		processor.mu.RLock()
		priority := processor.priority
		processor.mu.RUnlock()

		data = csm.padding.ApplyStreamPadding(streamID, priority, data)
	}

	select {
	case processor.dataChan <- data:
		return nil
	case <-time.After(100 * time.Millisecond):
		atomic.AddInt64(&processor.errors, 1)
		return ErrStreamOverloaded
	default:
		atomic.AddInt64(&processor.errors, 1)
		return ErrStreamOverloaded
	}
}

func (csm *ConcurrentStreamMultiplexer) CloseStreamProcessor(streamID uint16) {
	csm.processorMu.Lock()
	defer csm.processorMu.Unlock()

	processor, exists := csm.processors[streamID]
	if !exists {
		return
	}

	processor.cancel()
	close(processor.dataChan)
	delete(csm.processors, streamID)

	csm.CloseStream(streamID)
}

func (csm *ConcurrentStreamMultiplexer) SetStreamPriority(streamID uint16, priority StreamPriority) {
	csm.processorMu.Lock()
	defer csm.processorMu.Unlock()

	if processor, exists := csm.processors[streamID]; exists {
		processor.mu.Lock()
		processor.priority = priority
		processor.mu.Unlock()

		csm.priorityQueue.Push(processor)
	}
}

func (csm *ConcurrentStreamMultiplexer) GetStreamStats(streamID uint16) (processed int64, errors int64, lastProcess time.Time) {
	csm.processorMu.RLock()
	defer csm.processorMu.RUnlock()

	processor, exists := csm.processors[streamID]
	if !exists {
		return 0, 0, time.Time{}
	}

	processor.mu.RLock()
	defer processor.mu.RUnlock()

	return processor.processed, processor.errors, processor.lastProcess
}

func (csm *ConcurrentStreamMultiplexer) GetConcurrencyStats() (currentWorkers int32, maxConcurrency int, activeStreams int) {
	currentWorkers = atomic.LoadInt32(&csm.currentWorkers)
	maxConcurrency = csm.maxConcurrency

	csm.processorMu.RLock()
	activeStreams = len(csm.processors)
	csm.processorMu.RUnlock()

	return currentWorkers, maxConcurrency, activeStreams
}

func (csm *ConcurrentStreamMultiplexer) Shutdown() {
	close(csm.shutdown)

	csm.processorMu.Lock()
	for streamID := range csm.processors {
		csm.CloseStreamProcessor(streamID)
	}
	csm.processorMu.Unlock()
}

var ErrStreamOverloaded = &StreamError{Message: "stream overloaded"}

type StreamError struct {
	Message string
}

func (e *StreamError) Error() string {
	return e.Message
}
