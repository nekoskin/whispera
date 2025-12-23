package proto

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/util"
)

// StreamPriority - приоритет потока
type StreamPriority int

const (
	PriorityLow StreamPriority = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical
)

// StreamProcessor - обработчик потока с поддержкой concurrency
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

// ConcurrentStreamMultiplexer - мультиплексер с поддержкой concurrency
type ConcurrentStreamMultiplexer struct {
	*StreamMultiplexer
	processors     map[uint16]*StreamProcessor
	processorMu    sync.RWMutex
	maxConcurrency  int // Максимальное количество одновременных потоков
	currentWorkers  int32
	workerPool      chan struct{} // Semaphore для ограничения concurrency
	priorityQueue   *PriorityQueue
	padding         *MuxPadding // Обработчик padding для Mux потоков
	shutdown        chan struct{}
	wg              sync.WaitGroup
}

// PriorityQueue - очередь приоритетов для потоков
type PriorityQueue struct {
	queues map[StreamPriority][]*StreamProcessor
	mu     sync.Mutex
	cond   *sync.Cond
}

// NewPriorityQueue создает новую очередь приоритетов
func NewPriorityQueue() *PriorityQueue {
	pq := &PriorityQueue{
		queues: make(map[StreamPriority][]*StreamProcessor),
	}
	pq.cond = sync.NewCond(&pq.mu)
	return pq
}

// Push добавляет процессор в очередь
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

// Pop извлекает процессор с наивысшим приоритетом
func (pq *PriorityQueue) Pop() *StreamProcessor {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	
	// Ищем процессор с наивысшим приоритетом
	for priority := PriorityCritical; priority >= PriorityLow; priority-- {
		if queue, exists := pq.queues[priority]; exists && len(queue) > 0 {
			processor := queue[0]
			pq.queues[priority] = queue[1:]
			return processor
		}
	}
	return nil
}

// Wait ждет, пока в очереди появится элемент
func (pq *PriorityQueue) Wait(ctx context.Context) *StreamProcessor {
	for {
		pq.mu.Lock()
		processor := pq.Pop()
		if processor != nil {
			pq.mu.Unlock()
			return processor
		}
		
		// Ждем сигнала или отмены контекста
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

// NewConcurrentStreamMultiplexer создает новый concurrent мультиплексер
func NewConcurrentStreamMultiplexer(maxConcurrency int) *ConcurrentStreamMultiplexer {
	if maxConcurrency <= 0 {
		maxConcurrency = 100 // По умолчанию 100 одновременных потоков
	}
	
	csm := &ConcurrentStreamMultiplexer{
		StreamMultiplexer: NewStreamMultiplexer(),
		processors:        make(map[uint16]*StreamProcessor),
		maxConcurrency:    maxConcurrency,
		workerPool:        make(chan struct{}, maxConcurrency),
		priorityQueue:     NewPriorityQueue(),
		padding:           NewMuxPadding(DefaultMuxPaddingConfig()),
		shutdown:          make(chan struct{}),
	}
	
	// Запускаем worker pool
	csm.startWorkerPool()
	
	return csm
}

// NewConcurrentStreamMultiplexerWithPadding создает новый concurrent мультиплексер с настройками padding
func NewConcurrentStreamMultiplexerWithPadding(maxConcurrency int, paddingConfig *MuxPaddingConfig) *ConcurrentStreamMultiplexer {
	if maxConcurrency <= 0 {
		maxConcurrency = 100
	}
	
	csm := &ConcurrentStreamMultiplexer{
		StreamMultiplexer: NewStreamMultiplexer(),
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

// SetPaddingConfig устанавливает конфигурацию padding
func (csm *ConcurrentStreamMultiplexer) SetPaddingConfig(config *MuxPaddingConfig) {
	if csm.padding != nil {
		csm.padding.SetConfig(config)
	}
}

// SetMaxConcurrency обновляет максимальное количество одновременных потоков
// ВАЖНО: Это обновляет только размер workerPool для новых потоков.
// Уже работающие потоки продолжают работать, но новые будут ограничены новым значением.
func (csm *ConcurrentStreamMultiplexer) SetMaxConcurrency(newMax int) {
	if newMax <= 0 {
		newMax = 100 // Дефолт
	}
	
	csm.processorMu.Lock()
	csm.maxConcurrency = newMax
	
	// Пересоздаем workerPool с новым размером
	// Закрываем старый канал (если он еще не закрыт)
	select {
	case <-csm.shutdown:
		// Уже закрыт, просто создаем новый
	default:
		close(csm.workerPool)
	}
	csm.workerPool = make(chan struct{}, newMax)
	csm.processorMu.Unlock()
}

// GetPaddingConfig возвращает текущую конфигурацию padding
func (csm *ConcurrentStreamMultiplexer) GetPaddingConfig() *MuxPaddingConfig {
	if csm.padding != nil {
		return csm.padding.GetConfig()
	}
	return DefaultMuxPaddingConfig()
}

// startWorkerPool запускает пул воркеров для обработки потоков
func (csm *ConcurrentStreamMultiplexer) startWorkerPool() {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Запускаем воркеры
	numWorkers := csm.maxConcurrency
	if numWorkers > 100 {
		numWorkers = 100 // Ограничиваем количество воркеров
	}
	
	for i := 0; i < numWorkers; i++ {
		csm.wg.Add(1)
		go csm.worker(ctx)
	}
	
	// Graceful shutdown
	go func() {
		<-csm.shutdown
		cancel()
		csm.wg.Wait()
	}()
}

// worker обрабатывает потоки из очереди приоритетов
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
			
			// Обрабатываем данные из канала процессора
			csm.processStream(processor)
		}
	}
}

// processStream обрабатывает данные из потока
func (csm *ConcurrentStreamMultiplexer) processStream(processor *StreamProcessor) {
	// Получаем слот из worker pool
	select {
	case csm.workerPool <- struct{}{}:
		atomic.AddInt32(&csm.currentWorkers, 1)
		defer func() {
			<-csm.workerPool
			atomic.AddInt32(&csm.currentWorkers, -1)
		}()
	default:
		// Worker pool переполнен, возвращаем процессор в очередь
		csm.priorityQueue.Push(processor)
		return
	}
	
	// Обрабатываем данные из канала
	for {
		select {
		case data, ok := <-processor.dataChan:
			if !ok {
				return
			}
			
			// Удаляем padding если он был применен
			if csm.padding != nil && csm.padding.HasPadding(data) {
				data = csm.padding.RemovePadding(data)
			}
			
			// Обработка данных (здесь можно добавить логику обработки)
			// ОПТИМИЗАЦИЯ: Используем кэшированное время для уменьшения системных вызовов
			processor.mu.Lock()
			processor.processed++
			timeCache := util.GetGlobalTimeCache()
			processor.lastProcess = timeCache.Now()
			processor.mu.Unlock()
			
			// Здесь можно вызвать callback для обработки данных
			// Например: handler(processor.streamID, data)
			_ = data // Используем переменную, чтобы избежать ошибки компиляции
			
		case <-processor.ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
			// Таймаут для предотвращения блокировки
			return
		}
	}
}

// RegisterStreamProcessor регистрирует процессор для потока
func (csm *ConcurrentStreamMultiplexer) RegisterStreamProcessor(streamID uint16, priority StreamPriority, bufferSize int) *StreamProcessor {
	csm.processorMu.Lock()
	defer csm.processorMu.Unlock()
	
	// Проверяем, не существует ли уже процессор
	if processor, exists := csm.processors[streamID]; exists {
		return processor
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	// ОПТИМИЗАЦИЯ: Используем кэшированное время
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
	
	// Добавляем в очередь приоритетов
	csm.priorityQueue.Push(processor)
	
	return processor
}

// SendToStream отправляет данные в поток (неблокирующая операция)
// Автоматически применяет padding если он настроен
func (csm *ConcurrentStreamMultiplexer) SendToStream(streamID uint16, data []byte) error {
	csm.processorMu.RLock()
	processor, exists := csm.processors[streamID]
	csm.processorMu.RUnlock()
	
	if !exists {
		// Создаем процессор с нормальным приоритетом
		processor = csm.RegisterStreamProcessor(streamID, PriorityNormal, 100)
	}
	
	// Применяем padding если он настроен
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
		// Таймаут - поток перегружен
		atomic.AddInt64(&processor.errors, 1)
		return ErrStreamOverloaded
	default:
		// Канал переполнен
		atomic.AddInt64(&processor.errors, 1)
		return ErrStreamOverloaded
	}
}

// CloseStreamProcessor закрывает процессор потока
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
	
	// Закрываем поток в базовом мультиплексере
	csm.CloseStream(streamID)
}

// SetStreamPriority устанавливает приоритет потока
func (csm *ConcurrentStreamMultiplexer) SetStreamPriority(streamID uint16, priority StreamPriority) {
	csm.processorMu.Lock()
	defer csm.processorMu.Unlock()
	
	if processor, exists := csm.processors[streamID]; exists {
		processor.mu.Lock()
		processor.priority = priority
		processor.mu.Unlock()
		
		// Перемещаем в очередь с новым приоритетом
		csm.priorityQueue.Push(processor)
	}
}

// GetStreamStats возвращает статистику потока
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

// GetConcurrencyStats возвращает статистику concurrency
func (csm *ConcurrentStreamMultiplexer) GetConcurrencyStats() (currentWorkers int32, maxConcurrency int, activeStreams int) {
	currentWorkers = atomic.LoadInt32(&csm.currentWorkers)
	maxConcurrency = csm.maxConcurrency
	
	csm.processorMu.RLock()
	activeStreams = len(csm.processors)
	csm.processorMu.RUnlock()
	
	return currentWorkers, maxConcurrency, activeStreams
}

// Shutdown останавливает мультиплексер
func (csm *ConcurrentStreamMultiplexer) Shutdown() {
	close(csm.shutdown)
	
	// Закрываем все процессоры
	csm.processorMu.Lock()
	for streamID := range csm.processors {
		csm.CloseStreamProcessor(streamID)
	}
	csm.processorMu.Unlock()
}

// ErrStreamOverloaded - ошибка перегрузки потока
var ErrStreamOverloaded = &StreamError{Message: "stream overloaded"}

// StreamError - ошибка потока
type StreamError struct {
	Message string
}

func (e *StreamError) Error() string {
	return e.Message
}

