package util

import (
	"sync"
	"sync/atomic"
	"time"
)

// FlowActivityTracker отслеживает активность потоков без блокировок в горячем пути
// ОПТИМИЗАЦИЯ: Использует lock-free подход для обновления активности
type FlowActivityTracker struct {
	// Основная карта с блокировкой (используется для чтения и периодической очистки)
	activityMap map[interface{}]int64 // UnixNano timestamp
	mu          sync.RWMutex
	
	// Lock-free канал для обновлений активности
	updateChan chan flowUpdate
	
	// Флаг для остановки
	stopChan chan struct{}
	wg       sync.WaitGroup
	
	// Время последней очистки
	lastCleanup int64 // UnixNano
}

type flowUpdate struct {
	key  interface{}
	time int64 // UnixNano
}

// NewFlowActivityTracker создает новый трекер активности потоков
func NewFlowActivityTracker(bufferSize int) *FlowActivityTracker {
	if bufferSize <= 0 {
		bufferSize = 1024
	}
	
	tracker := &FlowActivityTracker{
		activityMap: make(map[interface{}]int64),
		updateChan:  make(chan flowUpdate, bufferSize),
		stopChan:    make(chan struct{}),
		lastCleanup: time.Now().UnixNano(),
	}
	
	tracker.start()
	return tracker
}

// start запускает воркер для обработки обновлений
func (f *FlowActivityTracker) start() {
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		
		for {
			select {
			case <-f.stopChan:
				return
			case update := <-f.updateChan:
				// ОПТИМИЗАЦИЯ: Батчинг обновлений
				f.mu.Lock()
				f.activityMap[update.key] = update.time
				f.mu.Unlock()
			case <-ticker.C:
				// Периодическая очистка неактивных потоков
				f.cleanup()
			}
		}
	}()
}

// Update обновляет активность потока (lock-free, неблокирующий)
func (f *FlowActivityTracker) Update(key interface{}) {
	now := time.Now().UnixNano()
	select {
	case f.updateChan <- flowUpdate{key: key, time: now}:
	default:
		// ОПТИМИЗАЦИЯ: Если канал переполнен, пропускаем обновление
		// Это не критично для производительности
	}
}

// Get возвращает время последней активности (с блокировкой)
func (f *FlowActivityTracker) Get(key interface{}) (time.Time, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	
	if t, ok := f.activityMap[key]; ok {
		return time.Unix(0, t), true
	}
	return time.Time{}, false
}

// cleanup удаляет неактивные потоки
func (f *FlowActivityTracker) cleanup() {
	now := time.Now().UnixNano()
	idleTimeout := int64(2 * time.Minute)
	
	f.mu.Lock()
	defer f.mu.Unlock()
	
	// Обновляем время последней очистки
	atomic.StoreInt64(&f.lastCleanup, now)
	
	for key, lastTime := range f.activityMap {
		if now-lastTime > idleTimeout {
			delete(f.activityMap, key)
		}
	}
}

// Close останавливает трекер
func (f *FlowActivityTracker) Close() {
	close(f.stopChan)
	f.wg.Wait()
}

