package util

import (
	"sync"
	"sync/atomic"
	"time"
)

// TimeCache предоставляет кэшированное время для уменьшения вызовов time.Now()
// ОПТИМИЗАЦИЯ: Кэшируем время на 1ms для уменьшения системных вызовов
type TimeCache struct {
	lastTime  int64 // UnixNano
	lastTime2 int64 // UnixNano для второго кэша
	mu        sync.RWMutex
}

var (
	globalTimeCache = &TimeCache{}
	timeCacheOnce   sync.Once
)

// GetGlobalTimeCache возвращает глобальный кэш времени
func GetGlobalTimeCache() *TimeCache {
	timeCacheOnce.Do(func() {
		globalTimeCache.lastTime = time.Now().UnixNano()
		// Запускаем обновление каждую миллисекунду
		go func() {
			ticker := time.NewTicker(1 * time.Millisecond)
			defer ticker.Stop()
			for range ticker.C {
				atomic.StoreInt64(&globalTimeCache.lastTime, time.Now().UnixNano())
			}
		}()
	})
	return globalTimeCache
}

// Now возвращает кэшированное время
func (tc *TimeCache) Now() time.Time {
	// ОПТИМИЗАЦИЯ: Используем atomic для lock-free чтения
	nano := atomic.LoadInt64(&tc.lastTime)
	if nano == 0 {
		return time.Now()
	}
	return time.Unix(0, nano)
}

// NowNano возвращает кэшированное время в наносекундах
func (tc *TimeCache) NowNano() int64 {
	return atomic.LoadInt64(&tc.lastTime)
}

// Since возвращает разницу между текущим временем и t
func (tc *TimeCache) Since(t time.Time) time.Duration {
	return tc.Now().Sub(t)
}

