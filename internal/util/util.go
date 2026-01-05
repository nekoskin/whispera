package util

import (
	"log"
	"sync"
	"time"
)

// SafeClose safely closes a resource and logs any error
func SafeClose(name string, closer func() error) {
	if err := closer(); err != nil {
		log.Printf("[WARN] Failed to close %s: %v", name, err)
	}
}

// TimeCache provides cached time for performance
type TimeCache struct {
	mu      sync.RWMutex
	current time.Time
}

var globalTimeCache = &TimeCache{current: time.Now()}

func init() {
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		for t := range ticker.C {
			globalTimeCache.mu.Lock()
			globalTimeCache.current = t
			globalTimeCache.mu.Unlock()
		}
	}()
}

// GetGlobalTimeCache returns the global time cache
func GetGlobalTimeCache() *TimeCache {
	return globalTimeCache
}

// Now returns the cached current time
func (tc *TimeCache) Now() time.Time {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.current
}

// NowNano returns the cached current time as nanoseconds
func (tc *TimeCache) NowNano() int64 {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.current.UnixNano()
}
