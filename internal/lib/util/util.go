package util

import (
	"log"
	"sync"
	"time"
)

func SafeClose(name string, closer func() error) {
	if err := closer(); err != nil {
		log.Printf("[WARN] Failed to close %s: %v", name, err)
	}
}

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

func GetGlobalTimeCache() *TimeCache {
	return globalTimeCache
}
func (tc *TimeCache) Now() time.Time {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.current
}
