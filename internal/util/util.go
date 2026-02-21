package util

import (
	"sync/atomic"
	"time"

	"whispera/internal/logger"
)

func SafeClose(name string, closer func() error) {
	if err := closer(); err != nil {
		logger.Warn("Failed to close %s: %v", name, err)
	}
}

type TimeCache struct {
	current atomic.Value
}

var globalTimeCache = &TimeCache{}

func init() {
	globalTimeCache.current.Store(time.Now())
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		for t := range ticker.C {
			globalTimeCache.current.Store(t)
		}
	}()
}

func GetGlobalTimeCache() *TimeCache {
	return globalTimeCache
}

func (tc *TimeCache) Now() time.Time {
	return tc.current.Load().(time.Time)
}

func (tc *TimeCache) NowNano() int64 {
	return tc.current.Load().(time.Time).UnixNano()
}
