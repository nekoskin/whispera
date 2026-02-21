package cache

import (
	"context"
	"sync"
	"time"
)


type entry struct {
	value     []byte
	expiresAt time.Time
	counter   int64 
}
type MemoryCache struct {
	data map[string]*entry
	mu   sync.RWMutex
}


func NewMemoryCache() *MemoryCache {
	mc := &MemoryCache{
		data: make(map[string]*entry),
	}
	
	go mc.cleanupLoop()
	return mc
}

func (m *MemoryCache) Get(ctx context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	e, ok := m.data[key]
	if !ok {
		return nil, nil
	}

	
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		return nil, nil
	}

	return e.value, nil
}

func (m *MemoryCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	e := &entry{value: value}
	if ttl > 0 {
		e.expiresAt = time.Now().Add(ttl)
	}
	m.data[key] = e
	return nil
}

func (m *MemoryCache) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *MemoryCache) Exists(ctx context.Context, key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	e, ok := m.data[key]
	if !ok {
		return false
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		return false
	}
	return true
}

func (m *MemoryCache) Incr(ctx context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.data[key]
	if !ok || (!e.expiresAt.IsZero() && time.Now().After(e.expiresAt)) {
		e = &entry{counter: 0}
		m.data[key] = e
	}
	e.counter++
	return e.counter, nil
}

func (m *MemoryCache) IncrWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.data[key]
	if !ok || (!e.expiresAt.IsZero() && time.Now().After(e.expiresAt)) {
		e = &entry{counter: 0}
		if ttl > 0 {
			e.expiresAt = time.Now().Add(ttl)
		}
		m.data[key] = e
	}
	e.counter++
	return e.counter, nil
}

func (m *MemoryCache) Close() error {
	return nil
}

func (m *MemoryCache) Ping(ctx context.Context) error {
	return nil
}

func (m *MemoryCache) Type() string {
	return "memory"
}


func (m *MemoryCache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.cleanup()
	}
}

func (m *MemoryCache) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for key, e := range m.data {
		if !e.expiresAt.IsZero() && now.After(e.expiresAt) {
			delete(m.data, key)
		}
	}
}
