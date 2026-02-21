package cache

import (
	"log"
)


func New(redisURL string) Cache {
	if redisURL == "" {
		log.Println("[CACHE] Using in-memory cache (no Redis URL configured)")
		return NewMemoryCache()
	}

	rc, err := NewRedisCache(redisURL)
	if err != nil {
		log.Printf("[CACHE] Redis unavailable (%v), falling back to memory cache", err)
		return NewMemoryCache()
	}

	log.Printf("[CACHE] Connected to Redis at %s", redisURL)
	return rc
}

var globalCache Cache


func SetGlobal(c Cache) {
	globalCache = c
}
func Global() Cache {
	if globalCache == nil {
		globalCache = NewMemoryCache()
	}
	return globalCache
}
