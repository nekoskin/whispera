package cache

import (
	"context"
	"testing"
	"time"
)

func TestLRUCacheEviction(t *testing.T) {
	c := NewLRUCache[int](2)
	ctx := context.Background()

	_ = c.Set(ctx, "a", 1, 0)
	_ = c.Set(ctx, "b", 2, 0)
	_ = c.Set(ctx, "c", 3, 0)

	if c.Len() != 2 {
		t.Fatalf("expected len 2, got %d", c.Len())
	}
	if v, _ := c.Get(ctx, "a"); v != 0 {
		t.Fatalf("expected 'a' evicted, got %d", v)
	}
	if v, _ := c.Get(ctx, "c"); v != 3 {
		t.Fatalf("expected 'c' present, got %d", v)
	}
}

func TestLRUCacheTTLExpiry(t *testing.T) {
	c := NewLRUCache[string](10)
	ctx := context.Background()

	_ = c.Set(ctx, "a", "1", 10*time.Millisecond)
	if !c.Exists(ctx, "a") {
		t.Fatalf("expected key to exist before TTL")
	}
	time.Sleep(30 * time.Millisecond)
	if c.Exists(ctx, "a") {
		t.Fatalf("expected key to expire after TTL")
	}
}
