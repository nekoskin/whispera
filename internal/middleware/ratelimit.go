package middleware

import (
	"context"
	"fmt"
	"sync"

	"whispera/core/router"
)

type RateLimiter interface {
	Allow(key string) bool
}
type SimpleRateLimiter struct {
	mu    sync.Mutex
	rates map[string]int
}

func (l *SimpleRateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return true
}

type RateLimitMiddleware struct {
	limiter RateLimiter
}

func NewRateLimitMiddleware(limiter RateLimiter) *RateLimitMiddleware {
	return &RateLimitMiddleware{limiter: limiter}
}

func (m *RateLimitMiddleware) Process(ctx context.Context, req *router.Request, next router.Handler) (*router.Response, error) {
	key := req.RemoteAddr.String()

	if !m.limiter.Allow(key) {
		return &router.Response{
			StatusCode: 429,
			Error:      fmt.Errorf("too many requests"),
		}, nil
	}

	return next.Handle(ctx, req)
}

func (m *RateLimitMiddleware) Name() string {
	return "ratelimit"
}
func (m *RateLimitMiddleware) Priority() int {
	return 15
}
