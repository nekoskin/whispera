package middleware

import (
	"context"
	"fmt"
	"sync"

	"whispera/core/router"
)

// RateLimiter определяет интерфейс для ограничителя
type RateLimiter interface {
	Allow(key string) bool
}

// SimpleRateLimiter простая реализация (заглушка)
type SimpleRateLimiter struct {
	mu    sync.Mutex
	rates map[string]int
}

func (l *SimpleRateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Реальная логика токен-бакета должна быть здесь
	return true
}

// RateLimitMiddleware ограничивает частоту запросов
type RateLimitMiddleware struct {
	limiter RateLimiter
}

// NewRateLimitMiddleware создает новый RateLimitMiddleware
func NewRateLimitMiddleware(limiter RateLimiter) *RateLimitMiddleware {
	return &RateLimitMiddleware{limiter: limiter}
}

// Process реализует интерфейс Middleware
func (m *RateLimitMiddleware) Process(ctx context.Context, req *router.Request, next router.Handler) (*router.Response, error) {
	// Ключ для лимита - IP адрес
	key := req.RemoteAddr.String()

	if !m.limiter.Allow(key) {
		return &router.Response{
			StatusCode: 429,
			Error:      fmt.Errorf("too many requests"),
		}, nil
	}

	return next.Handle(ctx, req)
}

// Name возвращает имя middleware
func (m *RateLimitMiddleware) Name() string {
	return "ratelimit"
}

// Priority возвращает приоритет
func (m *RateLimitMiddleware) Priority() int {
	return 15 // Высокий, до тяжелой обработки
}
