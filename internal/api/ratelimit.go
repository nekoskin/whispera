package api

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiter - простой rate limiter для защиты от DDoS
type RateLimiter struct {
	mu          sync.RWMutex
	requests    map[string][]time.Time
	maxRequests int
	window      time.Duration
	cleanup     *time.Ticker
	maxIPs      int      // Лимит на количество отслеживаемых IP для предотвращения утечки памяти
	stopChan    chan struct{} // Канал для остановки cleanup loop
}

// NewRateLimiter создает новый rate limiter
func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests:    make(map[string][]time.Time),
		maxRequests: maxRequests,
		window:      window,
		cleanup:     time.NewTicker(1 * time.Minute),
		maxIPs:      10000, // Максимум 10k IP адресов для предотвращения утечки памяти
		stopChan:    make(chan struct{}),
	}

	// Запускаем очистку старых записей
	go rl.cleanupLoop()

	return rl
}

// Stop останавливает rate limiter и очищает ресурсы
func (rl *RateLimiter) Stop() {
	close(rl.stopChan)
	if rl.cleanup != nil {
		rl.cleanup.Stop()
	}
}

// cleanupLoop периодически очищает старые записи
func (rl *RateLimiter) cleanupLoop() {
	for {
		select {
		case <-rl.stopChan:
			return
		case <-rl.cleanup.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, times := range rl.requests {
				// Удаляем записи старше window
				valid := make([]time.Time, 0)
				for _, t := range times {
					if now.Sub(t) < rl.window {
						valid = append(valid, t)
					}
				}
				if len(valid) == 0 {
					delete(rl.requests, ip)
				} else {
					rl.requests[ip] = valid
				}
			}
			rl.mu.Unlock()
		}
	}
}

// Allow проверяет, разрешен ли запрос для данного IP
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Защита от утечки памяти: если достигнут лимит IP, удаляем самый старый
	if len(rl.requests) >= rl.maxIPs {
		// Находим IP с самыми старыми записями и удаляем его
		var oldestIP string
		var oldestTime time.Time
		first := true
		for k, v := range rl.requests {
			if len(v) == 0 {
				oldestIP = k
				break
			}
			ipOldest := v[0]
			for _, t := range v {
				if t.Before(ipOldest) {
					ipOldest = t
				}
			}
			if first || ipOldest.Before(oldestTime) {
				oldestIP = k
				oldestTime = ipOldest
				first = false
			}
		}
		if oldestIP != "" {
			delete(rl.requests, oldestIP)
		}
	}

	times := rl.requests[ip]

	// Удаляем записи старше window
	valid := make([]time.Time, 0)
	for _, t := range times {
		if now.Sub(t) < rl.window {
			valid = append(valid, t)
		}
	}

	// Проверяем лимит
	if len(valid) >= rl.maxRequests {
		return false
	}

	// Добавляем текущий запрос
	valid = append(valid, now)
	rl.requests[ip] = valid

	return true
}

// RateLimitMiddleware - middleware для rate limiting
func RateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Получаем IP адрес
			ip := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				ip = forwarded
			}

			// Проверяем rate limit
			if !rl.Allow(ip) {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
