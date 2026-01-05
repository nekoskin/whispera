package middleware

import (
	"context"
	"log"
	"time"

	"whispera/core/router"
)

// ServerLoggingMiddleware реализует глобальное логирование
type ServerLoggingMiddleware struct{}

// NewServerLoggingMiddleware создает новый ServerLoggingMiddleware
func NewServerLoggingMiddleware() *ServerLoggingMiddleware {
	return &ServerLoggingMiddleware{}
}

// Process реализует интерфейс Middleware
func (m *ServerLoggingMiddleware) Process(ctx context.Context, req *router.Request, next router.Handler) (*router.Response, error) {
	start := time.Now()

	log.Printf("[SERVER] REQ ID=%s Type=%s Addr=%s Session=%s",
		req.ID, req.Type, req.RemoteAddr, req.SessionID)

	resp, err := next.Handle(ctx, req)

	duration := time.Since(start)

	if err != nil {
		log.Printf("[SERVER] ERR ID=%s Duration=%v Error=%v",
			req.ID, duration, err)
	} else {
		log.Printf("[SERVER] RES ID=%s Duration=%v Status=%d",
			req.ID, duration, resp.StatusCode)
	}

	return resp, err
}

// Name возвращает имя middleware
func (m *ServerLoggingMiddleware) Name() string {
	return "server_logging"
}

// Priority возвращает приоритет
func (m *ServerLoggingMiddleware) Priority() int {
	return 50 // Средний приоритет
}
