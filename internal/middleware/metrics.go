package middleware

import (
	"context"
	"time"

	"whispera/core/router"
)

// MetricsCollector определяет интерфейс для записи метрик
type MetricsCollector interface {
	RecordRequestDuration(reqType string, status int, duration time.Duration)
	RecordRequestCount(reqType string, status int)
}

// ServerMetricsMiddleware собирает метрики сервера
type ServerMetricsMiddleware struct {
	collector MetricsCollector
}

// NewServerMetricsMiddleware создает новый ServerMetricsMiddleware
func NewServerMetricsMiddleware(collector MetricsCollector) *ServerMetricsMiddleware {
	return &ServerMetricsMiddleware{collector: collector}
}

// Process реализует интерфейс Middleware
func (m *ServerMetricsMiddleware) Process(ctx context.Context, req *router.Request, next router.Handler) (*router.Response, error) {
	start := time.Now()

	resp, err := next.Handle(ctx, req)

	duration := time.Since(start)
	status := 500
	if resp != nil {
		status = resp.StatusCode
	}
	if err != nil {
		// Log error type if needed, but status covers most
	}

	if m.collector != nil {
		m.collector.RecordRequestCount(req.Type.String(), status)
		m.collector.RecordRequestDuration(req.Type.String(), status, duration)
	}

	return resp, err
}

// Name возвращает имя middleware
func (m *ServerMetricsMiddleware) Name() string {
	return "server_metrics"
}

// Priority возвращает приоритет
func (m *ServerMetricsMiddleware) Priority() int {
	return 40 // До логирования
}
