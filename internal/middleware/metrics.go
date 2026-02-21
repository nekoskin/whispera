package middleware

import (
	"context"
	"time"

	"whispera/core/router"
)

type MetricsCollector interface {
	RecordRequestDuration(reqType string, status int, duration time.Duration)
	RecordRequestCount(reqType string, status int)
}

type ServerMetricsMiddleware struct {
	collector MetricsCollector
}

func NewServerMetricsMiddleware(collector MetricsCollector) *ServerMetricsMiddleware {
	return &ServerMetricsMiddleware{collector: collector}
}

func (m *ServerMetricsMiddleware) Process(ctx context.Context, req *router.Request, next router.Handler) (*router.Response, error) {
	start := time.Now()

	resp, err := next.Handle(ctx, req)

	duration := time.Since(start)
	status := 500
	if resp != nil {
		status = resp.StatusCode
	}
	if err != nil {
	}

	if m.collector != nil {
		m.collector.RecordRequestCount(req.Type.String(), status)
		m.collector.RecordRequestDuration(req.Type.String(), status, duration)
	}

	return resp, err
}

func (m *ServerMetricsMiddleware) Name() string {
	return "server_metrics"
}
func (m *ServerMetricsMiddleware) Priority() int {
	return 40
}
