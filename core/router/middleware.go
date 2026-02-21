package router

import (
	"context"
	"fmt"
	"time"
)


type Middleware interface {
	
	Process(ctx context.Context, req *Request, next Handler) (*Response, error)

	
	Name() string

	
	Priority() int
}


type MiddlewareFunc struct {
	name     string
	priority int
	fn       func(ctx context.Context, req *Request, next Handler) (*Response, error)
}


func NewMiddlewareFunc(name string, priority int, fn func(ctx context.Context, req *Request, next Handler) (*Response, error)) Middleware {
	return &MiddlewareFunc{
		name:     name,
		priority: priority,
		fn:       fn,
	}
}


func (m *MiddlewareFunc) Process(ctx context.Context, req *Request, next Handler) (*Response, error) {
	return m.fn(ctx, req, next)
}


func (m *MiddlewareFunc) Name() string {
	return m.name
}


func (m *MiddlewareFunc) Priority() int {
	return m.priority
}


type MiddlewareChain struct {
	middlewares []Middleware
	handler     Handler
}


func NewMiddlewareChain(handler Handler, middlewares ...Middleware) *MiddlewareChain {
	return &MiddlewareChain{
		middlewares: middlewares,
		handler:     handler,
	}
}


func (mc *MiddlewareChain) Handle(ctx context.Context, req *Request) (*Response, error) {
	if len(mc.middlewares) == 0 {
		return mc.handler.Handle(ctx, req)
	}

	
	var next Handler
	next = HandlerFunc(func(ctx context.Context, req *Request) (*Response, error) {
		return mc.handler.Handle(ctx, req)
	})

	
	for i := len(mc.middlewares) - 1; i >= 0; i-- {
		middleware := mc.middlewares[i]
		currentNext := next
		next = HandlerFunc(func(ctx context.Context, req *Request) (*Response, error) {
			return middleware.Process(ctx, req, currentNext)
		})
	}

	return next.Handle(ctx, req)
}


func (mc *MiddlewareChain) Use(middleware ...Middleware) {
	mc.middlewares = append(mc.middlewares, middleware...)
}


type LoggingMiddleware struct {
	logger Logger
}
type Logger interface {
	Info(msg string, fields map[string]interface{})
	Error(msg string, err error, fields map[string]interface{})
}
func NewLoggingMiddleware(logger Logger) Middleware {
	return &LoggingMiddleware{logger: logger}
}


func (m *LoggingMiddleware) Process(ctx context.Context, req *Request, next Handler) (*Response, error) {
	start := time.Now()

	m.logger.Info("incoming request", map[string]interface{}{
		"request_id":   req.ID,
		"request_type": req.Type.String(),
		"remote_addr":  req.RemoteAddr.String(),
		"session_id":   req.SessionID,
	})

	resp, err := next.Handle(ctx, req)

	duration := time.Since(start)

	if err != nil {
		m.logger.Error("request failed", err, map[string]interface{}{
			"request_id": req.ID,
			"duration":   duration.String(),
		})
	} else {
		m.logger.Info("request completed", map[string]interface{}{
			"request_id":  req.ID,
			"duration":    duration.String(),
			"status_code": resp.StatusCode,
		})
	}

	return resp, err
}


func (m *LoggingMiddleware) Name() string {
	return "logging"
}


func (m *LoggingMiddleware) Priority() int {
	return 100 
}


type RecoveryMiddleware struct{}
func NewRecoveryMiddleware() Middleware {
	return &RecoveryMiddleware{}
}


func (m *RecoveryMiddleware) Process(ctx context.Context, req *Request, next Handler) (resp *Response, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic recovered: %v", r)
			resp = &Response{
				Error:      err,
				StatusCode: 500,
			}
		}
	}()

	return next.Handle(ctx, req)
}


func (m *RecoveryMiddleware) Name() string {
	return "recovery"
}
func (m *RecoveryMiddleware) Priority() int {
	return 0 
}


type MetricsMiddleware struct {
	collector MetricsCollector
}


type MetricsCollector interface {
	RecordRequest(requestType string, duration time.Duration, success bool)
	RecordError(requestType string, errType string)
}

func NewMetricsMiddleware(collector MetricsCollector) Middleware {
	return &MetricsMiddleware{collector: collector}
}


func (m *MetricsMiddleware) Process(ctx context.Context, req *Request, next Handler) (*Response, error) {
	start := time.Now()

	resp, err := next.Handle(ctx, req)

	duration := time.Since(start)
	success := err == nil && (resp == nil || resp.Error == nil)

	m.collector.RecordRequest(req.Type.String(), duration, success)

	if err != nil {
		m.collector.RecordError(req.Type.String(), "handler_error")
	} else if resp != nil && resp.Error != nil {
		m.collector.RecordError(req.Type.String(), "response_error")
	}

	return resp, err
}


func (m *MetricsMiddleware) Name() string {
	return "metrics"
}
func (m *MetricsMiddleware) Priority() int {
	return 90 
}
type TimeoutMiddleware struct {
	timeout time.Duration
}
func NewTimeoutMiddleware(timeout time.Duration) Middleware {
	return &TimeoutMiddleware{timeout: timeout}
}


func (m *TimeoutMiddleware) Process(ctx context.Context, req *Request, next Handler) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	type result struct {
		resp *Response
		err  error
	}

	resultChan := make(chan result, 1)

	go func() {
		resp, err := next.Handle(ctx, req)
		resultChan <- result{resp: resp, err: err}
	}()

	select {
	case res := <-resultChan:
		return res.resp, res.err
	case <-ctx.Done():
		return &Response{
			Error:      fmt.Errorf("request timeout after %v", m.timeout),
			StatusCode: 408,
		}, ctx.Err()
	}
}


func (m *TimeoutMiddleware) Name() string {
	return "timeout"
}
func (m *TimeoutMiddleware) Priority() int {
	return 10 
}
