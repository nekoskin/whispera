package router

import (
	"context"
	"fmt"
	"time"
)

// Middleware определяет интерфейс для обработки запросов в цепочке
type Middleware interface {
	// Process обрабатывает запрос и вызывает следующий обработчик
	Process(ctx context.Context, req *Request, next Handler) (*Response, error)

	// Name возвращает имя middleware
	Name() string

	// Priority возвращает приоритет (меньше = раньше в цепочке)
	Priority() int
}

// MiddlewareFunc адаптер функции к интерфейсу Middleware
type MiddlewareFunc struct {
	name     string
	priority int
	fn       func(ctx context.Context, req *Request, next Handler) (*Response, error)
}

// NewMiddlewareFunc создает новый MiddlewareFunc
func NewMiddlewareFunc(name string, priority int, fn func(ctx context.Context, req *Request, next Handler) (*Response, error)) Middleware {
	return &MiddlewareFunc{
		name:     name,
		priority: priority,
		fn:       fn,
	}
}

// Process реализует интерфейс Middleware
func (m *MiddlewareFunc) Process(ctx context.Context, req *Request, next Handler) (*Response, error) {
	return m.fn(ctx, req, next)
}

// Name возвращает имя middleware
func (m *MiddlewareFunc) Name() string {
	return m.name
}

// Priority возвращает приоритет
func (m *MiddlewareFunc) Priority() int {
	return m.priority
}

// MiddlewareChain представляет цепочку middleware
type MiddlewareChain struct {
	middlewares []Middleware
	handler     Handler
}

// NewMiddlewareChain создает новую цепочку middleware
func NewMiddlewareChain(handler Handler, middlewares ...Middleware) *MiddlewareChain {
	return &MiddlewareChain{
		middlewares: middlewares,
		handler:     handler,
	}
}

// Handle выполняет цепочку middleware и конечный обработчик
func (mc *MiddlewareChain) Handle(ctx context.Context, req *Request) (*Response, error) {
	if len(mc.middlewares) == 0 {
		return mc.handler.Handle(ctx, req)
	}

	// Создаем рекурсивную цепочку
	var next Handler
	next = HandlerFunc(func(ctx context.Context, req *Request) (*Response, error) {
		return mc.handler.Handle(ctx, req)
	})

	// Применяем middleware в обратном порядке
	for i := len(mc.middlewares) - 1; i >= 0; i-- {
		middleware := mc.middlewares[i]
		currentNext := next
		next = HandlerFunc(func(ctx context.Context, req *Request) (*Response, error) {
			return middleware.Process(ctx, req, currentNext)
		})
	}

	return next.Handle(ctx, req)
}

// Use добавляет middleware в цепочку
func (mc *MiddlewareChain) Use(middleware ...Middleware) {
	mc.middlewares = append(mc.middlewares, middleware...)
}

// --- Базовые Middleware ---

// LoggingMiddleware логирует запросы и ответы
type LoggingMiddleware struct {
	logger Logger
}

// Logger интерфейс для логирования
type Logger interface {
	Info(msg string, fields map[string]interface{})
	Error(msg string, err error, fields map[string]interface{})
}

// NewLoggingMiddleware создает новый LoggingMiddleware
func NewLoggingMiddleware(logger Logger) Middleware {
	return &LoggingMiddleware{logger: logger}
}

// Process реализует интерфейс Middleware
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

// Name возвращает имя middleware
func (m *LoggingMiddleware) Name() string {
	return "logging"
}

// Priority возвращает приоритет
func (m *LoggingMiddleware) Priority() int {
	return 100 // Высокий приоритет, выполняется рано
}

// RecoveryMiddleware восстанавливается после паники
type RecoveryMiddleware struct{}

// NewRecoveryMiddleware создает новый RecoveryMiddleware
func NewRecoveryMiddleware() Middleware {
	return &RecoveryMiddleware{}
}

// Process реализует интерфейс Middleware
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

// Name возвращает имя middleware
func (m *RecoveryMiddleware) Name() string {
	return "recovery"
}

// Priority возвращает приоритет
func (m *RecoveryMiddleware) Priority() int {
	return 0 // Самый высокий приоритет, выполняется первым
}

// MetricsMiddleware собирает метрики
type MetricsMiddleware struct {
	collector MetricsCollector
}

// MetricsCollector интерфейс для сбора метрик
type MetricsCollector interface {
	RecordRequest(requestType string, duration time.Duration, success bool)
	RecordError(requestType string, errType string)
}

// NewMetricsMiddleware создает новый MetricsMiddleware
func NewMetricsMiddleware(collector MetricsCollector) Middleware {
	return &MetricsMiddleware{collector: collector}
}

// Process реализует интерфейс Middleware
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

// Name возвращает имя middleware
func (m *MetricsMiddleware) Name() string {
	return "metrics"
}

// Priority возвращает приоритет
func (m *MetricsMiddleware) Priority() int {
	return 90 // Высокий приоритет
}

// TimeoutMiddleware добавляет timeout к обработке запроса
type TimeoutMiddleware struct {
	timeout time.Duration
}

// NewTimeoutMiddleware создает новый TimeoutMiddleware
func NewTimeoutMiddleware(timeout time.Duration) Middleware {
	return &TimeoutMiddleware{timeout: timeout}
}

// Process реализует интерфейс Middleware
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

// Name возвращает имя middleware
func (m *TimeoutMiddleware) Name() string {
	return "timeout"
}

// Priority возвращает приоритет
func (m *TimeoutMiddleware) Priority() int {
	return 10 // Очень высокий приоритет
}
