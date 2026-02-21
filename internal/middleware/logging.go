package middleware

import (
	"context"
	"time"

	"whispera/core/router"
	"whispera/internal/logger"
)

type ServerLoggingMiddleware struct {
	log *logger.Logger
}

func NewServerLoggingMiddleware() *ServerLoggingMiddleware {
	return &ServerLoggingMiddleware{
		log: logger.Module("server"),
	}
}

func (m *ServerLoggingMiddleware) Process(ctx context.Context, req *router.Request, next router.Handler) (*router.Response, error) {
	start := time.Now()

	m.log.Debug("REQ ID=%s Type=%s Addr=%s Session=%s",
		req.ID, req.Type, req.RemoteAddr, req.SessionID)

	resp, err := next.Handle(ctx, req)

	duration := time.Since(start)

	if err != nil {
		m.log.Error("ERR ID=%s Duration=%v Error=%v",
			req.ID, duration, err)
	} else {
		m.log.Info("RES ID=%s Duration=%v Status=%d",
			req.ID, duration, resp.StatusCode)
	}

	return resp, err
}

func (m *ServerLoggingMiddleware) Name() string {
	return "server_logging"
}
func (m *ServerLoggingMiddleware) Priority() int {
	return 50
}
