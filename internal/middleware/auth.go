package middleware

import (
	"context"
	"fmt"

	"whispera/core/router"
	"whispera/core/session"
)

type AuthMiddleware struct {
	sessionMgr session.SessionManager
}

func NewAuthMiddleware(sm session.SessionManager) *AuthMiddleware {
	return &AuthMiddleware{sessionMgr: sm}
}

func (m *AuthMiddleware) Process(ctx context.Context, req *router.Request, next router.Handler) (*router.Response, error) {
	if req.Type == router.RequestTypeHandshake {
		return next.Handle(ctx, req)
	}

	if req.SessionID == "" {
		return &router.Response{
			StatusCode: 401,
			Error:      fmt.Errorf("unauthorized: missing session id"),
		}, nil
	}

	sess, ok := m.sessionMgr.GetSession(req.SessionID)
	if !ok || sess.State() == session.SessionStateClosed {
		return &router.Response{
			StatusCode: 401,
			Error:      fmt.Errorf("unauthorized: invalid or closed session"),
		}, nil
	}

	return next.Handle(ctx, req)
}

func (m *AuthMiddleware) Name() string {
	return "auth"
}

func (m *AuthMiddleware) Priority() int {
	return 20
}
