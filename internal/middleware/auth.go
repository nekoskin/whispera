package middleware

import (
	"context"
	"fmt"

	"whispera/core/router"
	"whispera/core/session"
)

// AuthMiddleware проверяет валидность сессии
type AuthMiddleware struct {
	sessionMgr session.SessionManager
}

// NewAuthMiddleware создает новый AuthMiddleware
func NewAuthMiddleware(sm session.SessionManager) *AuthMiddleware {
	return &AuthMiddleware{sessionMgr: sm}
}

// Process реализует интерфейс Middleware
func (m *AuthMiddleware) Process(ctx context.Context, req *router.Request, next router.Handler) (*router.Response, error) {
	// Если это Handshake, пропускаем проверку (или проверяем специфично)
	if req.Type == router.RequestTypeHandshake {
		return next.Handle(ctx, req)
	}

	// Для Data и Control требуем валидную сессию
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

	// Можно добавить UserID в контекст, если нужно
	// ctx = context.WithValue(ctx, "user_id", sess.UserID())

	return next.Handle(ctx, req)
}

// Name возвращает имя middleware
func (m *AuthMiddleware) Name() string {
	return "auth"
}

// Priority возвращает приоритет
func (m *AuthMiddleware) Priority() int {
	return 20 // Высокий, после Recovery и Timeout, но перед Logging
}
