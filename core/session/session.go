package session

import (
	"context"
	"net"
	"time"
)


type SessionManager interface {
	
	CreateSession(ctx context.Context, userID string, metadata map[string]interface{}) (Session, error)

	
	GetSession(id string) (Session, bool)

	
	RemoveSession(id string) error

	
	ListSessions() []Session

	
	PruneSessions(maxAge time.Duration) int

	
	Count() int
}


type Session interface {
	
	ID() string

	
	UserID() string

	
	CreatedAt() time.Time

	
	LastActivity() time.Time

	
	UpdateActivity()

	
	Metadata() map[string]interface{}

	// SetMetadata sets session metadata
	SetMetadata(key string, value interface{})

	State() SessionState

	
	SetState(state SessionState)

	
	Close() error
}


type SessionState int

const (
	SessionStateNew SessionState = iota
	SessionStateHandshaking
	SessionStateActive
	SessionStateIdle
	SessionStateClosing
	SessionStateClosed
)

var stateNames = map[SessionState]string{
	SessionStateNew:         "new",
	SessionStateHandshaking: "handshaking",
	SessionStateActive:      "active",
	SessionStateIdle:        "idle",
	SessionStateClosing:     "closing",
	SessionStateClosed:      "closed",
}

func (s SessionState) String() string {
	if name, ok := stateNames[s]; ok {
		return name
	}
	return "unknown"
}


type SessionStore interface {
	
	Save(session Session) error

	
	Load(id string) (Session, error)

	
	Delete(id string) error

	
	List() ([]Session, error)
}


type SessionLifecycleListener interface {
	
	OnSessionCreated(session Session)

	
	OnSessionClosed(session Session)

	
	OnSessionStateChanged(session Session, oldState, newState SessionState)
}


type ContextKey string

const (
	
	SessionContextKey ContextKey = "session"
)


func FromContext(ctx context.Context) (Session, bool) {
	val := ctx.Value(SessionContextKey)
	if session, ok := val.(Session); ok {
		return session, true
	}
	return nil, false
}


func NewContext(ctx context.Context, session Session) context.Context {
	return context.WithValue(ctx, SessionContextKey, session)
}


type SessionConfig struct {
	Timeout       time.Duration
	MaxSessions   int
	CleanupTick   time.Duration
	StorageDriver string 
}


type ConnectionInfo struct {
	RemoteAddr net.Addr
	LocalAddr  net.Addr
	Transport  string 
	Protocol   string 
}
