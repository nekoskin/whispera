package session

import (
	"context"
	"net"
	"time"
)

// SessionManager defines the interface for managing sessions
type SessionManager interface {
	// CreateSession creates a new session
	CreateSession(ctx context.Context, userID string, metadata map[string]interface{}) (Session, error)

	// GetSession retrieves a session by ID
	GetSession(id string) (Session, bool)

	// RemoveSession removes a session
	RemoveSession(id string) error

	// ListSessions returns all active sessions
	ListSessions() []Session

	// PruneSessions removes expired sessions
	PruneSessions(maxAge time.Duration) int

	// Count returns the number of active sessions
	Count() int
}

// Session represents a user session
type Session interface {
	// ID returns the session ID
	ID() string

	// UserID returns the user ID associated with the session
	UserID() string

	// CreatedAt returns when the session was created
	CreatedAt() time.Time

	// LastActivity returns when the session was last active
	LastActivity() time.Time

	// UpdateActivity updates the last activity time
	UpdateActivity()

	// Metadata returns session metadata
	Metadata() map[string]interface{}

	// SetMetadata sets session metadata
	SetMetadata(key string, value interface{})

	// State returns the current session state
	State() SessionState

	// SetState updates the session state
	SetState(state SessionState)

	// Close closes the session
	Close() error
}

// SessionState represents the state of a session
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

// SessionStore defines storage for sessions
type SessionStore interface {
	// Save saves a session
	Save(session Session) error

	// Load loads a session by ID
	Load(id string) (Session, error)

	// Delete deletes a session
	Delete(id string) error

	// List returns all sessions
	List() ([]Session, error)
}

// SessionLifecycleListener defines callbacks for session events
type SessionLifecycleListener interface {
	// OnSessionCreated called when a session is created
	OnSessionCreated(session Session)

	// OnSessionClosed called when a session is closed
	OnSessionClosed(session Session)

	// OnSessionStateChanged called when a session state changes
	OnSessionStateChanged(session Session, oldState, newState SessionState)
}

// ContextKey is a key for context values
type ContextKey string

const (
	// SessionContextKey is the key for the session in the context
	SessionContextKey ContextKey = "session"
)

// FromContext extracts the session from the context
func FromContext(ctx context.Context) (Session, bool) {
	val := ctx.Value(SessionContextKey)
	if session, ok := val.(Session); ok {
		return session, true
	}
	return nil, false
}

// NewContext returns a new context with the session
func NewContext(ctx context.Context, session Session) context.Context {
	return context.WithValue(ctx, SessionContextKey, session)
}

// SessionConfig defines configuration for sessions
type SessionConfig struct {
	Timeout       time.Duration
	MaxSessions   int
	CleanupTick   time.Duration
	StorageDriver string // "memory", "redis", etc.
}

// ConnectionInfo contains information about the underlying connection
type ConnectionInfo struct {
	RemoteAddr net.Addr
	LocalAddr  net.Addr
	Transport  string // "udp", "tcp", "ws", "quic", etc.
	Protocol   string // "whispera", "vless", "trojan", etc.
}
