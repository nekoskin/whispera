// Package session provides client session context
package session

import (
	"sync"
	"sync/atomic"
)

// SessionCtx represents a client session context
type SessionCtx struct {
	mu        sync.RWMutex
	SessionID uint32
	seq       uint32
	Keys      *SessionKeys
	Active    bool
}

// SessionKeys holds session encryption keys
type SessionKeys struct {
	SendKey []byte
	RecvKey []byte
	Seed    []byte
}

// NewSessionCtx creates a new session context
func NewSessionCtx(sessionID uint32) *SessionCtx {
	return &SessionCtx{
		SessionID: sessionID,
		Active:    true,
	}
}

// NextSeq returns the next sequence number
func (s *SessionCtx) NextSeq() uint32 {
	return atomic.AddUint32(&s.seq, 1)
}

// GetSeq returns the current sequence number
func (s *SessionCtx) GetSeq() uint32 {
	return atomic.LoadUint32(&s.seq)
}

// SetKeys sets the session keys
func (s *SessionCtx) SetKeys(keys *SessionKeys) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Keys = keys
}

// GetKeys returns the session keys
func (s *SessionCtx) GetKeys() *SessionKeys {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Keys
}

// Close closes the session
func (s *SessionCtx) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Active = false
}

// IsActive returns whether the session is active
func (s *SessionCtx) IsActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Active
}
