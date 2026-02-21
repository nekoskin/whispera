
package session

import (
	"sync"
	"sync/atomic"
)


type SessionCtx struct {
	mu        sync.RWMutex
	SessionID uint32
	seq       uint32
	Keys      *SessionKeys
	Active    bool
}


type SessionKeys struct {
	SendKey []byte
	RecvKey []byte
	Seed    []byte
}


func NewSessionCtx(sessionID uint32) *SessionCtx {
	return &SessionCtx{
		SessionID: sessionID,
		Active:    true,
	}
}


func (s *SessionCtx) NextSeq() uint32 {
	return atomic.AddUint32(&s.seq, 1)
}
func (s *SessionCtx) GetSeq() uint32 {
	return atomic.LoadUint32(&s.seq)
}


func (s *SessionCtx) SetKeys(keys *SessionKeys) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Keys = keys
}


func (s *SessionCtx) GetKeys() *SessionKeys {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Keys
}


func (s *SessionCtx) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Active = false
}


func (s *SessionCtx) IsActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Active
}
