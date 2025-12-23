package api

import (
	"sync"
	"time"
)

// SessionTracker - трекер активных сессий (интеграция с сервером)
type SessionTracker struct {
	sessions map[uint32]*ServerSession
	mu       sync.RWMutex
}

// ServerSession - активная сессия на сервере
type ServerSession struct {
	SessionID    uint32       `json:"session_id"`
	UserID       string       `json:"user_id,omitempty"`
	Token        string       `json:"token,omitempty"`
	RemoteAddr   string       `json:"remote_addr"`
	Protocol     string       `json:"protocol"` // "udp", "tcp", "ws", "ws2"
	StartTime    time.Time    `json:"start_time"`
	LastActivity time.Time    `json:"last_activity"`
	Upload       int64        `json:"upload"`
	Download     int64        `json:"download"`
	PacketsTx    int64        `json:"packets_tx"`
	PacketsRx    int64        `json:"packets_rx"`
	State        string       `json:"state"` // "handshake", "connected", "disconnected"
}

// NewSessionTracker создает новый трекер сессий
func NewSessionTracker() *SessionTracker {
	return &SessionTracker{
		sessions: make(map[uint32]*ServerSession),
	}
}

// RegisterSession регистрирует новую сессию
func (st *SessionTracker) RegisterSession(sessionID uint32, remoteAddr, protocol, token string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	
	now := time.Now()
	st.sessions[sessionID] = &ServerSession{
		SessionID:    sessionID,
		Token:        token,
		RemoteAddr:   remoteAddr,
		Protocol:     protocol,
		StartTime:    now,
		LastActivity: now,
		State:        "handshake",
	}
}

// UpdateSession обновляет информацию о сессии
func (st *SessionTracker) UpdateSession(sessionID uint32, upload, download int64, packetsTx, packetsRx int64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	
	if session, exists := st.sessions[sessionID]; exists {
		session.Upload += upload
		session.Download += download
		session.PacketsTx += packetsTx
		session.PacketsRx += packetsRx
		session.LastActivity = time.Now()
		if session.State == "handshake" {
			session.State = "connected"
		}
	}
}

// RemoveSession удаляет сессию
func (st *SessionTracker) RemoveSession(sessionID uint32) {
	st.mu.Lock()
	defer st.mu.Unlock()
	
	delete(st.sessions, sessionID)
}

// GetSession возвращает информацию о сессии
func (st *SessionTracker) GetSession(sessionID uint32) *ServerSession {
	st.mu.RLock()
	defer st.mu.RUnlock()
	
	return st.sessions[sessionID]
}

// GetAllSessions возвращает все активные сессии
func (st *SessionTracker) GetAllSessions() []*ServerSession {
	st.mu.RLock()
	defer st.mu.RUnlock()
	
	sessions := make([]*ServerSession, 0, len(st.sessions))
	for _, session := range st.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// GetSessionsByUser возвращает сессии пользователя
func (st *SessionTracker) GetSessionsByUser(userID string) []*ServerSession {
	st.mu.RLock()
	defer st.mu.RUnlock()
	
	sessions := make([]*ServerSession, 0)
	for _, session := range st.sessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// CleanupInactiveSessions удаляет неактивные сессии
func (st *SessionTracker) CleanupInactiveSessions(timeout time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()
	
	now := time.Now()
	for sessionID, session := range st.sessions {
		if now.Sub(session.LastActivity) > timeout {
			delete(st.sessions, sessionID)
		}
	}
}

