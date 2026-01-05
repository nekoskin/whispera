// Package session provides the session manager module
package session

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

const (
	ModuleName    = "session.manager"
	ModuleVersion = "1.0.0"
)

// Config holds session manager configuration
type Config struct {
	MaxSessions     int
	SessionTimeout  time.Duration
	CleanupInterval time.Duration
	EnableMetrics   bool
}

// DefaultConfig returns default session manager configuration
func DefaultConfig() *Config {
	return &Config{
		MaxSessions:     10000,
		SessionTimeout:  30 * time.Minute,
		CleanupInterval: 1 * time.Minute,
		EnableMetrics:   true,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.MaxSessions <= 0 {
		c.MaxSessions = 10000
	}
	if c.SessionTimeout <= 0 {
		c.SessionTimeout = 30 * time.Minute
	}
	if c.CleanupInterval <= 0 {
		c.CleanupInterval = 1 * time.Minute
	}
	return nil
}

// Manager implements interfaces.SessionManager
type Manager struct {
	*base.Module
	config *Config

	mu       sync.RWMutex
	sessions map[uint32]*Session
	byAddr   map[string]uint32 // addr.String() -> sessionID

	// Event channels for subscribers
	eventChans   []chan interfaces.SessionEvent
	eventChansMu sync.RWMutex

	// Stats
	totalCreated uint64
	totalRemoved uint64

	// Cleanup
	cleanupStop chan struct{}
}

// Session represents a client session
type Session struct {
	mu           sync.RWMutex
	id           uint32
	clientAddr   net.Addr
	createdAt    time.Time
	lastActivity time.Time
	metadata     map[string]interface{}
	closed       bool

	// Crypto state (placeholder - would integrate with crypto module)
	seed    []byte
	sendKey []byte
	recvKey []byte

	// Streams
	streams   map[uint16]*Stream
	streamsMu sync.RWMutex

	// Sequence numbers
	seqSend uint32
	seqRecv uint32

	// Callbacks
	onClose func(id uint32)
}

// Stream represents a multiplexed stream
type Stream struct {
	id        uint16
	state     StreamState
	buffer    []byte
	closed    bool
	createdAt time.Time
	mu        sync.RWMutex
}

// StreamState represents stream state
type StreamState int

const (
	StreamStateOpen StreamState = iota
	StreamStateHalfClosed
	StreamStateClosed
)

// New creates a new session manager
func New(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	m := &Manager{
		Module:      base.NewModule(ModuleName, ModuleVersion, nil),
		config:      cfg,
		sessions:    make(map[uint32]*Session),
		byAddr:      make(map[string]uint32),
		eventChans:  make([]chan interfaces.SessionEvent, 0),
		cleanupStop: make(chan struct{}),
	}

	return m, nil
}

// Init initializes the session manager
func (m *Manager) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := m.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if sessCfg, ok := cfg.(*Config); ok {
		m.config = sessCfg
	}

	return nil
}

// Start starts the session manager
func (m *Manager) Start() error {
	if err := m.Module.Start(); err != nil {
		return err
	}

	// Start cleanup goroutine
	go m.cleanupLoop()

	m.SetHealthy(true, "session manager running")
	m.PublishEvent(events.EventTypeModuleStarted, nil)
	return nil
}

// Stop stops the session manager
func (m *Manager) Stop() error {
	close(m.cleanupStop)

	// Close all sessions
	m.mu.Lock()
	for id := range m.sessions {
		m.removeSessionLocked(id)
	}
	m.mu.Unlock()

	// Close event channels
	m.eventChansMu.Lock()
	for _, ch := range m.eventChans {
		close(ch)
	}
	m.eventChans = nil
	m.eventChansMu.Unlock()

	m.PublishEvent(events.EventTypeModuleStopped, nil)
	return m.Module.Stop()
}

// GetSession gets a session by ID
func (m *Manager) GetSession(id uint32) (interfaces.Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[id]
	if !exists || session.closed {
		return nil, false
	}
	return session, true
}

// GetSessionByAddr gets a session by client address
func (m *Manager) GetSessionByAddr(addr net.Addr) (interfaces.Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	id, exists := m.byAddr[addr.String()]
	if !exists {
		return nil, false
	}

	session, exists := m.sessions[id]
	if !exists || session.closed {
		return nil, false
	}
	return session, true
}

// CreateSession creates a new session
func (m *Manager) CreateSession(params interfaces.SessionParams) (interfaces.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check max sessions
	if len(m.sessions) >= m.config.MaxSessions {
		// Try to cleanup oldest session
		m.cleanupOldestLocked()
		if len(m.sessions) >= m.config.MaxSessions {
			return nil, fmt.Errorf("max sessions reached (%d)", m.config.MaxSessions)
		}
	}

	// Generate session ID
	id, err := m.generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	now := time.Now()
	session := &Session{
		id:           id,
		clientAddr:   params.ClientAddr,
		createdAt:    now,
		lastActivity: now,
		metadata:     params.Metadata,
		seed:         params.Seed,
		streams:      make(map[uint16]*Stream),
		seqSend:      1,
		seqRecv:      0,
	}

	session.onClose = func(sid uint32) {
		m.RemoveSession(sid)
	}

	m.sessions[id] = session
	if params.ClientAddr != nil {
		m.byAddr[params.ClientAddr.String()] = id
	}

	atomic.AddUint64(&m.totalCreated, 1)
	m.UpdateActivity()

	// Publish event
	m.publishSessionEvent(interfaces.SessionEventCreated, id, nil)

	return session, nil
}

// RemoveSession removes a session
func (m *Manager) RemoveSession(id uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeSessionLocked(id)
}

// removeSessionLocked removes a session (must hold lock)
func (m *Manager) removeSessionLocked(id uint32) {
	session, exists := m.sessions[id]
	if !exists {
		return
	}

	// Remove from addr index
	if session.clientAddr != nil {
		delete(m.byAddr, session.clientAddr.String())
	}

	// Mark as closed
	session.mu.Lock()
	session.closed = true
	session.mu.Unlock()

	delete(m.sessions, id)
	atomic.AddUint64(&m.totalRemoved, 1)

	// Publish event
	m.publishSessionEvent(interfaces.SessionEventRemoved, id, nil)
}

// GetAllSessions returns all active sessions
func (m *Manager) GetAllSessions() []interfaces.Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]interfaces.Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		if !s.closed {
			sessions = append(sessions, s)
		}
	}
	return sessions
}

// Count returns the number of active sessions
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// Subscribe subscribes to session events
func (m *Manager) Subscribe(eventType interfaces.SessionEventType) <-chan interfaces.SessionEvent {
	ch := make(chan interfaces.SessionEvent, 100)

	m.eventChansMu.Lock()
	m.eventChans = append(m.eventChans, ch)
	m.eventChansMu.Unlock()

	return ch
}

// SetMaxSessions sets the maximum number of sessions
func (m *Manager) SetMaxSessions(max int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.MaxSessions = max
}

// SetTimeout sets the session timeout
func (m *Manager) SetTimeout(timeout time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.SessionTimeout = timeout
}

// HealthCheck returns health status
func (m *Manager) HealthCheck() interfaces.HealthStatus {
	status := m.Module.HealthCheck()
	status.Details["session_count"] = m.Count()
	status.Details["total_created"] = atomic.LoadUint64(&m.totalCreated)
	status.Details["total_removed"] = atomic.LoadUint64(&m.totalRemoved)
	status.Details["max_sessions"] = m.config.MaxSessions
	return status
}

// generateSessionID generates a unique session ID
func (m *Manager) generateSessionID() (uint32, error) {
	for attempts := 0; attempts < 10; attempts++ {
		var buf [4]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, err
		}
		id := binary.BigEndian.Uint32(buf[:])
		if id == 0 {
			continue
		}
		if _, exists := m.sessions[id]; !exists {
			return id, nil
		}
	}
	return 0, fmt.Errorf("failed to generate unique session ID")
}

// cleanupLoop periodically cleans up expired sessions
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(m.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.cleanupStop:
			return
		case <-ticker.C:
			m.cleanupExpired()
		}
	}
}

// cleanupExpired removes expired sessions
func (m *Manager) cleanupExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	expired := make([]uint32, 0)

	for id, session := range m.sessions {
		session.mu.RLock()
		lastActivity := session.lastActivity
		session.mu.RUnlock()

		if now.Sub(lastActivity) > m.config.SessionTimeout {
			expired = append(expired, id)
		}
	}

	for _, id := range expired {
		m.removeSessionLocked(id)
		m.publishSessionEvent(interfaces.SessionEventExpired, id, nil)
	}
}

// cleanupOldestLocked removes the oldest session (must hold lock)
func (m *Manager) cleanupOldestLocked() {
	var oldestID uint32
	var oldestTime time.Time

	for id, session := range m.sessions {
		session.mu.RLock()
		lastActivity := session.lastActivity
		session.mu.RUnlock()

		if oldestID == 0 || lastActivity.Before(oldestTime) {
			oldestID = id
			oldestTime = lastActivity
		}
	}

	if oldestID != 0 {
		m.removeSessionLocked(oldestID)
	}
}

// publishSessionEvent publishes a session event
func (m *Manager) publishSessionEvent(eventType interfaces.SessionEventType, sessionID uint32, data interface{}) {
	event := interfaces.SessionEvent{
		Type:      eventType,
		SessionID: sessionID,
		Timestamp: time.Now(),
		Data:      data,
	}

	m.eventChansMu.RLock()
	defer m.eventChansMu.RUnlock()

	for _, ch := range m.eventChans {
		select {
		case ch <- event:
		default:
			// Channel full, skip
		}
	}

	// Also publish to event bus
	m.PublishEvent(string(eventType), map[string]interface{}{
		"session_id": sessionID,
		"data":       data,
	})
}

// Session interface implementation

func (s *Session) ID() uint32 {
	return s.id
}

func (s *Session) ClientAddr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clientAddr
}

func (s *Session) LastActivity() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastActivity
}

func (s *Session) UpdateActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActivity = time.Now()
}

func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	onClose := s.onClose
	id := s.id
	s.mu.Unlock()

	if onClose != nil {
		onClose(id)
	}
	return nil
}

func (s *Session) Encrypt(seq uint32, aad, plaintext []byte) ([]byte, error) {
	// TODO: Integrate with crypto module
	// For now, return plaintext as-is (placeholder)
	return plaintext, nil
}

func (s *Session) Decrypt(seq uint32, aad, ciphertext []byte) ([]byte, error) {
	// TODO: Integrate with crypto module
	// For now, return ciphertext as-is (placeholder)
	return ciphertext, nil
}

func (s *Session) GetStream(streamID uint16) (interfaces.Stream, bool) {
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()

	stream, exists := s.streams[streamID]
	if !exists {
		return nil, false
	}
	return stream, true
}

func (s *Session) CreateStream(streamID uint16) (interfaces.Stream, error) {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()

	if _, exists := s.streams[streamID]; exists {
		return nil, fmt.Errorf("stream %d already exists", streamID)
	}

	stream := &Stream{
		id:        streamID,
		state:     StreamStateOpen,
		buffer:    make([]byte, 0),
		createdAt: time.Now(),
	}

	s.streams[streamID] = stream
	return stream, nil
}

// GetNextSeqSend returns and increments the send sequence number
func (s *Session) GetNextSeqSend() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.seqSend
	s.seqSend++
	return seq
}

// GetMetadata returns a specific metadata value
func (s *Session) GetMetadata(key string) interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.metadata == nil {
		return nil
	}
	return s.metadata[key]
}

// SetMetadata sets a metadata value
func (s *Session) SetMetadata(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.metadata == nil {
		s.metadata = make(map[string]interface{})
	}
	s.metadata[key] = value
}

// Stream interface implementation

func (st *Stream) ID() uint16 {
	return st.id
}

func (st *Stream) Read(buf []byte) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.closed {
		return 0, fmt.Errorf("stream closed")
	}

	n := copy(buf, st.buffer)
	st.buffer = st.buffer[n:]
	return n, nil
}

func (st *Stream) Write(data []byte) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.closed {
		return 0, fmt.Errorf("stream closed")
	}

	st.buffer = append(st.buffer, data...)
	return len(data), nil
}

func (st *Stream) Close() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.closed = true
	st.state = StreamStateClosed
	return nil
}

func (st *Stream) IsClosed() bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.closed
}

// Factory creates session manager modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
