package xhttp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	metr "whispera/internal/metrics"
)

// PacketUpSession represents an XHTTP packet-up session
// Implements HTTP-level session lifecycle for XHTTP per Xray-core specification
// packet-up: Client sends packets as HTTP POST requests, server responds with GET sequences
type PacketUpSession struct {
	// Session metadata
	UUID           string // Unique session ID
	Path           string // HTTP path for this session
	ClientIP       string
	CreatedAt      time.Time
	LastActivityAt time.Time

	// Buffering and reassembly
	incomingBuffer bytes.Buffer // Buffer for packets received from client
	outgoingBuffer bytes.Buffer // Buffer for packets to send to client
	mutex          sync.RWMutex

	// Flow control
	MaxPostSize     int64 // Max size per POST request (scMaxEachPostBytes) - default 1000000
	MaxBufferedSize int64 // Max buffered size (scMaxBufferedPosts) - default 100000000
	CurrentBuffered int64

	// Padding and obfuscation
	PaddingBytes int // xPaddingBytes - random padding per request

	// Close state
	closed    bool
	closeOnce sync.Once
}

// SessionManager manages all active XHTTP sessions
type SessionManager struct {
	sessions map[string]*PacketUpSession
	mutex    sync.RWMutex

	// Configuration
	MaxSessions     int
	SessionTimeout  time.Duration
	MaxPostSize     int64
	MaxBufferedSize int64
	PaddingBytes    int
}

// NewSessionManager creates a new session manager
func NewSessionManager(maxSessions int, sessionTimeout time.Duration) *SessionManager {
	sm := &SessionManager{
		sessions:        make(map[string]*PacketUpSession),
		MaxSessions:     maxSessions,
		SessionTimeout:  sessionTimeout,
		MaxPostSize:     1000000,   // 1MB per POST (default per Xray-core)
		MaxBufferedSize: 100000000, // 100MB buffered (default per Xray-core)
		PaddingBytes:    16,        // Random padding per request
	}

	// Start cleanup goroutine
	go sm.cleanupExpiredSessions()

	return sm
}

// GetOrCreateSession gets existing session or creates new one
func (sm *SessionManager) GetOrCreateSession(uuid, path, clientIP string) (*PacketUpSession, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Check if session exists
	if session, exists := sm.sessions[uuid]; exists {
		session.mutex.Lock()
		session.LastActivityAt = time.Now()
		session.mutex.Unlock()
		return session, nil
	}

	// Check session limit
	if len(sm.sessions) >= sm.MaxSessions {
		return nil, fmt.Errorf("session limit reached: %d", sm.MaxSessions)
	}

	// Create new session
	session := &PacketUpSession{
		UUID:            uuid,
		Path:            path,
		ClientIP:        clientIP,
		CreatedAt:       time.Now(),
		LastActivityAt:  time.Now(),
		MaxPostSize:     sm.MaxPostSize,
		MaxBufferedSize: sm.MaxBufferedSize,
		PaddingBytes:    sm.PaddingBytes,
	}

	sm.sessions[uuid] = session

	// Record metrics
	metr.XHTTPSessionsCreated.Inc()
	metr.XHTTPSessionsActive.Set(float64(len(sm.sessions)))

	return session, nil
}

// GetSession retrieves existing session
func (sm *SessionManager) GetSession(uuid string) (*PacketUpSession, bool) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	session, exists := sm.sessions[uuid]
	return session, exists
}

// RemoveSession removes session from manager
func (sm *SessionManager) RemoveSession(uuid string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	delete(sm.sessions, uuid)
}

// cleanupExpiredSessions removes sessions that haven't been active
func (sm *SessionManager) cleanupExpiredSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		sm.mutex.Lock()
		now := time.Now()
		var toRemove []string

		for uuid, session := range sm.sessions {
			session.mutex.RLock()
			lastActivity := session.LastActivityAt
			createdAt := session.CreatedAt
			session.mutex.RUnlock()

			if now.Sub(lastActivity) > sm.SessionTimeout {
				toRemove = append(toRemove, uuid)
				// Record session duration metric
				duration := now.Sub(createdAt).Seconds()
				metr.XHTTPSessionDuration.Observe(duration)
				metr.XHTTPSessionsTimeout.Inc()
			}
		}

		for _, uuid := range toRemove {
			delete(sm.sessions, uuid)
		}

		// Update active sessions gauge
		metr.XHTTPSessionsActive.Set(float64(len(sm.sessions)))

		sm.mutex.Unlock()
	}
}

// WritePacket writes incoming packet to session buffer (from client POST)
// Returns buffered size after write
func (session *PacketUpSession) WritePacket(data []byte) (int64, error) {
	session.mutex.Lock()
	defer session.mutex.Unlock()

	if session.closed {
		return 0, fmt.Errorf("session closed")
	}

	// Check packet size
	if int64(len(data)) > session.MaxPostSize {
		return 0, fmt.Errorf("packet too large: %d > %d", len(data), session.MaxPostSize)
	}

	// Check total buffered size
	if session.CurrentBuffered+int64(len(data)) > session.MaxBufferedSize {
		return 0, fmt.Errorf("buffer overflow: %d bytes", session.CurrentBuffered+int64(len(data)))
	}

	// For packet-up mode the POSTed packets should be available
	// to GET requests immediately. Store written packets into
	// the outgoing buffer so ReadPacket can return them.
	session.outgoingBuffer.Write(data)
	session.CurrentBuffered += int64(len(data))
	session.LastActivityAt = time.Now()

	return session.CurrentBuffered, nil
}

// ReadPacket reads outgoing packet from session buffer (for client GET)
// Returns up to maxSize bytes
func (session *PacketUpSession) ReadPacket(maxSize int64) ([]byte, error) {
	session.mutex.Lock()
	defer session.mutex.Unlock()

	if session.closed && session.outgoingBuffer.Len() == 0 {
		return nil, io.EOF
	}

	// Read up to maxSize
	if maxSize == 0 {
		maxSize = session.MaxPostSize
	}
	if int64(session.outgoingBuffer.Len()) < maxSize {
		maxSize = int64(session.outgoingBuffer.Len())
	}

	data := make([]byte, maxSize)
	n, _ := session.outgoingBuffer.Read(data)
	session.CurrentBuffered -= int64(n)
	session.LastActivityAt = time.Now()

	return data[:n], nil
}

// Close closes the session
func (session *PacketUpSession) Close() error {
	session.closeOnce.Do(func() {
		session.mutex.Lock()
		defer session.mutex.Unlock()
		session.closed = true
	})
	return nil
}

// HTTPPacketUpHandler handles HTTP packet-up requests
// This implements the HTTP-level semantics of XHTTP packet-up mode
type HTTPPacketUpHandler struct {
	sessionManager *SessionManager
}

// NewHTTPPacketUpHandler creates new handler
func NewHTTPPacketUpHandler(sessionManager *SessionManager) *HTTPPacketUpHandler {
	return &HTTPPacketUpHandler{
		sessionManager: sessionManager,
	}
}

// ParseXHTTPRequest parses XHTTP packet-up request
// Extracts UUID and path from HTTP request
func ParseXHTTPRequest(r *http.Request) (uuid, path string, err error) {
	// UUID can be in header or path
	uuid = r.Header.Get("X-Forwarded-For")
	if uuid == "" {
		uuid = r.Header.Get("X-Session-ID")
	}
	if uuid == "" {
		// Try to extract from path: /path/[uuid]
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) > 1 {
			uuid = parts[len(parts)-1]
		}
	}

	if uuid == "" {
		return "", "", fmt.Errorf("no session UUID found")
	}

	path = r.URL.Path
	return uuid, path, nil
}

// HandlePOSTRequest handles incoming POST request (client sends packets)
// Packets are submitted as hex-encoded body
func (h *HTTPPacketUpHandler) HandlePOSTRequest(w http.ResponseWriter, r *http.Request) {
	uuid, path, err := ParseXHTTPRequest(r)
	if err != nil {
		http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get or create session
	session, err := h.sessionManager.GetOrCreateSession(uuid, path, r.RemoteAddr)
	if err != nil {
		http.Error(w, "Service Unavailable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Read request body
	body := make([]byte, 0, r.ContentLength)
	if r.ContentLength > 0 {
		body = make([]byte, r.ContentLength)
		_, err = io.ReadFull(r.Body, body)
		if err != nil {
			http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	defer r.Body.Close()

	// Decode hex-encoded packets
	packets, err := decodePackets(body)
	if err != nil {
		http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Write packets to session
	for _, packet := range packets {
		_, err := session.WritePacket(packet)
		if err != nil {
			http.Error(w, "Internal Server Error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Return 200 with optional padding
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Optional padding (xPaddingBytes)
	if session.PaddingBytes > 0 {
		padding := make([]byte, session.PaddingBytes)
		for i := range padding {
			padding[i] = byte(i % 256)
		}
		w.Write(padding)
	}
}

// HandleGETRequest handles outgoing GET request (client receives packets)
func (h *HTTPPacketUpHandler) HandleGETRequest(w http.ResponseWriter, r *http.Request) {
	uuid, _, err := ParseXHTTPRequest(r)
	if err != nil {
		http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get session
	session, exists := h.sessionManager.GetSession(uuid)
	if !exists {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Get max size from query parameter (default to MaxPostSize)
	maxSize := session.MaxPostSize
	if sizeStr := r.URL.Query().Get("size"); sizeStr != "" {
		if size, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
			if size > 0 && size < maxSize {
				maxSize = size
			}
		}
	}

	// Read packets from session
	packet, err := session.ReadPacket(maxSize)
	if err != nil && err != io.EOF {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Return packets as hex-encoded
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	if len(packet) > 0 {
		encoded := hex.EncodeToString(packet)
		w.Write([]byte(encoded))
	}
}

// decodePackets decodes packets from request body
// Expected format: hex-encoded packets separated by newlines or as raw bytes
func decodePackets(body []byte) ([][]byte, error) {
	var packets [][]byte

	// Try to parse as hex-encoded packets
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// Try to decode as hex
		decoded, err := hex.DecodeString(string(line))
		if err == nil && len(decoded) > 0 {
			packets = append(packets, decoded)
			continue
		}

		// If not hex, treat as raw packet
		packets = append(packets, bytes.Clone(line))
	}

	if len(packets) == 0 {
		// If no newlines, treat entire body as single packet
		if len(body) > 0 {
			packets = append(packets, bytes.Clone(body))
		}
	}

	return packets, nil
}

// StreamUpSession represents stream-up mode (different from packet-up)
// stream-up uses single long-lived HTTP connection with sequential packets
type StreamUpSession struct {
	UUID           string
	ClientConn     net.Conn
	Conn           net.Conn
	CreatedAt      time.Time
	LastActivityAt time.Time
}

// HandleStreamUpConn handles stream-up mode connection
// In stream-up, the connection stays open and packets are streamed continuously
func (s *StreamUpSession) HandleStreamUpConn(ctx context.Context, obfuscatedConn net.Conn) error {
	// Create reader/writer from connection
	reader := bufio.NewReader(obfuscatedConn)
	writer := bufio.NewWriter(obfuscatedConn)

	defer obfuscatedConn.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Read packet size (2 bytes, big-endian)
		sizeBuf := make([]byte, 2)
		if _, err := io.ReadFull(reader, sizeBuf); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		size := int(sizeBuf[0])<<8 | int(sizeBuf[1])

		// Read packet
		packet := make([]byte, size)
		if _, err := io.ReadFull(reader, packet); err != nil {
			return err
		}

		// Process packet (would be handled by upper layer)
		_ = packet

		// Write response (empty or ack)
		if _, err := writer.WriteString("OK"); err != nil {
			return err
		}
		if err := writer.Flush(); err != nil {
			return err
		}
	}
}

// StreamOneMode handles stream-one mode (single request-response)
// stream-one: Client sends all data in single POST, server responds with all data in single response
type StreamOneMode struct {
	UUID string
}

// HandleStreamOneRequest handles stream-one request
func (s *StreamOneMode) HandleStreamOneRequest(w http.ResponseWriter, r *http.Request) {
	// Read all data from request
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Process data (would be handled by upper layer)
	_ = data

	// Return response (would be populated by upper layer)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte{})
}
