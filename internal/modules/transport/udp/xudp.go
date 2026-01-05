// Package udp provides UDP transport module implementation with XUDP support
// XUDP provides Full Cone NAT behavior for improved UDP connectivity

package udp

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// XUDP Header Constants (compatible with Xray-core XUDP)
const (
	XUDPVersion byte = 0x01

	// XUDP Commands
	XUDPCmdNew  byte = 0x01 // Create new session
	XUDPCmdKeep byte = 0x02 // Keep session alive / data
	XUDPCmdEnd  byte = 0x03 // End session

	// XUDP Header size
	XUDPHeaderSize = 8 // Version(1) + Command(1) + GlobalID(2) + Reserved(4)

	// Session timeout
	XUDPSessionTimeout = 5 * time.Minute
)

// XUDPHeader represents an XUDP packet header
type XUDPHeader struct {
	Version  byte
	Command  byte
	GlobalID uint16
	Reserved uint32
	DestAddr net.Addr // Original destination (for New command)
}

// XUDPSession represents an XUDP Full Cone NAT session
type XUDPSession struct {
	GlobalID    uint16
	LocalAddr   net.Addr // Client's address
	DestAddr    net.Addr // Original destination
	CreatedAt   time.Time
	LastActive  time.Time
	PacketsSent uint64
	PacketsRecv uint64
	BytesSent   uint64
	BytesRecv   uint64
	closed      int32
}

// XUDPManager manages XUDP sessions for Full Cone NAT
type XUDPManager struct {
	sessions     map[uint16]*XUDPSession
	sessionsByID map[string]uint16 // clientAddr+destAddr -> globalID
	mu           sync.RWMutex
	nextID       uint32
	transport    *Transport

	// Stats
	sessionsCreated uint64
	sessionsClosed  uint64
	packetsRelayed  uint64
}

// NewXUDPManager creates a new XUDP session manager
func NewXUDPManager(transport *Transport) *XUDPManager {
	m := &XUDPManager{
		sessions:     make(map[uint16]*XUDPSession),
		sessionsByID: make(map[string]uint16),
		transport:    transport,
		nextID:       1,
	}

	// Start cleanup goroutine
	go m.cleanupLoop()

	return m
}

// ParseXUDPHeader parses an XUDP header from packet data
func ParseXUDPHeader(data []byte) (*XUDPHeader, int, error) {
	if len(data) < XUDPHeaderSize {
		return nil, 0, nil // Not an XUDP packet
	}

	// Check version
	if data[0] != XUDPVersion {
		return nil, 0, nil // Not an XUDP packet
	}

	header := &XUDPHeader{
		Version:  data[0],
		Command:  data[1],
		GlobalID: binary.BigEndian.Uint16(data[2:4]),
		Reserved: binary.BigEndian.Uint32(data[4:8]),
	}

	headerLen := XUDPHeaderSize

	// For New command, parse destination address
	if header.Command == XUDPCmdNew && len(data) > XUDPHeaderSize+2 {
		addrType := data[XUDPHeaderSize]
		switch addrType {
		case 0x01: // IPv4
			if len(data) >= XUDPHeaderSize+1+4+2 {
				ip := net.IP(data[XUDPHeaderSize+1 : XUDPHeaderSize+5])
				port := binary.BigEndian.Uint16(data[XUDPHeaderSize+5 : XUDPHeaderSize+7])
				header.DestAddr = &net.UDPAddr{IP: ip, Port: int(port)}
				headerLen = XUDPHeaderSize + 7
			}
		case 0x02: // IPv6
			if len(data) >= XUDPHeaderSize+1+16+2 {
				ip := net.IP(data[XUDPHeaderSize+1 : XUDPHeaderSize+17])
				port := binary.BigEndian.Uint16(data[XUDPHeaderSize+17 : XUDPHeaderSize+19])
				header.DestAddr = &net.UDPAddr{IP: ip, Port: int(port)}
				headerLen = XUDPHeaderSize + 19
			}
		}
	}

	return header, headerLen, nil
}

// BuildXUDPHeader builds an XUDP header
func BuildXUDPHeader(cmd byte, globalID uint16, destAddr net.Addr) []byte {
	header := make([]byte, XUDPHeaderSize)
	header[0] = XUDPVersion
	header[1] = cmd
	binary.BigEndian.PutUint16(header[2:4], globalID)
	binary.BigEndian.PutUint32(header[4:8], 0) // Reserved

	// For New command, append destination address
	if cmd == XUDPCmdNew && destAddr != nil {
		if udpAddr, ok := destAddr.(*net.UDPAddr); ok {
			ip := udpAddr.IP.To4()
			if ip != nil {
				// IPv4
				header = append(header, 0x01)
				header = append(header, ip...)
				portBytes := make([]byte, 2)
				binary.BigEndian.PutUint16(portBytes, uint16(udpAddr.Port))
				header = append(header, portBytes...)
			} else {
				// IPv6
				header = append(header, 0x02)
				header = append(header, udpAddr.IP.To16()...)
				portBytes := make([]byte, 2)
				binary.BigEndian.PutUint16(portBytes, uint16(udpAddr.Port))
				header = append(header, portBytes...)
			}
		}
	}

	return header
}

// HandlePacket processes an incoming XUDP packet
func (m *XUDPManager) HandlePacket(data []byte, clientAddr net.Addr) ([]byte, *XUDPSession, error) {
	header, headerLen, err := ParseXUDPHeader(data)
	if err != nil {
		return data, nil, err
	}

	// Not an XUDP packet, return as-is
	if header == nil {
		return data, nil, nil
	}

	payload := data[headerLen:]

	switch header.Command {
	case XUDPCmdNew:
		session := m.createSession(header.GlobalID, clientAddr, header.DestAddr)
		atomic.AddUint64(&m.packetsRelayed, 1)
		return payload, session, nil

	case XUDPCmdKeep:
		session := m.getSession(header.GlobalID)
		if session != nil {
			session.LastActive = time.Now()
			atomic.AddUint64(&session.PacketsRecv, 1)
			atomic.AddUint64(&session.BytesRecv, uint64(len(payload)))
		}
		atomic.AddUint64(&m.packetsRelayed, 1)
		return payload, session, nil

	case XUDPCmdEnd:
		m.closeSession(header.GlobalID)
		return nil, nil, nil
	}

	return payload, nil, nil
}

// createSession creates a new XUDP session
func (m *XUDPManager) createSession(globalID uint16, clientAddr, destAddr net.Addr) *XUDPSession {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if session already exists
	if session, exists := m.sessions[globalID]; exists {
		session.LastActive = time.Now()
		return session
	}

	session := &XUDPSession{
		GlobalID:   globalID,
		LocalAddr:  clientAddr,
		DestAddr:   destAddr,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
	}

	m.sessions[globalID] = session

	// Create reverse lookup key
	if clientAddr != nil && destAddr != nil {
		key := clientAddr.String() + "->" + destAddr.String()
		m.sessionsByID[key] = globalID
	}

	atomic.AddUint64(&m.sessionsCreated, 1)
	return session
}

// getSession retrieves an XUDP session by global ID
func (m *XUDPManager) getSession(globalID uint16) *XUDPSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[globalID]
}

// GetOrCreateSession gets an existing session or creates a new one
func (m *XUDPManager) GetOrCreateSession(clientAddr, destAddr net.Addr) *XUDPSession {
	key := clientAddr.String() + "->" + destAddr.String()

	m.mu.RLock()
	if globalID, exists := m.sessionsByID[key]; exists {
		session := m.sessions[globalID]
		m.mu.RUnlock()
		if session != nil {
			session.LastActive = time.Now()
			return session
		}
	}
	m.mu.RUnlock()

	// Create new session
	globalID := uint16(atomic.AddUint32(&m.nextID, 1) & 0xFFFF)
	return m.createSession(globalID, clientAddr, destAddr)
}

// closeSession closes an XUDP session
func (m *XUDPManager) closeSession(globalID uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[globalID]
	if !exists {
		return
	}

	if atomic.CompareAndSwapInt32(&session.closed, 0, 1) {
		// Remove from maps
		delete(m.sessions, globalID)

		if session.LocalAddr != nil && session.DestAddr != nil {
			key := session.LocalAddr.String() + "->" + session.DestAddr.String()
			delete(m.sessionsByID, key)
		}

		atomic.AddUint64(&m.sessionsClosed, 1)
	}
}

// cleanupLoop periodically cleans up expired sessions
func (m *XUDPManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.cleanupExpiredSessions()
	}
}

// cleanupExpiredSessions removes expired XUDP sessions
func (m *XUDPManager) cleanupExpiredSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for globalID, session := range m.sessions {
		if now.Sub(session.LastActive) > XUDPSessionTimeout {
			if atomic.CompareAndSwapInt32(&session.closed, 0, 1) {
				delete(m.sessions, globalID)

				if session.LocalAddr != nil && session.DestAddr != nil {
					key := session.LocalAddr.String() + "->" + session.DestAddr.String()
					delete(m.sessionsByID, key)
				}

				atomic.AddUint64(&m.sessionsClosed, 1)
			}
		}
	}
}

// SendResponse sends a response through XUDP session
func (m *XUDPManager) SendResponse(session *XUDPSession, data []byte) error {
	if session == nil || session.LocalAddr == nil {
		return nil
	}

	// Build XUDP response header
	header := BuildXUDPHeader(XUDPCmdKeep, session.GlobalID, nil)
	packet := append(header, data...)

	// Send to client
	_, err := m.transport.WriteTo(packet, session.LocalAddr)
	if err == nil {
		atomic.AddUint64(&session.PacketsSent, 1)
		atomic.AddUint64(&session.BytesSent, uint64(len(data)))
	}

	return err
}

// Stats returns XUDP manager statistics
func (m *XUDPManager) Stats() XUDPStats {
	m.mu.RLock()
	activeSessions := len(m.sessions)
	m.mu.RUnlock()

	return XUDPStats{
		ActiveSessions:  activeSessions,
		SessionsCreated: atomic.LoadUint64(&m.sessionsCreated),
		SessionsClosed:  atomic.LoadUint64(&m.sessionsClosed),
		PacketsRelayed:  atomic.LoadUint64(&m.packetsRelayed),
	}
}

// XUDPStats holds XUDP manager statistics
type XUDPStats struct {
	ActiveSessions  int
	SessionsCreated uint64
	SessionsClosed  uint64
	PacketsRelayed  uint64
}
