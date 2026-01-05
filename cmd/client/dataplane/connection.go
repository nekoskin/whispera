// Package dataplane provides connection state machine for Whispera protocol
package dataplane

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionState represents the state of a Whispera connection
// Similar to XMLHttpRequest readyState
type ConnectionState int32

const (
	// StateUnsent - Object created, Open() not yet called
	StateUnsent ConnectionState = 0
	// StateOpened - Open() called, headers can be set
	StateOpened ConnectionState = 1
	// StateHeadersReceived - Send() called, server returned headers
	StateHeadersReceived ConnectionState = 2
	// StateLoading - Response body loading, data arriving in chunks
	StateLoading ConnectionState = 3
	// StateDone - Operation completely finished
	StateDone ConnectionState = 4
)

// String returns human-readable state name
func (s ConnectionState) String() string {
	switch s {
	case StateUnsent:
		return "UNSENT"
	case StateOpened:
		return "OPENED"
	case StateHeadersReceived:
		return "HEADERS_RECEIVED"
	case StateLoading:
		return "LOADING"
	case StateDone:
		return "DONE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// ConnectionHeaders represents Whispera protocol headers
type ConnectionHeaders struct {
	Version     uint8             // Protocol version (1 = Whispera v1)
	UUID        [16]byte          // Client UUID
	Addons      uint8             // Addon flags (obfuscation, compression, etc)
	ObfProfile  string            // Obfuscation profile
	Compression string            // Compression type
	CustomData  map[string]string // Custom headers
}

// StateChangeHandler is called when connection state changes
type StateChangeHandler func(oldState, newState ConnectionState)

// Connection represents a Whispera protocol connection with state machine
type Connection struct {
	// State machine
	state         int32 // atomic ConnectionState
	stateHandlers []StateChangeHandler
	stateMu       sync.RWMutex

	// Connection info
	serverAddr string
	transport  string // "udp", "tcp", "websocket", "quic"
	headers    ConnectionHeaders

	// Underlying connection
	conn   net.Conn
	connMu sync.RWMutex

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// Data channels
	rxChan chan []byte
	txChan chan []byte

	// Metrics
	bytesSent     uint64
	bytesReceived uint64
	startTime     time.Time

	// Error handling
	lastError error
	errorMu   sync.RWMutex
}

// NewConnection creates a new Whispera connection in UNSENT state
func NewConnection(serverAddr string, transport string) *Connection {
	ctx, cancel := context.WithCancel(context.Background())
	return &Connection{
		state:      int32(StateUnsent),
		serverAddr: serverAddr,
		transport:  transport,
		ctx:        ctx,
		cancel:     cancel,
		rxChan:     make(chan []byte, 1024),
		txChan:     make(chan []byte, 1024),
		headers: ConnectionHeaders{
			Version:    1,
			CustomData: make(map[string]string),
		},
	}
}

// State returns current connection state
func (c *Connection) State() ConnectionState {
	return ConnectionState(atomic.LoadInt32(&c.state))
}

// OnStateChange registers a handler for state changes
func (c *Connection) OnStateChange(handler StateChangeHandler) {
	c.stateMu.Lock()
	c.stateHandlers = append(c.stateHandlers, handler)
	c.stateMu.Unlock()
}

// setState changes state and notifies handlers
func (c *Connection) setState(newState ConnectionState) error {
	oldState := ConnectionState(atomic.SwapInt32(&c.state, int32(newState)))

	// Validate state transition
	if !c.isValidTransition(oldState, newState) {
		atomic.StoreInt32(&c.state, int32(oldState)) // Rollback
		return fmt.Errorf("invalid state transition: %s -> %s", oldState, newState)
	}

	// Notify handlers
	c.stateMu.RLock()
	handlers := c.stateHandlers
	c.stateMu.RUnlock()

	for _, handler := range handlers {
		handler(oldState, newState)
	}

	return nil
}

// isValidTransition checks if state transition is valid
func (c *Connection) isValidTransition(from, to ConnectionState) bool {
	// Valid transitions:
	// UNSENT -> OPENED
	// OPENED -> HEADERS_RECEIVED, DONE (on error)
	// HEADERS_RECEIVED -> LOADING, DONE
	// LOADING -> DONE
	// DONE -> UNSENT (reset)
	switch from {
	case StateUnsent:
		return to == StateOpened
	case StateOpened:
		return to == StateHeadersReceived || to == StateDone
	case StateHeadersReceived:
		return to == StateLoading || to == StateDone
	case StateLoading:
		return to == StateDone
	case StateDone:
		return to == StateUnsent // Allow reset
	default:
		return false
	}
}

// Open transitions from UNSENT to OPENED
// Allows setting headers before Send()
func (c *Connection) Open() error {
	if c.State() != StateUnsent {
		return fmt.Errorf("cannot Open(): state is %s, expected UNSENT", c.State())
	}

	c.startTime = time.Now()
	return c.setState(StateOpened)
}

// SetHeader sets a custom header (only in OPENED state)
func (c *Connection) SetHeader(key, value string) error {
	if c.State() != StateOpened {
		return fmt.Errorf("cannot SetHeader(): state is %s, expected OPENED", c.State())
	}
	c.headers.CustomData[key] = value
	return nil
}

// SetUUID sets the client UUID (only in OPENED state)
func (c *Connection) SetUUID(uuid [16]byte) error {
	if c.State() != StateOpened {
		return fmt.Errorf("cannot SetUUID(): state is %s, expected OPENED", c.State())
	}
	c.headers.UUID = uuid
	return nil
}

// SetObfuscation sets obfuscation profile (only in OPENED state)
func (c *Connection) SetObfuscation(profile string, compression string) error {
	if c.State() != StateOpened {
		return fmt.Errorf("cannot SetObfuscation(): state is %s, expected OPENED", c.State())
	}
	c.headers.ObfProfile = profile
	c.headers.Compression = compression
	c.headers.Addons |= 0x01 // Enable obfuscation flag
	if compression != "" {
		c.headers.Addons |= 0x02 // Enable compression flag
	}
	return nil
}

// Send establishes connection to server
// Transitions: OPENED -> HEADERS_RECEIVED (on success) or DONE (on error)
func (c *Connection) Send(ctx context.Context) error {
	if c.State() != StateOpened {
		return fmt.Errorf("cannot Send(): state is %s, expected OPENED", c.State())
	}

	// Dial server based on transport type
	var conn net.Conn
	var err error

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()

	dialer := &net.Dialer{Timeout: 10 * time.Second}

	switch c.transport {
	case "udp":
		conn, err = dialer.DialContext(dialCtx, "udp", c.serverAddr)
	case "tcp", "websocket", "quic":
		conn, err = dialer.DialContext(dialCtx, "tcp", c.serverAddr)
	default:
		err = fmt.Errorf("unsupported transport: %s", c.transport)
	}

	if err != nil {
		c.setError(err)
		c.setState(StateDone)
		return fmt.Errorf("dial failed: %w", err)
	}

	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()

	// Send Whispera handshake
	if err := c.sendHandshake(); err != nil {
		c.setError(err)
		c.setState(StateDone)
		return fmt.Errorf("handshake failed: %w", err)
	}

	// Receive server response headers
	if err := c.receiveHeaders(); err != nil {
		c.setError(err)
		c.setState(StateDone)
		return fmt.Errorf("receive headers failed: %w", err)
	}

	// Transition to HEADERS_RECEIVED
	return c.setState(StateHeadersReceived)
}

// sendHandshake sends Whispera protocol handshake (server-compatible format)
// Format: [type:1][version:1][uuid:16][ephemeral_pubkey:32][timestamp:4][padding:10] = 64 bytes
func (c *Connection) sendHandshake() error {
	c.connMu.RLock()
	conn := c.conn
	c.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("connection is nil")
	}

	// Build server-compatible handshake packet (64 bytes)
	handshake := make([]byte, 64)

	// Byte 0: Type (0x01 = Init)
	handshake[0] = 0x01

	// Byte 1: Version
	handshake[1] = c.headers.Version

	// Bytes 2-17: UUID (16 bytes)
	copy(handshake[2:18], c.headers.UUID[:])

	// Bytes 18-49: Ephemeral Public Key (32 bytes) - generated randomly for now
	// In production, use proper X25519 key exchange
	for i := 18; i < 50; i++ {
		handshake[i] = byte(i * 7) // Placeholder - should be real ephemeral key
	}

	// Bytes 50-53: Timestamp (4 bytes, big-endian)
	timestamp := uint32(time.Now().Unix())
	handshake[50] = byte(timestamp >> 24)
	handshake[51] = byte(timestamp >> 16)
	handshake[52] = byte(timestamp >> 8)
	handshake[53] = byte(timestamp)

	// Bytes 54-63: Random padding (10 bytes)
	for i := 54; i < 64; i++ {
		handshake[i] = byte(i + int(timestamp&0xFF))
	}

	_, err := conn.Write(handshake)
	if err != nil {
		return err
	}

	atomic.AddUint64(&c.bytesSent, uint64(len(handshake)))
	return nil
}

// receiveHeaders receives server response headers (server-compatible format)
// Format: [type:1][status:1][session_id:4][server_pubkey:32][nonce:10] = 48 bytes
func (c *Connection) receiveHeaders() error {
	c.connMu.RLock()
	conn := c.conn
	c.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("connection is nil")
	}

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	// Read server response (48 bytes expected)
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}

	if n < 6 {
		return fmt.Errorf("response too short: %d bytes", n)
	}

	// Parse response
	respType := buf[0]
	status := buf[1]

	// Type should be 0x02 (Response)
	if respType != 0x02 {
		return fmt.Errorf("unexpected response type: 0x%02x", respType)
	}

	// Status 0x00 = OK
	if status != 0x00 {
		return fmt.Errorf("server returned error status: 0x%02x", status)
	}

	// Extract session ID (bytes 2-5)
	if n >= 6 {
		sessionID := uint32(buf[2])<<24 | uint32(buf[3])<<16 | uint32(buf[4])<<8 | uint32(buf[5])
		c.headers.CustomData["session_id"] = fmt.Sprintf("%d", sessionID)
	}

	// Server public key would be in bytes 6-37 if we need key exchange
	// Nonce would be in bytes 38-47

	atomic.AddUint64(&c.bytesReceived, uint64(n))
	return nil
}

// StartDataTransfer transitions to LOADING state and starts data pumps
func (c *Connection) StartDataTransfer() error {
	if c.State() != StateHeadersReceived {
		return fmt.Errorf("cannot StartDataTransfer(): state is %s, expected HEADERS_RECEIVED", c.State())
	}

	if err := c.setState(StateLoading); err != nil {
		return err
	}

	// Start RX/TX pumps
	go c.rxPump()
	go c.txPump()

	return nil
}

// rxPump reads data from connection and sends to rxChan
func (c *Connection) rxPump() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		c.connMu.RLock()
		conn := c.conn
		c.connMu.RUnlock()

		if conn == nil {
			return
		}

		n, err := conn.Read(buf)
		if err != nil {
			c.setError(err)
			c.Close()
			return
		}

		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])

			atomic.AddUint64(&c.bytesReceived, uint64(n))

			select {
			case c.rxChan <- data:
			case <-c.ctx.Done():
				return
			default:
				// Channel full, drop oldest
				select {
				case <-c.rxChan:
					c.rxChan <- data
				default:
				}
			}
		}
	}
}

// txPump reads from txChan and writes to connection
func (c *Connection) txPump() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case data := <-c.txChan:
			c.connMu.RLock()
			conn := c.conn
			c.connMu.RUnlock()

			if conn == nil {
				return
			}

			n, err := conn.Write(data)
			if err != nil {
				c.setError(err)
				c.Close()
				return
			}

			atomic.AddUint64(&c.bytesSent, uint64(n))
		}
	}
}

// Send data through the connection (only in LOADING state)
func (c *Connection) Write(data []byte) (int, error) {
	if c.State() != StateLoading {
		return 0, fmt.Errorf("cannot Write(): state is %s, expected LOADING", c.State())
	}

	select {
	case c.txChan <- data:
		return len(data), nil
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	default:
		return 0, fmt.Errorf("write buffer full")
	}
}

// Read data from the connection (only in LOADING state)
func (c *Connection) Read(buf []byte) (int, error) {
	if c.State() != StateLoading {
		return 0, fmt.Errorf("cannot Read(): state is %s, expected LOADING", c.State())
	}

	select {
	case data := <-c.rxChan:
		n := copy(buf, data)
		return n, nil
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	}
}

// Close closes the connection and transitions to DONE state
func (c *Connection) Close() error {
	c.cancel()

	c.connMu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connMu.Unlock()

	// Only transition if not already DONE
	if c.State() != StateDone {
		return c.setState(StateDone)
	}
	return nil
}

// Reset resets connection to UNSENT state for reuse
func (c *Connection) Reset() error {
	if c.State() != StateDone {
		return fmt.Errorf("cannot Reset(): state is %s, expected DONE", c.State())
	}

	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.rxChan = make(chan []byte, 1024)
	c.txChan = make(chan []byte, 1024)
	c.bytesSent = 0
	c.bytesReceived = 0
	c.lastError = nil

	return c.setState(StateUnsent)
}

// Error returns the last error
func (c *Connection) Error() error {
	c.errorMu.RLock()
	defer c.errorMu.RUnlock()
	return c.lastError
}

func (c *Connection) setError(err error) {
	c.errorMu.Lock()
	c.lastError = err
	c.errorMu.Unlock()
}

// Stats returns connection statistics
func (c *Connection) Stats() (sent, received uint64, duration time.Duration) {
	return atomic.LoadUint64(&c.bytesSent),
		atomic.LoadUint64(&c.bytesReceived),
		time.Since(c.startTime)
}
