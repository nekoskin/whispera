// Package relay provides stream management for multiplexed connections
package relay

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// StreamState represents the state of a stream
type StreamState int

const (
	StreamStateConnecting StreamState = iota
	StreamStateConnected
	StreamStateClosed
	StreamStateError
)

func (s StreamState) String() string {
	switch s {
	case StreamStateConnecting:
		return "connecting"
	case StreamStateConnected:
		return "connected"
	case StreamStateClosed:
		return "closed"
	case StreamStateError:
		return "error"
	default:
		return "unknown"
	}
}

// Stream represents a single multiplexed stream (one TCP/UDP connection)
type Stream struct {
	ID         uint16
	State      StreamState
	Protocol   uint8 // ProtoTCP or ProtoUDP
	TargetAddr string
	TargetPort uint16

	// TCP connection to target (server-side)
	conn net.Conn

	// UDP connection (for UDP relay)
	udpConn *net.UDPConn

	// Callbacks for sending frames back through tunnel
	onFrame func(*Frame) error

	// Channels
	incoming  chan []byte // Data from tunnel to target
	outgoing  chan []byte // Data from target to tunnel
	closeChan chan struct{}

	// Timing
	CreatedAt  time.Time
	LastActive time.Time

	// Stats
	BytesIn  uint64
	BytesOut uint64

	mu sync.RWMutex
}

// NewStream creates a new stream
func NewStream(id uint16, proto uint8, addr string, port uint16, onFrame func(*Frame) error) *Stream {
	return &Stream{
		ID:         id,
		State:      StreamStateConnecting,
		Protocol:   proto,
		TargetAddr: addr,
		TargetPort: port,
		onFrame:    onFrame,
		incoming:   make(chan []byte, 256),
		outgoing:   make(chan []byte, 256),
		closeChan:  make(chan struct{}),
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
	}
}

// Connect establishes connection to the target
func (s *Stream) Connect(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	target := fmt.Sprintf("%s:%d", s.TargetAddr, s.TargetPort)

	if s.Protocol == ProtoTCP {
		dialer := &net.Dialer{
			Timeout: 10 * time.Second,
		}
		conn, err := dialer.DialContext(ctx, "tcp", target)
		if err != nil {
			s.State = StreamStateError
			return err
		}
		s.conn = conn
		s.State = StreamStateConnected

		// Start relay goroutines
		go s.readFromTarget()
	} else if s.Protocol == ProtoUDP {
		addr, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			s.State = StreamStateError
			return err
		}
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			s.State = StreamStateError
			return err
		}
		s.udpConn = conn
		s.State = StreamStateConnected

		go s.readUDPFromTarget()
	}

	return nil
}

// Write sends data to the target
func (s *Stream) Write(data []byte) error {
	s.mu.RLock()
	state := s.State
	conn := s.conn
	udpConn := s.udpConn
	s.mu.RUnlock()

	if state != StreamStateConnected {
		return ErrStreamClosed
	}

	s.LastActive = time.Now()

	if s.Protocol == ProtoTCP && conn != nil {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		s.BytesOut += uint64(n)
		return nil
	} else if s.Protocol == ProtoUDP && udpConn != nil {
		n, err := udpConn.Write(data)
		if err != nil {
			return err
		}
		s.BytesOut += uint64(n)
		return nil
	}

	return ErrStreamClosed
}

// readFromTarget reads data from TCP target and sends back through tunnel
func (s *Stream) readFromTarget() {
	defer s.Close()

	buf := make([]byte, 32*1024) // 32KB buffer
	for {
		select {
		case <-s.closeChan:
			return
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := s.conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				// Log error but still close gracefully
			}
			return
		}

		if n > 0 {
			s.BytesIn += uint64(n)
			s.LastActive = time.Now()

			// Send data frame back through tunnel
			frame := NewDataFrame(s.ID, buf[:n])
			if s.onFrame != nil {
				if err := s.onFrame(frame); err != nil {
					return
				}
			}
		}
	}
}

// readUDPFromTarget reads data from UDP target and sends back through tunnel
func (s *Stream) readUDPFromTarget() {
	defer s.Close()

	buf := make([]byte, 65535)
	for {
		select {
		case <-s.closeChan:
			return
		default:
		}

		s.udpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := s.udpConn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // UDP timeout is okay, keep reading
			}
			return
		}

		if n > 0 {
			s.BytesIn += uint64(n)
			s.LastActive = time.Now()

			// Send data frame back through tunnel
			frame := NewDataFrame(s.ID, buf[:n])
			if s.onFrame != nil {
				if err := s.onFrame(frame); err != nil {
					return
				}
			}
		}
	}
}

// Close closes the stream
func (s *Stream) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.State == StreamStateClosed {
		return
	}

	s.State = StreamStateClosed

	// Signal close
	select {
	case <-s.closeChan:
	default:
		close(s.closeChan)
	}

	// Close connections
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	if s.udpConn != nil {
		s.udpConn.Close()
		s.udpConn = nil
	}
}

// IsActive returns true if the stream is still usable
func (s *Stream) IsActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.State == StreamStateConnected
}

// StreamManager manages all active streams
type StreamManager struct {
	streams map[uint16]*Stream
	mu      sync.RWMutex
	idGen   *StreamIDGenerator
	onFrame func(*Frame) error // Callback to send frames through tunnel

	ctx    context.Context
	cancel context.CancelFunc
}

// NewStreamManager creates a new stream manager
func NewStreamManager(onFrame func(*Frame) error) *StreamManager {
	ctx, cancel := context.WithCancel(context.Background())
	sm := &StreamManager{
		streams: make(map[uint16]*Stream),
		idGen:   NewStreamIDGenerator(),
		onFrame: onFrame,
		ctx:     ctx,
		cancel:  cancel,
	}

	// Start cleanup goroutine
	go sm.cleanupLoop()

	return sm
}

// CreateStream creates a new stream for outgoing connections (client-side)
func (sm *StreamManager) CreateStream(proto uint8, addr string, port uint16) *Stream {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	id := sm.idGen.Next()
	stream := NewStream(id, proto, addr, port, sm.onFrame)
	sm.streams[id] = stream

	return stream
}

// HandleConnect handles incoming CONNECT frame (server-side)
func (sm *StreamManager) HandleConnect(streamID uint16, payload *ConnectPayload) error {
	sm.mu.Lock()

	// Create stream
	stream := NewStream(streamID, payload.Protocol, payload.Addr, payload.Port, sm.onFrame)
	sm.streams[streamID] = stream
	sm.mu.Unlock()

	// Connect to target
	ctx, cancel := context.WithTimeout(sm.ctx, 10*time.Second)
	defer cancel()

	if err := stream.Connect(ctx); err != nil {
		sm.mu.Lock()
		delete(sm.streams, streamID)
		sm.mu.Unlock()

		// Send CONNECT_FAIL
		if sm.onFrame != nil {
			sm.onFrame(NewConnectFailFrame(streamID, err.Error()))
		}
		return err
	}

	// Send CONNECT_OK
	if sm.onFrame != nil {
		sm.onFrame(NewConnectOKFrame(streamID))
	}

	return nil
}

// HandleData handles incoming DATA frame
func (sm *StreamManager) HandleData(streamID uint16, data []byte) error {
	sm.mu.RLock()
	stream, ok := sm.streams[streamID]
	sm.mu.RUnlock()

	if !ok {
		return ErrStreamNotFound
	}

	return stream.Write(data)
}

// HandleClose handles incoming CLOSE frame
func (sm *StreamManager) HandleClose(streamID uint16) {
	sm.mu.Lock()
	stream, ok := sm.streams[streamID]
	if ok {
		delete(sm.streams, streamID)
	}
	sm.mu.Unlock()

	if stream != nil {
		stream.Close()
	}
}

// GetStream returns a stream by ID
func (sm *StreamManager) GetStream(id uint16) (*Stream, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	stream, ok := sm.streams[id]
	return stream, ok
}

// RemoveStream removes a stream
func (sm *StreamManager) RemoveStream(id uint16) {
	sm.mu.Lock()
	stream, ok := sm.streams[id]
	if ok {
		delete(sm.streams, id)
	}
	sm.mu.Unlock()

	if stream != nil {
		stream.Close()
	}
}

// Close closes all streams and stops the manager
func (sm *StreamManager) Close() {
	sm.cancel()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for id, stream := range sm.streams {
		stream.Close()
		delete(sm.streams, id)
	}
}

// Stats returns stream statistics
func (sm *StreamManager) Stats() (activeStreams int, totalBytesIn, totalBytesOut uint64) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	activeStreams = len(sm.streams)
	for _, stream := range sm.streams {
		totalBytesIn += stream.BytesIn
		totalBytesOut += stream.BytesOut
	}
	return
}

// cleanupLoop periodically cleans up stale streams
func (sm *StreamManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			sm.cleanup()
		}
	}
}

// cleanup removes stale streams
func (sm *StreamManager) cleanup() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	staleTimeout := 5 * time.Minute

	for id, stream := range sm.streams {
		if stream.State == StreamStateClosed {
			delete(sm.streams, id)
			continue
		}

		if now.Sub(stream.LastActive) > staleTimeout {
			stream.Close()
			delete(sm.streams, id)
		}
	}
}
