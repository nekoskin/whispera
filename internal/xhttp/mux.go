package xhttp

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Stream represents a multiplexed stream within XHTTP
// Allows multiple logical connections over single XHTTP session
type Stream struct {
	ID           uint32
	Created      time.Time
	LastActivity time.Time

	// Buffers for read/write
	incomingBuffer chan []byte
	outgoingBuffer chan []byte

	// State
	closed     bool
	closeMutex sync.Mutex

	// Flow control
	sendWindow int64 // How much data we can send
	recvWindow int64 // How much data we can receive
	mu         sync.RWMutex

	// Metadata
	Metadata map[string]interface{}
}

// NewStream creates new stream
func NewStream(id uint32) *Stream {
	return &Stream{
		ID:             id,
		Created:        time.Now(),
		LastActivity:   time.Now(),
		incomingBuffer: make(chan []byte, 100),
		outgoingBuffer: make(chan []byte, 100),
		sendWindow:     65536, // 64KB default window
		recvWindow:     65536, // 64KB default window
		Metadata:       make(map[string]interface{}),
	}
}

// Write writes data to stream
func (s *Stream) Write(data []byte) error {
	s.closeMutex.Lock()
	if s.closed {
		s.closeMutex.Unlock()
		return fmt.Errorf("stream closed")
	}
	s.closeMutex.Unlock()

	s.LastActivity = time.Now()

	select {
	case s.incomingBuffer <- data:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("stream write timeout")
	}
}

// Read reads data from stream
func (s *Stream) Read() ([]byte, error) {
	select {
	case data := <-s.outgoingBuffer:
		return data, nil
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("stream read timeout")
	}
}

// Close closes stream
func (s *Stream) Close() error {
	s.closeMutex.Lock()
	defer s.closeMutex.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	close(s.incomingBuffer)
	close(s.outgoingBuffer)
	return nil
}

// Multiplexer represents XMUX multiplexer
// Allows multiple streams over single connection
type Multiplexer struct {
	conn         net.Conn
	streams      map[uint32]*Stream
	streamsMutex sync.RWMutex
	nextStreamID uint32

	// Control
	ctx    context.Context
	cancel context.CancelFunc

	// Statistics
	totalStreams uint64
	totalBytes   uint64
}

// NewMultiplexer creates new multiplexer
func NewMultiplexer(conn net.Conn) *Multiplexer {
	ctx, cancel := context.WithCancel(context.Background())

	m := &Multiplexer{
		conn:         conn,
		streams:      make(map[uint32]*Stream),
		nextStreamID: 1,
		ctx:          ctx,
		cancel:       cancel,
	}

	// Start demultiplexer
	go m.demultiplex()

	return m
}

// OpenStream opens new stream
func (m *Multiplexer) OpenStream() (*Stream, error) {
	m.streamsMutex.Lock()
	defer m.streamsMutex.Unlock()

	streamID := m.nextStreamID
	m.nextStreamID += 2 // Client streams are odd

	stream := NewStream(streamID)
	m.streams[streamID] = stream
	m.totalStreams++

	return stream, nil
}

// GetStream gets existing stream
func (m *Multiplexer) GetStream(id uint32) (*Stream, bool) {
	m.streamsMutex.RLock()
	defer m.streamsMutex.RUnlock()

	stream, exists := m.streams[id]
	return stream, exists
}

// CloseStream closes stream and removes it
func (m *Multiplexer) CloseStream(id uint32) error {
	m.streamsMutex.Lock()
	defer m.streamsMutex.Unlock()

	stream, exists := m.streams[id]
	if !exists {
		return fmt.Errorf("stream not found: %d", id)
	}

	delete(m.streams, id)
	return stream.Close()
}

// Frame represents XMUX frame
// Format: [StreamID:4][Type:1][Length:4][Data:...]
type Frame struct {
	StreamID uint32
	Type     FrameType
	Data     []byte
}

// FrameType represents frame type
type FrameType byte

const (
	FrameTypeData FrameType = iota
	FrameTypeWindowUpdate
	FrameTypeClose
	FrameTypePing
	FrameTypePong
)

// EncodeFrame encodes frame to bytes
func EncodeFrame(f *Frame) []byte {
	result := make([]byte, 9+len(f.Data))
	binary.BigEndian.PutUint32(result[0:4], f.StreamID)
	result[4] = byte(f.Type)
	binary.BigEndian.PutUint32(result[5:9], uint32(len(f.Data)))
	copy(result[9:], f.Data)
	return result
}

// DecodeFrame decodes frame from bytes
func DecodeFrame(data []byte) (*Frame, int, error) {
	if len(data) < 9 {
		return nil, 0, fmt.Errorf("frame too small")
	}

	streamID := binary.BigEndian.Uint32(data[0:4])
	frameType := FrameType(data[4])
	length := binary.BigEndian.Uint32(data[5:9])

	if int(length) > len(data)-9 {
		return nil, 0, fmt.Errorf("frame data truncated")
	}

	frameData := data[9 : 9+length]
	frame := &Frame{
		StreamID: streamID,
		Type:     frameType,
		Data:     frameData,
	}

	return frame, 9 + int(length), nil
}

// demultiplex reads frames and routes to streams
func (m *Multiplexer) demultiplex() {
	reader := NewFrameReader(m.conn)

	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		frame, err := reader.ReadFrame()
		if err != nil {
			if err != io.EOF {
				// Handle error
			}
			return
		}

		stream, exists := m.GetStream(frame.StreamID)
		if !exists {
			// Stream doesn't exist, create it (server-initiated)
			m.streamsMutex.Lock()
			stream = NewStream(frame.StreamID)
			m.streams[frame.StreamID] = stream
			m.streamsMutex.Unlock()
		}

		switch frame.Type {
		case FrameTypeData:
			_ = stream.Write(frame.Data)
			m.totalBytes += uint64(len(frame.Data))
		case FrameTypeClose:
			m.CloseStream(frame.StreamID)
		case FrameTypePing:
			// Send PONG
			pongFrame := &Frame{
				StreamID: frame.StreamID,
				Type:     FrameTypePong,
			}
			_ = m.WriteFrame(pongFrame)
		}
	}
}

// WriteFrame writes frame to connection
func (m *Multiplexer) WriteFrame(frame *Frame) error {
	data := EncodeFrame(frame)

	_, err := m.conn.Write(data)
	if err != nil {
		return err
	}

	m.totalBytes += uint64(len(data))
	return nil
}

// Close closes multiplexer
func (m *Multiplexer) Close() error {
	m.cancel()

	m.streamsMutex.Lock()
	defer m.streamsMutex.Unlock()

	for _, stream := range m.streams {
		_ = stream.Close()
	}

	return m.conn.Close()
}

// FrameReader reads frames from connection
type FrameReader struct {
	conn   net.Conn
	buffer []byte
}

// NewFrameReader creates new frame reader
func NewFrameReader(conn net.Conn) *FrameReader {
	return &FrameReader{
		conn:   conn,
		buffer: make([]byte, 0, 65536),
	}
}

// ReadFrame reads next frame from connection
func (fr *FrameReader) ReadFrame() (*Frame, error) {
	// Read header (9 bytes minimum)
	header := make([]byte, 9)
	if _, err := io.ReadFull(fr.conn, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(header[5:9])

	// Read payload
	payload := make([]byte, length)
	if _, err := io.ReadFull(fr.conn, payload); err != nil {
		return nil, err
	}

	streamID := binary.BigEndian.Uint32(header[0:4])
	frameType := FrameType(header[4])

	return &Frame{
		StreamID: streamID,
		Type:     frameType,
		Data:     payload,
	}, nil
}

// Extra represents XHTTP extra metadata
// Used for per-stream or per-session routing and configuration
type Extra struct {
	// Stream metadata
	StreamID   uint32
	StreamType string // "data", "control", etc.

	// Routing
	RoutingTag string
	Policy     string

	// Metadata
	Headers    map[string]string
	Attributes map[string]interface{}
}

// ExtraCodec handles encoding/decoding of Extra metadata
type ExtraCodec struct {
}

// EncodeExtra encodes extra metadata
func (ec *ExtraCodec) EncodeExtra(e *Extra) []byte {
	// Simple JSON encoding (could be optimized)
	return []byte{} // Implementation would use JSON or protobuf
}

// DecodeExtra decodes extra metadata
func (ec *ExtraCodec) DecodeExtra(data []byte) (*Extra, error) {
	// Simple JSON decoding
	return &Extra{}, nil
}
