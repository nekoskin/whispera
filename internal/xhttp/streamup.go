package xhttp

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// StreamUpConn represents a stream-up mode connection
// Stream-up: single long-lived TCP connection with continuous packet streaming
// Uses XMUX for multiplexing multiple logical streams over single connection
type StreamUpConn struct {
	conn        net.Conn
	multiplexer *Multiplexer
	ctx         context.Context
	cancel      context.CancelFunc

	// Configuration
	config *Config

	// Stream management
	streams  map[uint32]*Stream
	streamMu sync.RWMutex

	// Flow control
	connWindow    int64
	maxConnWindow int64
	mu            sync.RWMutex

	// Read/Write management
	reader     *bufio.Reader
	writer     *bufio.Writer
	writeMutex sync.Mutex

	// Statistics
	totalPackets uint64
	totalBytes   uint64
	startTime    time.Time
}

// NewStreamUpConn creates new stream-up connection wrapper
func NewStreamUpConn(conn net.Conn, config *Config) *StreamUpConn {
	ctx, cancel := context.WithCancel(context.Background())

	// Default window size
	maxWindow := int64(65536) // 64KB
	if config.StreamUp.BufferSize > 0 {
		maxWindow = config.StreamUp.BufferSize
	}

	return &StreamUpConn{
		conn:          conn,
		config:        config,
		multiplexer:   NewMultiplexer(conn),
		ctx:           ctx,
		cancel:        cancel,
		reader:        bufio.NewReaderSize(conn, 65536),
		writer:        bufio.NewWriterSize(conn, 65536),
		startTime:     time.Now(),
		streams:       make(map[uint32]*Stream),
		connWindow:    maxWindow,
		maxConnWindow: maxWindow,
	}
}

// HandleStreamUpConnection handles incoming stream-up connection
// Manages packet reception and delivery over multiplexed streams
func (suc *StreamUpConn) HandleStreamUpConnection(obfuscationConfig *ServerConfig) error {
	defer suc.Close()

	// Start receiving frames from multiplexer
	errChan := make(chan error, 1)

	go func() {
		for {
			select {
			case <-suc.ctx.Done():
				return
			default:
			}

			// Try to read frame
			frame, err := suc.readFrame()
			if err != nil {
				if err != io.EOF {
					errChan <- fmt.Errorf("frame read error: %w", err)
				}
				return
			}

			// Route frame to appropriate stream
			stream, exists := suc.multiplexer.GetStream(frame.StreamID)
			if !exists {
				// Server-initiated stream
				stream = NewStream(frame.StreamID)
				suc.multiplexer.streams[frame.StreamID] = stream
				suc.multiplexer.streamsMutex.Lock()
				suc.multiplexer.streams[frame.StreamID] = stream
				suc.multiplexer.streamsMutex.Unlock()
			}

			// Process frame based on type
			switch frame.Type {
			case FrameTypeData:
				_ = stream.Write(frame.Data)
				suc.totalBytes += uint64(len(frame.Data))
				suc.totalPackets++

			case FrameTypeClose:
				suc.multiplexer.CloseStream(frame.StreamID)

			case FrameTypePing:
				// Send PONG response
				pongFrame := &Frame{
					StreamID: frame.StreamID,
					Type:     FrameTypePong,
				}
				_ = suc.writeFrame(pongFrame)

			case FrameTypeWindowUpdate:
				// Handle flow control update
				if len(frame.Data) >= 4 {
					streamID := binary.BigEndian.Uint32(frame.Data[:4])
					windowIncrement := binary.BigEndian.Uint32(frame.Data[4:8])

					// Update stream window
					if stream, ok := suc.streams[streamID]; ok {
						stream.mu.Lock()
						stream.sendWindow += int64(windowIncrement)
						if stream.sendWindow > suc.maxConnWindow {
							stream.sendWindow = suc.maxConnWindow
						}
						stream.mu.Unlock()
					} else {
						// Update connection-level window
						suc.streamMu.Lock()
						suc.connWindow += int64(windowIncrement)
						if suc.connWindow > suc.maxConnWindow {
							suc.connWindow = suc.maxConnWindow
						}
						suc.streamMu.Unlock()
					}
				}
			}
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-suc.ctx.Done():
		return suc.ctx.Err()
	case err := <-errChan:
		return err
	}
}

// readFrame reads next XMUX frame from connection
func (suc *StreamUpConn) readFrame() (*Frame, error) {
	// Read frame header (9 bytes: StreamID[4] Type[1] Length[4])
	header := make([]byte, 9)
	if _, err := io.ReadFull(suc.reader, header); err != nil {
		return nil, err
	}

	streamID := binary.BigEndian.Uint32(header[0:4])
	frameType := FrameType(header[4])
	length := binary.BigEndian.Uint32(header[5:9])

	// Read payload
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(suc.reader, payload); err != nil {
			return nil, err
		}
	}

	return &Frame{
		StreamID: streamID,
		Type:     frameType,
		Data:     payload,
	}, nil
}

// writeFrame writes XMUX frame to connection
func (suc *StreamUpConn) writeFrame(frame *Frame) error {
	suc.writeMutex.Lock()
	defer suc.writeMutex.Unlock()

	// Encode frame
	data := EncodeFrame(frame)

	// Write to buffered writer
	if _, err := suc.writer.Write(data); err != nil {
		return err
	}

	// Flush on large frames or periodically
	if len(data) > 10000 {
		if err := suc.writer.Flush(); err != nil {
			return err
		}
	}

	return nil
}

// OpenStreamForClient opens new outbound stream for client
func (suc *StreamUpConn) OpenStreamForClient() (*Stream, error) {
	return suc.multiplexer.OpenStream()
}

// GetStream gets existing stream
func (suc *StreamUpConn) GetStream(id uint32) (*Stream, bool) {
	return suc.multiplexer.GetStream(id)
}

// Close closes connection
func (suc *StreamUpConn) Close() error {
	suc.cancel()
	_ = suc.writer.Flush()
	return suc.multiplexer.Close()
}

// GetStatistics returns connection statistics
func (suc *StreamUpConn) GetStatistics() map[string]interface{} {
	suc.multiplexer.streamsMutex.RLock()
	activeStreams := len(suc.multiplexer.streams)
	suc.multiplexer.streamsMutex.RUnlock()

	uptime := time.Since(suc.startTime)

	return map[string]interface{}{
		"uptime_seconds":  uptime.Seconds(),
		"total_packets":   suc.totalPackets,
		"total_bytes":     suc.totalBytes,
		"active_streams":  activeStreams,
		"total_streams":   suc.multiplexer.totalStreams,
		"bytes_per_sec":   float64(suc.totalBytes) / uptime.Seconds(),
		"packets_per_sec": float64(suc.totalPackets) / uptime.Seconds(),
	}
}

// StreamUpServer manages stream-up mode connections
type StreamUpServer struct {
	listener          net.Listener
	config            *Config
	obfuscationConfig *ServerConfig
	activeConns       map[string]*StreamUpConn
	connsMutex        sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
}

// NewStreamUpServerWithConfig creates new stream-up server
func NewStreamUpServerWithConfig(config *Config, obfuscationConfig *ServerConfig) (*StreamUpServer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	return &StreamUpServer{
		config:            config,
		obfuscationConfig: obfuscationConfig,
		activeConns:       make(map[string]*StreamUpConn),
		ctx:               ctx,
		cancel:            cancel,
	}, nil
}

// Listen starts listening for stream-up connections
func (sus *StreamUpServer) Listen() error {
	listener, err := net.Listen("tcp", sus.config.Transport.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", sus.config.Transport.ListenAddr, err)
	}
	defer listener.Close()

	sus.listener = listener

	fmt.Printf("[XHTTP] Stream-up server listening on %s\n", sus.config.Transport.ListenAddr)

	for {
		select {
		case <-sus.ctx.Done():
			return sus.ctx.Err()
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		// Handle connection in goroutine
		go sus.handleConnection(conn)
	}
}

// handleConnection handles individual stream-up connection
func (sus *StreamUpServer) handleConnection(conn net.Conn) {
	streamUpConn := NewStreamUpConn(conn, sus.config)
	clientID := conn.RemoteAddr().String()

	sus.connsMutex.Lock()
	sus.activeConns[clientID] = streamUpConn
	sus.connsMutex.Unlock()

	defer func() {
		streamUpConn.Close()
		sus.connsMutex.Lock()
		delete(sus.activeConns, clientID)
		sus.connsMutex.Unlock()
	}()

	// Handle the stream-up connection
	if err := streamUpConn.HandleStreamUpConnection(sus.obfuscationConfig); err != nil {
		fmt.Printf("[XHTTP] Stream-up error from %s: %v\n", clientID, err)
	}
}

// Close closes server
func (sus *StreamUpServer) Close() error {
	sus.cancel()

	sus.connsMutex.Lock()
	for _, conn := range sus.activeConns {
		_ = conn.Close()
	}
	sus.connsMutex.Unlock()

	if sus.listener != nil {
		return sus.listener.Close()
	}

	return nil
}

// GetActiveConnections returns list of active stream-up connections
func (sus *StreamUpServer) GetActiveConnections() []map[string]interface{} {
	sus.connsMutex.RLock()
	defer sus.connsMutex.RUnlock()

	var result []map[string]interface{}
	for clientID, conn := range sus.activeConns {
		result = append(result, map[string]interface{}{
			"client_id": clientID,
			"stats":     conn.GetStatistics(),
		})
	}

	return result
}

// FrameBuilder helps construct XMUX frames
type FrameBuilder struct {
	streamID  uint32
	frameType FrameType
	buffer    []byte
}

// NewFrameBuilder creates new frame builder
func NewFrameBuilder(streamID uint32, frameType FrameType) *FrameBuilder {
	return &FrameBuilder{
		streamID:  streamID,
		frameType: frameType,
		buffer:    make([]byte, 0, 1024),
	}
}

// WithData adds data to frame
func (fb *FrameBuilder) WithData(data []byte) *FrameBuilder {
	fb.buffer = append(fb.buffer, data...)
	return fb
}

// WithInt32 adds 32-bit integer to frame (big-endian)
func (fb *FrameBuilder) WithInt32(value uint32) *FrameBuilder {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, value)
	fb.buffer = append(fb.buffer, buf...)
	return fb
}

// Build creates frame
func (fb *FrameBuilder) Build() *Frame {
	return &Frame{
		StreamID: fb.streamID,
		Type:     fb.frameType,
		Data:     fb.buffer,
	}
}

// WindowUpdateFrame creates window update frame for flow control
func NewWindowUpdateFrame(streamID, windowSize uint32) *Frame {
	return NewFrameBuilder(streamID, FrameTypeWindowUpdate).
		WithInt32(windowSize).
		Build()
}

// PingFrame creates ping frame
func NewPingFrame(streamID uint32) *Frame {
	return NewFrameBuilder(streamID, FrameTypePing).Build()
}

// DataFrameBuilder helps create data frames with chunking
type DataFrameBuilder struct {
	streamID  uint32
	chunkSize uint32
}

// NewDataFrameBuilder creates builder for chunked data frames
func NewDataFrameBuilder(streamID uint32, chunkSize uint32) *DataFrameBuilder {
	if chunkSize == 0 {
		chunkSize = 65536
	}

	return &DataFrameBuilder{
		streamID:  streamID,
		chunkSize: chunkSize,
	}
}

// ChunkData splits data into frames
func (dfb *DataFrameBuilder) ChunkData(data []byte) []*Frame {
	var frames []*Frame

	for i := 0; i < len(data); i += int(dfb.chunkSize) {
		end := i + int(dfb.chunkSize)
		if end > len(data) {
			end = len(data)
		}

		frame := &Frame{
			StreamID: dfb.streamID,
			Type:     FrameTypeData,
			Data:     data[i:end],
		}
		frames = append(frames, frame)
	}

	return frames
}
