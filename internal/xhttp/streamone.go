package xhttp

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// StreamOneConn represents a single-shot stream-one connection
// Used for one request/response pair with automatic cleanup
type StreamOneConn struct {
	id                string
	conn              net.Conn
	config            *Config
	obfuscationConfig *ServerConfig

	// Request/Response handling
	request  *http.Request
	response []byte

	// State
	state  ConnState
	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc

	// Metadata
	createdAt    time.Time
	closedAt     time.Time
	bytesRead    uint64
	bytesWritten uint64
}

// StreamOneHandler handles stream-one mode HTTP requests
type StreamOneHandler struct {
	config            *Config
	obfuscationConfig *ServerConfig
	errorHandler      *ErrorHandler
	metadataRouter    *MetadataRouter
	connManager       sync.Map // map[string]*StreamOneConn
	connCounter       uint64
	mu                sync.RWMutex
}

// NewStreamOneHandler creates new stream-one handler
func NewStreamOneHandler(config *Config, obfuscationConfig *ServerConfig, errorHandler *ErrorHandler) *StreamOneHandler {
	soh := &StreamOneHandler{
		config:            config,
		obfuscationConfig: obfuscationConfig,
		errorHandler:      errorHandler,
		connManager:       sync.Map{},
	}

	// If package default metadata router is set, attach it
	if mr := GetDefaultMetadataRouter(); mr != nil {
		soh.SetMetadataRouter(mr)
	}

	return soh
}

// SetMetadataRouter sets metadata router for per-connection routing
func (soh *StreamOneHandler) SetMetadataRouter(router *MetadataRouter) {
	soh.mu.Lock()
	defer soh.mu.Unlock()
	soh.metadataRouter = router
}

// HandleRequest handles single stream-one HTTP request
// Stream-one: single request carries complete data, response has complete data
// No multiplexing, no flow control - simpler than stream-up
func (soh *StreamOneHandler) HandleRequest(w http.ResponseWriter, r *http.Request) {
	connID := fmt.Sprintf("streamone_%d", soh.getNextConnID())
	conn := &StreamOneConn{
		id:                connID,
		config:            soh.config,
		obfuscationConfig: soh.obfuscationConfig,
		state:             ConnStateOpen,
		createdAt:         time.Now(),
	}
	conn.ctx, conn.cancel = context.WithCancel(context.Background())
	defer conn.cancel()

	// Store connection
	soh.connManager.Store(connID, conn)
	defer soh.connManager.Delete(connID)

	// Detect mode from path
	if err := conn.processRequest(r); err != nil {
		soh.errorHandler.RecordError(&XHTTPError{
			Type:      ErrorTypeInvalidFrame,
			Message:   fmt.Sprintf("Failed to process request: %v", err),
			Timestamp: time.Now(),
			Retryable: false,
		})
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Handle based on mode
	switch r.Method {
	case http.MethodPost:
		soh.handlePost(w, r, conn)
	case http.MethodGet:
		soh.handleGet(w, r, conn)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}

	conn.closedAt = time.Now()
}

// handlePost handles POST request (upload mode)
func (soh *StreamOneHandler) handlePost(w http.ResponseWriter, r *http.Request, conn *StreamOneConn) {
	// Read entire request body
	data, err := io.ReadAll(r.Body)
	if err != nil {
		soh.recordError(&XHTTPError{
			Type:      ErrorTypeConnectionClosed,
			Message:   fmt.Sprintf("Failed to read request body: %v", err),
			Timestamp: time.Now(),
			Retryable: false,
		})
		http.Error(w, "Failed to read request", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	conn.bytesRead = uint64(len(data))

	// Decode hex-encoded packet data
	if len(data) > 2 && data[0] == '"' && data[len(data)-1] == '"' {
		data = data[1 : len(data)-1]
	}

	decodedData := make([]byte, hex.DecodedLen(len(data)))
	n, err := hex.Decode(decodedData, data)
	if err != nil {
		soh.recordError(&XHTTPError{
			Type:      ErrorTypeInvalidFrame,
			Message:   fmt.Sprintf("Failed to decode hex data: %v", err),
			Timestamp: time.Now(),
			Retryable: false,
		})
		http.Error(w, "Invalid hex encoding", http.StatusBadRequest)
		return
	}
	decodedData = decodedData[:n]

	// Extract metadata from headers if present
	var metadata *ExtraMetadata
	if extraJSON := r.Header.Get("X-Xhttp-Extra"); extraJSON != "" {
		if m, err := ParseExtraMetadata(extraJSON); err == nil {
			metadata = m
		}
	}

	// Process packet (application-specific logic here)
	response, err := soh.processPacket(decodedData, metadata)
	if err != nil {
		soh.recordError(&XHTTPError{
			Type:      ErrorTypeInternalServer,
			Message:   fmt.Sprintf("Failed to process packet: %v", err),
			Timestamp: time.Now(),
			Retryable: true,
		})
		http.Error(w, "Processing error", http.StatusInternalServerError)
		return
	}

	// Send response
	conn.response = response
	conn.bytesWritten = uint64(len(response))

	// Encode response as hex
	encodedResponse := hex.EncodeToString(response)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "\"%s\"", encodedResponse)
}

// handleGet handles GET request (download mode)
func (soh *StreamOneHandler) handleGet(w http.ResponseWriter, r *http.Request, conn *StreamOneConn) {
	// Stream-one GET: request body is path parameter or header
	// Could also support query parameters

	// Try to get data from X-Xhttp-Data header
	dataHex := r.Header.Get("X-Xhttp-Data")
	if dataHex == "" {
		// Try query parameter
		if val := r.URL.Query().Get("data"); val != "" {
			dataHex = val
		}
	}

	var decodedData []byte
	if dataHex != "" {
		var err error
		decodedData, err = hex.DecodeString(dataHex)
		if err != nil {
			soh.recordError(&XHTTPError{
				Type:      ErrorTypeInvalidFrame,
				Message:   fmt.Sprintf("Invalid hex data: %v", err),
				Timestamp: time.Now(),
				Retryable: false,
			})
			http.Error(w, "Invalid hex encoding", http.StatusBadRequest)
			return
		}
	}

	conn.bytesRead = uint64(len(decodedData))

	// Extract metadata
	var metadata *ExtraMetadata
	if extraJSON := r.Header.Get("X-Xhttp-Extra"); extraJSON != "" {
		if m, err := ParseExtraMetadata(extraJSON); err == nil {
			metadata = m
		}
	}

	// Process packet
	response, err := soh.processPacket(decodedData, metadata)
	if err != nil {
		soh.recordError(&XHTTPError{
			Type:      ErrorTypeInternalServer,
			Message:   fmt.Sprintf("Failed to process packet: %v", err),
			Timestamp: time.Now(),
			Retryable: true,
		})
		http.Error(w, "Processing error", http.StatusInternalServerError)
		return
	}

	conn.response = response
	conn.bytesWritten = uint64(len(response))

	// Encode response
	encodedResponse := hex.EncodeToString(response)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "\"%s\"", encodedResponse)
}

// processPacket processes XHTTP packet and returns response
// This is where application-specific logic would go
// For now, echo back the data
func (soh *StreamOneHandler) processPacket(data []byte, metadata *ExtraMetadata) ([]byte, error) {
	if metadata != nil && soh.metadataRouter != nil {
		// Route based on metadata
		target := soh.metadataRouter.Route(metadata)
		_ = target // Would be used for actual routing decision
	}

	// Simple echo response for now
	// In production, this would forward to destination or route based on metadata
	response := &bytes.Buffer{}
	response.Write([]byte("ACK:"))
	response.Write(data)

	return response.Bytes(), nil
}

// processRequest processes HTTP request and extracts metadata
func (conn *StreamOneConn) processRequest(r *http.Request) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.request = r
	return nil
}

// GetID returns connection ID
func (conn *StreamOneConn) GetID() string {
	conn.mu.RLock()
	defer conn.mu.RUnlock()
	return conn.id
}

// GetState returns connection state
func (conn *StreamOneConn) GetState() ConnState {
	conn.mu.RLock()
	defer conn.mu.RUnlock()
	return conn.state
}

// Close closes stream-one connection
func (conn *StreamOneConn) Close() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.state == ConnStateClosed {
		return nil
	}

	conn.state = ConnStateClosed
	conn.cancel()

	if conn.conn != nil {
		return conn.conn.Close()
	}
	return nil
}

// GetStats returns connection statistics
func (conn *StreamOneConn) GetStats() map[string]interface{} {
	conn.mu.RLock()
	defer conn.mu.RUnlock()

	return map[string]interface{}{
		"id":            conn.id,
		"state":         conn.state,
		"bytes_read":    conn.bytesRead,
		"bytes_written": conn.bytesWritten,
		"created_at":    conn.createdAt,
		"closed_at":     conn.closedAt,
		"duration_ms":   conn.closedAt.Sub(conn.createdAt).Milliseconds(),
	}
}

// getNextConnID gets next connection ID
func (soh *StreamOneHandler) getNextConnID() uint64 {
	soh.mu.Lock()
	defer soh.mu.Unlock()

	soh.connCounter++
	return soh.connCounter
}

// recordError records error
func (soh *StreamOneHandler) recordError(err *XHTTPError) {
	if soh.errorHandler != nil {
		soh.errorHandler.RecordError(err)
	}
}

// GetActiveConnectionCount returns number of active connections
func (soh *StreamOneHandler) GetActiveConnectionCount() int {
	count := 0
	soh.connManager.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// GetConnectionStats returns statistics for all connections
func (soh *StreamOneHandler) GetConnectionStats() []map[string]interface{} {
	var stats []map[string]interface{}
	soh.connManager.Range(func(key, value interface{}) bool {
		if conn, ok := value.(*StreamOneConn); ok {
			stats = append(stats, conn.GetStats())
		}
		return true
	})
	return stats
}
