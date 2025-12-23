package xhttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// HTTPListener represents XHTTP HTTP-level listener
// Handles packet-up, stream-up, and stream-one modes
type HTTPListener struct {
	addr              string
	sessionManager    *SessionManager
	server            *http.Server
	obfuscationConfig *ServerConfig

	// Mode configuration
	Mode string // "packet-up", "stream-up", or "stream-one"

	// Connection handling
	connectionsMutex  sync.RWMutex
	activeConnections map[string]net.Conn
}

// NewHTTPListener creates new XHTTP HTTP listener
func NewHTTPListener(
	addr string,
	obfuscationConfig *ServerConfig,
	mode string,
) *HTTPListener {
	sessionManager := NewSessionManager(
		10000,          // Max 10K simultaneous sessions
		10*time.Minute, // Session timeout 10 minutes
	)

	listener := &HTTPListener{
		addr:              addr,
		sessionManager:    sessionManager,
		obfuscationConfig: obfuscationConfig,
		Mode:              mode,
		activeConnections: make(map[string]net.Conn),
	}

	// Setup HTTP routes based on mode
	listener.setupRoutes()

	return listener
}

// setupRoutes configures HTTP routes based on mode
func (hl *HTTPListener) setupRoutes() {
	mux := http.NewServeMux()
	handler := NewHTTPPacketUpHandler(hl.sessionManager)

	// Routes for packet-up mode
	mux.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handler.HandlePOSTRequest(w, r)
		} else {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			handler.HandleGETRequest(w, r)
		} else {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	// Generic route for both POST and GET
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handler.HandlePOSTRequest(w, r)
		} else if r.Method == http.MethodGet {
			handler.HandleGETRequest(w, r)
		} else {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	hl.server = &http.Server{
		Addr:           hl.addr,
		Handler:        mux,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}
}

// Listen starts listening for HTTP connections
func (hl *HTTPListener) Listen(ctx context.Context) error {
	listener, err := net.Listen("tcp", hl.addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", hl.addr, err)
	}
	defer listener.Close()

	// Wrap with obfuscation
	obfuscatedListener := &ObfuscatedListener{
		listener: listener,
		config:   hl.obfuscationConfig,
	}

	// Start HTTP server
	errChan := make(chan error, 1)
	go func() {
		if err := hl.server.Serve(obfuscatedListener); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		hl.server.Close()
		return ctx.Err()
	case err := <-errChan:
		return err
	}
}

// ObfuscatedListener wraps net.Listener with obfuscation
type ObfuscatedListener struct {
	listener net.Listener
	config   *ServerConfig
}

// Accept accepts connection and applies obfuscation
func (ol *ObfuscatedListener) Accept() (net.Conn, error) {
	conn, err := ol.listener.Accept()
	if err != nil {
		return nil, err
	}

	// Apply XHTTP obfuscation
	obfuscatedConn, err := ol.config.HandleConn(context.Background(), conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return obfuscatedConn, nil
}

// Close closes the listener
func (ol *ObfuscatedListener) Close() error {
	return ol.listener.Close()
}

// Addr returns listener address
func (ol *ObfuscatedListener) Addr() net.Addr {
	return ol.listener.Addr()
}

// PacketUpDataPlane handles packet-up mode data plane
// Bridges HTTP packet-up sessions with actual traffic
type PacketUpDataPlane struct {
	sessionManager *SessionManager
	handlers       map[string]DataPlaneHandler
	handlersMutex  sync.RWMutex
}

// DataPlaneHandler handles data plane operations
type DataPlaneHandler interface {
	// HandlePacket processes incoming packet from session
	HandlePacket(ctx context.Context, packet []byte) (response []byte, err error)

	// GetPendingData returns data waiting to be sent to client
	GetPendingData(ctx context.Context, maxSize int64) ([]byte, error)
}

// NewPacketUpDataPlane creates new data plane handler
func NewPacketUpDataPlane(sessionManager *SessionManager) *PacketUpDataPlane {
	return &PacketUpDataPlane{
		sessionManager: sessionManager,
		handlers:       make(map[string]DataPlaneHandler),
	}
}

// RegisterHandler registers data plane handler for session
func (pdp *PacketUpDataPlane) RegisterHandler(sessionUUID string, handler DataPlaneHandler) {
	pdp.handlersMutex.Lock()
	defer pdp.handlersMutex.Unlock()
	pdp.handlers[sessionUUID] = handler
}

// UnregisterHandler unregisters data plane handler
func (pdp *PacketUpDataPlane) UnregisterHandler(sessionUUID string) {
	pdp.handlersMutex.Lock()
	defer pdp.handlersMutex.Unlock()
	delete(pdp.handlers, sessionUUID)
}

// ProcessIncoming processes incoming packets from HTTP POST
func (pdp *PacketUpDataPlane) ProcessIncoming(ctx context.Context, sessionUUID string, packets [][]byte) error {
	pdp.handlersMutex.RLock()
	handler, exists := pdp.handlers[sessionUUID]
	pdp.handlersMutex.RUnlock()

	if !exists {
		return fmt.Errorf("no handler for session %s", sessionUUID)
	}

	for _, packet := range packets {
		_, err := handler.HandlePacket(ctx, packet)
		if err != nil {
			return err
		}
	}

	return nil
}

// ProcessOutgoing gets outgoing data for HTTP GET response
func (pdp *PacketUpDataPlane) ProcessOutgoing(ctx context.Context, sessionUUID string, maxSize int64) ([]byte, error) {
	pdp.handlersMutex.RLock()
	handler, exists := pdp.handlers[sessionUUID]
	pdp.handlersMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no handler for session %s", sessionUUID)
	}

	return handler.GetPendingData(ctx, maxSize)
}

// HTTPMuxer multiplexes multiple XHTTP modes on single listener
// Detects mode from path and routes accordingly
type HTTPMuxer struct {
	packetUpHandler *HTTPPacketUpHandler
	sessionManager  *SessionManager
}

// NewHTTPMuxer creates new HTTP muxer
func NewHTTPMuxer(sessionManager *SessionManager) *HTTPMuxer {
	return &HTTPMuxer{
		packetUpHandler: NewHTTPPacketUpHandler(sessionManager),
		sessionManager:  sessionManager,
	}
}

// ServeHTTP routes request based on method and path
func (m *HTTPMuxer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Detect mode from request method
	if r.Method == http.MethodPost {
		// POST - handle as packet submission
		m.packetUpHandler.HandlePOSTRequest(w, r)
	} else if r.Method == http.MethodGet {
		// GET - handle as packet retrieval
		m.packetUpHandler.HandleGETRequest(w, r)
	} else if r.Method == http.MethodOptions {
		// CORS preflight
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Session-ID")
		w.WriteHeader(http.StatusOK)
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// Statistics tracks listener statistics
type Statistics struct {
	TotalConnections  int64
	ActiveConnections int64
	ActiveSessions    int64
	TotalPackets      int64
	TotalBytes        int64
	TotalErrors       int64
	LastUpdated       time.Time
}

// GetStatistics returns listener statistics
func (hl *HTTPListener) GetStatistics() Statistics {
	hl.connectionsMutex.RLock()
	activeConnections := int64(len(hl.activeConnections))
	hl.connectionsMutex.RUnlock()

	hl.sessionManager.mutex.RLock()
	activeSessions := int64(len(hl.sessionManager.sessions))
	hl.sessionManager.mutex.RUnlock()

	return Statistics{
		ActiveConnections: activeConnections,
		ActiveSessions:    activeSessions,
		LastUpdated:       time.Now(),
	}
}
