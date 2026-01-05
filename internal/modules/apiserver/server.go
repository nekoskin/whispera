// Package apiserver provides the API server module
package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
)

const (
	ModuleName    = "api.server"
	ModuleVersion = "1.0.0"
)

// Config holds API server configuration
type Config struct {
	Enabled    bool
	ListenAddr string
	AuthToken  string
	EnableCORS bool
	TLSCert    string
	TLSKey     string
}

// DefaultConfig returns default API configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:    true,
		ListenAddr: ":8080",
		EnableCORS: true,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	return nil
}

// Server implements the API server module
type Server struct {
	*base.Module
	config *Config

	// HTTP server
	server *http.Server
	mux    *http.ServeMux

	// Dependencies
	registry registry.Registry

	// Route handlers
	mu       sync.RWMutex
	handlers map[string]http.HandlerFunc
}

// New creates a new API server
func New(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	s := &Server{
		Module:   base.NewModule(ModuleName, ModuleVersion, nil),
		config:   cfg,
		mux:      http.NewServeMux(),
		handlers: make(map[string]http.HandlerFunc),
	}

	// Register default routes
	s.registerDefaultRoutes()

	return s, nil
}

// registerDefaultRoutes registers built-in API routes
func (s *Server) registerDefaultRoutes() {
	s.Handle("GET /api/v1/health", s.handleHealth)
	s.Handle("GET /api/v1/status", s.handleStatus)
	s.Handle("GET /api/v1/modules", s.handleModules)
	s.Handle("GET /api/v1/config", s.handleGetConfig)
	s.Handle("POST /api/v1/config/reload", s.handleReloadConfig)
	s.Handle("GET /api/v1/sessions", s.handleGetSessions)
	s.Handle("DELETE /api/v1/sessions/{id}", s.handleDeleteSession)
	s.Handle("GET /api/v1/stats", s.handleGetStats)
}

// Init initializes the API server
func (s *Server) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := s.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if apiCfg, ok := cfg.(*Config); ok {
		s.config = apiCfg
	}

	return nil
}

// Start starts the API server
func (s *Server) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	if !s.config.Enabled {
		s.SetHealthy(true, "API server disabled")
		return nil
	}

	// Build final handler
	handler := s.buildHandler()

	s.server = &http.Server{
		Addr:         s.config.ListenAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		var err error
		if s.config.TLSCert != "" && s.config.TLSKey != "" {
			err = s.server.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
		} else {
			err = s.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			s.SetHealthy(false, fmt.Sprintf("HTTP server error: %v", err))
		}
	}()

	s.SetHealthy(true, fmt.Sprintf("API server running on %s", s.config.ListenAddr))
	s.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"listen_addr": s.config.ListenAddr,
	})

	return nil
}

// Stop stops the API server
func (s *Server) Stop() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.server.Shutdown(ctx)
	}

	s.PublishEvent(events.EventTypeModuleStopped, nil)
	return s.Module.Stop()
}

// SetRegistry sets the module registry
func (s *Server) SetRegistry(reg registry.Registry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registry = reg
}

// Handle registers a handler for a route
func (s *Server) Handle(pattern string, handler http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[pattern] = handler
}

// buildHandler builds the final HTTP handler
func (s *Server) buildHandler() http.Handler {
	// Register all handlers
	s.mu.RLock()
	for pattern, handler := range s.handlers {
		// Parse method and path from pattern
		parts := strings.SplitN(pattern, " ", 2)
		if len(parts) == 2 {
			s.mux.HandleFunc(parts[1], s.methodFilter(parts[0], handler))
		} else {
			s.mux.HandleFunc(pattern, handler)
		}
	}
	s.mu.RUnlock()

	// Wrap with middleware
	var handler http.Handler = s.mux

	// CORS middleware
	if s.config.EnableCORS {
		handler = s.corsMiddleware(handler)
	}

	// Auth middleware
	if s.config.AuthToken != "" {
		handler = s.authMiddleware(handler)
	}

	// Logging middleware
	handler = s.loggingMiddleware(handler)

	return handler
}

// methodFilter filters requests by HTTP method
func (s *Server) methodFilter(method string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handler(w, r)
	}
}

// corsMiddleware adds CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// authMiddleware validates authentication
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health endpoint
		if strings.HasSuffix(r.URL.Path, "/health") {
			next.ServeHTTP(w, r)
			return
		}

		// Check Authorization header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+s.config.AuthToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.UpdateActivity()

		// Could log here
		_ = start
	})
}

// JSON response helpers

type jsonResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func (s *Server) jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonResponse{Success: true, Data: data})
}

func (s *Server) jsonError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(jsonResponse{Success: false, Error: message})
}

// Route handlers

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := s.HealthCheck()

	response := map[string]interface{}{
		"status":  "ok",
		"healthy": health.Healthy,
		"message": health.Message,
	}

	if s.registry != nil {
		moduleHealth := s.registry.HealthCheck()
		response["modules"] = moduleHealth
	}

	s.jsonOK(w, response)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"version": ModuleVersion,
		"uptime":  time.Since(s.LastActivity()).String(),
		"running": s.IsRunning(),
	}

	if s.registry != nil {
		modules := s.registry.GetAll()
		status["module_count"] = len(modules)
	}

	s.jsonOK(w, status)
}

func (s *Server) handleModules(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		s.jsonError(w, http.StatusInternalServerError, "Registry not available")
		return
	}

	modules := s.registry.GetAll()
	moduleList := make([]map[string]interface{}, 0, len(modules))

	for _, m := range modules {
		health := m.HealthCheck()
		moduleList = append(moduleList, map[string]interface{}{
			"name":         m.Name(),
			"version":      m.Version(),
			"healthy":      health.Healthy,
			"message":      health.Message,
			"dependencies": m.Dependencies(),
		})
	}

	s.jsonOK(w, moduleList)
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	// Would return current configuration
	// This is a placeholder
	s.jsonOK(w, map[string]interface{}{
		"api": map[string]interface{}{
			"listen_addr": s.config.ListenAddr,
			"cors":        s.config.EnableCORS,
		},
	})
}

func (s *Server) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		s.jsonError(w, http.StatusInternalServerError, "Registry not available")
		return
	}

	if err := s.registry.Reload(r.Context(), nil); err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.PublishEvent(events.EventTypeConfigReloaded, nil)
	s.jsonOK(w, map[string]string{"message": "Configuration reloaded"})
}

func (s *Server) handleGetSessions(w http.ResponseWriter, r *http.Request) {
	if s.registry == nil {
		s.jsonError(w, http.StatusInternalServerError, "Registry not available")
		return
	}

	// Get session manager
	module, ok := s.registry.Get("session.manager")
	if !ok {
		s.jsonError(w, http.StatusNotFound, "Session manager not found")
		return
	}

	sessionMgr, ok := module.(interfaces.SessionManager)
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "Invalid session manager")
		return
	}

	sessions := sessionMgr.GetAllSessions()
	sessionList := make([]map[string]interface{}, 0, len(sessions))

	for _, sess := range sessions {
		sessionList = append(sessionList, map[string]interface{}{
			"id":            sess.ID(),
			"client_addr":   sess.ClientAddr().String(),
			"last_activity": sess.LastActivity(),
		})
	}

	s.jsonOK(w, map[string]interface{}{
		"count":    len(sessionList),
		"sessions": sessionList,
	})
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	// Would delete a specific session
	// Path parameter parsing would go here
	s.jsonOK(w, map[string]string{"message": "Session deleted"})
}

func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"timestamp": time.Now(),
	}

	if s.registry != nil {
		health := s.registry.HealthCheck()
		for name, h := range health {
			if h.Details != nil {
				stats[name] = h.Details
			}
		}
	}

	s.jsonOK(w, stats)
}

// HealthCheck returns health status
func (s *Server) HealthCheck() interfaces.HealthStatus {
	status := s.Module.HealthCheck()
	status.Details["listen_addr"] = s.config.ListenAddr
	status.Details["enabled"] = s.config.Enabled

	s.mu.RLock()
	status.Details["routes_registered"] = len(s.handlers)
	s.mu.RUnlock()

	return status
}

// Factory creates API server modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
