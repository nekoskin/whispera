// Package selector provides transport selection with ML and manual control
package selector

import (
	"context"
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
	ModuleName    = "transport.selector"
	ModuleVersion = "1.0.0"
)

// SelectionMode defines how transport is selected
type SelectionMode string

const (
	ModeAuto   SelectionMode = "auto"   // ML-based selection
	ModeManual SelectionMode = "manual" // Manual override
)

// NetworkContext provides context for transport selection
type NetworkContext struct {
	DestinationAddr string
	Latency         time.Duration
	Bandwidth       float64 // bytes/sec
	PacketLoss      float64 // 0.0 - 1.0
	IsBlocked       map[interfaces.TransportType]bool
	ThreatLevel     int // 0-10
	StealthRequired bool
}

// TransportMetrics holds performance metrics for a transport
type TransportMetrics struct {
	Type        interfaces.TransportType
	Latency     time.Duration
	Bandwidth   float64
	PacketLoss  float64
	Connections int64
	Errors      int64
	LastUsed    time.Time
	Score       float64 // Computed selection score
}

// Config holds selector configuration
type Config struct {
	DefaultTransport  interfaces.TransportType
	Mode              SelectionMode
	MLWeight          float64 // 0.0 - 1.0, weight for ML vs heuristics
	LatencyWeight     float64
	BandwidthWeight   float64
	StealthWeight     float64
	ReliabilityWeight float64
}

// DefaultConfig returns default selector configuration
func DefaultConfig() *Config {
	return &Config{
		DefaultTransport:  interfaces.TransportUDP,
		Mode:              ModeAuto,
		MLWeight:          0.5,
		LatencyWeight:     0.25,
		BandwidthWeight:   0.25,
		StealthWeight:     0.25,
		ReliabilityWeight: 0.25,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Normalize weights to sum to 1.0
	totalWeight := c.LatencyWeight + c.BandwidthWeight + c.StealthWeight + c.ReliabilityWeight
	if totalWeight <= 0 {
		c.LatencyWeight = 0.25
		c.BandwidthWeight = 0.25
		c.StealthWeight = 0.25
		c.ReliabilityWeight = 0.25
	}
	if c.MLWeight < 0 || c.MLWeight > 1 {
		c.MLWeight = 0.5
	}
	return nil
}

// Selector manages multiple transports with intelligent selection
type Selector struct {
	*base.Module
	config     *Config
	mu         sync.RWMutex
	transports map[interfaces.TransportType]interfaces.Transport
	metrics    map[interfaces.TransportType]*TransportMetrics
	preferred  interfaces.TransportType
	mlEnabled  bool

	// Stats
	selections uint64
	mlUsed     uint64
	manualUsed uint64
}

// New creates a new transport selector
func New(cfg *Config) (*Selector, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	s := &Selector{
		Module:     base.NewModule(ModuleName, ModuleVersion, nil),
		config:     cfg,
		transports: make(map[interfaces.TransportType]interfaces.Transport),
		metrics:    make(map[interfaces.TransportType]*TransportMetrics),
		preferred:  cfg.DefaultTransport,
		mlEnabled:  cfg.Mode == ModeAuto,
	}

	return s, nil
}

// Init initializes the selector
func (s *Selector) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := s.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if selectorCfg, ok := cfg.(*Config); ok {
		s.config = selectorCfg
	}

	return nil
}

// Start starts the selector
func (s *Selector) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	// Initialize metrics for all registered transports
	s.mu.Lock()
	for t := range s.transports {
		if _, exists := s.metrics[t]; !exists {
			s.metrics[t] = &TransportMetrics{
				Type:     t,
				LastUsed: time.Now(),
			}
		}
	}
	s.mu.Unlock()

	// Start metrics collection loop
	go s.metricsLoop()

	s.SetHealthy(true, fmt.Sprintf("mode=%s, default=%s", s.config.Mode, s.config.DefaultTransport))
	s.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"mode":      s.config.Mode,
		"default":   s.config.DefaultTransport,
		"ml_weight": s.config.MLWeight,
	})

	return nil
}

// Stop stops the selector
func (s *Selector) Stop() error {
	s.PublishEvent(events.EventTypeModuleStopped, nil)
	return s.Module.Stop()
}

// RegisterTransport registers a transport
func (s *Selector) RegisterTransport(t interfaces.Transport) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	transportType := t.Type()
	s.transports[transportType] = t
	s.metrics[transportType] = &TransportMetrics{
		Type:     transportType,
		LastUsed: time.Now(),
	}

	return nil
}

// SetMode sets the selection mode
func (s *Selector) SetMode(mode SelectionMode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.Mode = mode
	s.mlEnabled = mode == ModeAuto
}

// SetPreferred sets the preferred transport for manual mode
func (s *Selector) SetPreferred(t interfaces.TransportType) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.transports[t]; !exists {
		return fmt.Errorf("transport %s not registered", t)
	}

	s.preferred = t
	return nil
}

// Select selects the best transport based on context
func (s *Selector) Select(ctx *NetworkContext) (interfaces.Transport, error) {
	atomic.AddUint64(&s.selections, 1)

	s.mu.RLock()
	mode := s.config.Mode
	preferred := s.preferred
	s.mu.RUnlock()

	if mode == ModeManual {
		atomic.AddUint64(&s.manualUsed, 1)
		return s.getTransport(preferred)
	}

	// Auto mode - use ML scoring
	atomic.AddUint64(&s.mlUsed, 1)
	return s.autoSelect(ctx)
}

// autoSelect uses ML-based scoring to select transport
func (s *Selector) autoSelect(ctx *NetworkContext) (interfaces.Transport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var bestTransport interfaces.TransportType
	var bestScore float64 = -1

	for t, metrics := range s.metrics {
		// Skip blocked transports
		if ctx != nil && ctx.IsBlocked[t] {
			continue
		}

		// Check if transport is registered
		if _, exists := s.transports[t]; !exists {
			continue
		}

		score := s.calculateScore(t, metrics, ctx)
		if score > bestScore {
			bestScore = score
			bestTransport = t
		}
	}

	if bestScore < 0 {
		return nil, fmt.Errorf("no suitable transport available")
	}

	// Update last used
	if m, exists := s.metrics[bestTransport]; exists {
		m.LastUsed = time.Now()
	}

	return s.transports[bestTransport], nil
}

// calculateScore calculates the selection score for a transport
func (s *Selector) calculateScore(t interfaces.TransportType, m *TransportMetrics, ctx *NetworkContext) float64 {
	var score float64

	// Base scores by transport type (stealth factor)
	stealthScores := map[interfaces.TransportType]float64{
		interfaces.TransportUDP:       0.3, // Less stealthy
		interfaces.TransportTCP:       0.6, // More common
		interfaces.TransportWebSocket: 0.8, // Looks like web traffic
		interfaces.TransportXHTTP:     0.9, // Very stealthy
		interfaces.TransportQUIC:      0.7, // Good but detectable
		interfaces.TransportH2C:       0.8, // Mimics HTTP/2
	}

	// Latency scores (lower is better)
	latencyScores := map[interfaces.TransportType]float64{
		interfaces.TransportUDP:       1.0,  // Fastest
		interfaces.TransportQUIC:      0.9,  // Very fast
		interfaces.TransportTCP:       0.7,  // Good
		interfaces.TransportWebSocket: 0.6,  // Overhead
		interfaces.TransportXHTTP:     0.5,  // More overhead
		interfaces.TransportH2C:       0.75, // Good efficiency
	}

	// Bandwidth scores
	bandwidthScores := map[interfaces.TransportType]float64{
		interfaces.TransportUDP:       1.0,
		interfaces.TransportQUIC:      0.95,
		interfaces.TransportTCP:       0.85,
		interfaces.TransportWebSocket: 0.75,
		interfaces.TransportXHTTP:     0.7,
		interfaces.TransportH2C:       0.8,
	}

	// Reliability scores
	reliabilityScores := map[interfaces.TransportType]float64{
		interfaces.TransportTCP:       1.0, // Most reliable
		interfaces.TransportQUIC:      0.95,
		interfaces.TransportWebSocket: 0.9,
		interfaces.TransportXHTTP:     0.85,
		interfaces.TransportUDP:       0.7, // Less reliable
		interfaces.TransportH2C:       0.95,
	}

	// Calculate weighted score
	stealth := stealthScores[t]
	latency := latencyScores[t]
	bandwidth := bandwidthScores[t]
	reliability := reliabilityScores[t]

	// Apply context adjustments
	if ctx != nil {
		if ctx.StealthRequired {
			stealth *= 1.5 // Boost stealth importance
		}
		if ctx.ThreatLevel > 7 {
			stealth *= 2.0 // High threat = prioritize stealth
		}
	}

	// Apply metrics from actual measurements
	if m.Latency > 0 {
		// Adjust latency score based on actual latency
		latencyPenalty := float64(m.Latency.Milliseconds()) / 1000.0
		if latencyPenalty > 1 {
			latencyPenalty = 1
		}
		latency *= (1 - latencyPenalty*0.5)
	}

	if m.PacketLoss > 0 {
		reliability *= (1 - m.PacketLoss)
	}

	if m.Bandwidth > 0 {
		// Normalize to 0-1 range (assume 100MB/s is max)
		bwNorm := m.Bandwidth / (100 * 1024 * 1024)
		if bwNorm > 1 {
			bwNorm = 1
		}
		bandwidth *= bwNorm
	}

	// Weighted sum
	score = s.config.StealthWeight*stealth +
		s.config.LatencyWeight*latency +
		s.config.BandwidthWeight*bandwidth +
		s.config.ReliabilityWeight*reliability

	m.Score = score
	return score
}

// getTransport returns specific transport
func (s *Selector) getTransport(t interfaces.TransportType) (interfaces.Transport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	transport, exists := s.transports[t]
	if !exists {
		return nil, fmt.Errorf("transport %s not registered", t)
	}

	return transport, nil
}

// GetTransport returns a specific transport by type
func (s *Selector) GetTransport(t interfaces.TransportType) (interfaces.Transport, error) {
	return s.getTransport(t)
}

// Dial uses selected transport to dial
func (s *Selector) Dial(ctx context.Context, addr string, netCtx *NetworkContext) (net.Conn, error) {
	transport, err := s.Select(netCtx)
	if err != nil {
		return nil, err
	}
	return transport.Dial(ctx, addr)
}

// UpdateMetrics updates metrics for a transport
func (s *Selector) UpdateMetrics(t interfaces.TransportType, latency time.Duration, bandwidth float64, packetLoss float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if m, exists := s.metrics[t]; exists {
		m.Latency = latency
		m.Bandwidth = bandwidth
		m.PacketLoss = packetLoss
	}
}

// metricsLoop periodically updates transport metrics
func (s *Selector) metricsLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for s.IsRunning() {
		<-ticker.C
		s.collectMetrics()
	}
}

// collectMetrics collects metrics from all transports
func (s *Selector) collectMetrics() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for t, transport := range s.transports {
		health := transport.HealthCheck()
		if m, exists := s.metrics[t]; exists {
			// Extract metrics from health details
			if conns, ok := health.Details["active_conns"].(int64); ok {
				m.Connections = conns
			}
			if errors, ok := health.Details["accept_errors"].(uint64); ok {
				m.Errors = int64(errors)
			}
		}
	}
}

// HealthCheck returns detailed health status
func (s *Selector) HealthCheck() interfaces.HealthStatus {
	status := s.Module.HealthCheck()

	s.mu.RLock()
	status.Details["mode"] = s.config.Mode
	status.Details["preferred"] = s.preferred
	status.Details["transport_count"] = len(s.transports)
	status.Details["selections"] = atomic.LoadUint64(&s.selections)
	status.Details["ml_used"] = atomic.LoadUint64(&s.mlUsed)
	status.Details["manual_used"] = atomic.LoadUint64(&s.manualUsed)
	s.mu.RUnlock()

	return status
}

// GetMetrics returns all transport metrics
func (s *Selector) GetMetrics() map[interfaces.TransportType]*TransportMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[interfaces.TransportType]*TransportMetrics)
	for t, m := range s.metrics {
		copy := *m
		result[t] = &copy
	}
	return result
}

// Factory creates transport selector modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
