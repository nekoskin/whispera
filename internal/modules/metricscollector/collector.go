// Package metricscollector provides the metrics collector module
package metricscollector

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
)

const (
	ModuleName    = "metrics.collector"
	ModuleVersion = "1.0.0"
)

// MetricType represents the type of metric
type MetricType int

const (
	MetricTypeCounter MetricType = iota
	MetricTypeGauge
	MetricTypeHistogram
)

// Config holds metrics collector configuration
type Config struct {
	Enabled       bool
	ListenAddr    string
	Path          string
	EnableRuntime bool
}

// DefaultConfig returns default metrics configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:       true,
		ListenAddr:    ":9090",
		Path:          "/metrics",
		EnableRuntime: true,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Path == "" {
		c.Path = "/metrics"
	}
	if c.ListenAddr == "" {
		c.ListenAddr = ":9090"
	}
	return nil
}

// metricDef holds metric definition
type metricDef struct {
	Name       string
	Help       string
	Type       MetricType
	LabelNames []string
}

// Collector implements interfaces.MetricsCollector
type Collector struct {
	*base.Module
	config *Config

	// Metric definitions
	defsMu      sync.RWMutex
	definitions map[string]*metricDef

	// Counter values
	countersMu sync.RWMutex
	counters   map[string]map[string]float64

	// Gauge values
	gaugesMu sync.RWMutex
	gauges   map[string]map[string]float64

	// Histogram values
	histogramsMu sync.RWMutex
	histograms   map[string]*histogram

	// HTTP server
	server *http.Server
}

// histogram holds histogram data
type histogram struct {
	buckets map[float64]uint64
	count   uint64
	sum     float64
}

// New creates a new metrics collector
func New(cfg *Config) (*Collector, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	c := &Collector{
		Module:      base.NewModule(ModuleName, ModuleVersion, nil),
		config:      cfg,
		definitions: make(map[string]*metricDef),
		counters:    make(map[string]map[string]float64),
		gauges:      make(map[string]map[string]float64),
		histograms:  make(map[string]*histogram),
	}

	c.registerDefaultMetrics()

	return c, nil
}

// registerDefaultMetrics registers built-in metrics
func (c *Collector) registerDefaultMetrics() {
	c.RegisterCounter("whispera_packets_received_total", "Total packets received", []string{"transport"})
	c.RegisterCounter("whispera_packets_sent_total", "Total packets sent", []string{"transport"})
	c.RegisterCounter("whispera_packets_dropped_total", "Total packets dropped", []string{"reason"})
	c.RegisterCounter("whispera_bytes_received_total", "Total bytes received", []string{"transport"})
	c.RegisterCounter("whispera_bytes_sent_total", "Total bytes sent", []string{"transport"})
	c.RegisterGauge("whispera_sessions_active", "Number of active sessions", nil)
	c.RegisterCounter("whispera_sessions_created_total", "Total sessions created", nil)
	c.RegisterCounter("whispera_handshakes_total", "Total handshakes", []string{"status"})
	c.RegisterCounter("whispera_errors_total", "Total errors", []string{"module", "type"})
}

// Init initializes the metrics collector
func (c *Collector) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := c.Module.Init(ctx, cfg); err != nil {
		return err
	}
	if metricsCfg, ok := cfg.(*Config); ok {
		c.config = metricsCfg
	}
	return nil
}

// Start starts the metrics collector
func (c *Collector) Start() error {
	if err := c.Module.Start(); err != nil {
		return err
	}

	if c.config.Enabled {
		mux := http.NewServeMux()
		mux.HandleFunc(c.config.Path, c.handleMetrics)
		mux.HandleFunc("/health", c.handleHealth)

		c.server = &http.Server{
			Addr:    c.config.ListenAddr,
			Handler: mux,
		}

		go func() {
			if err := c.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				c.SetHealthy(false, fmt.Sprintf("HTTP server error: %v", err))
			}
		}()
	}

	c.SetHealthy(true, fmt.Sprintf("metrics collector running on %s", c.config.ListenAddr))
	c.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"listen_addr": c.config.ListenAddr,
	})

	return nil
}

// Stop stops the metrics collector
func (c *Collector) Stop() error {
	if c.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c.server.Shutdown(ctx)
	}
	c.PublishEvent(events.EventTypeModuleStopped, nil)
	return c.Module.Stop()
}

// Increment increments a counter metric
func (c *Collector) Increment(name string, labels map[string]string) {
	c.Add(name, 1, labels)
}

// Add adds a value to a counter metric
func (c *Collector) Add(name string, value float64, labels map[string]string) {
	c.countersMu.Lock()
	defer c.countersMu.Unlock()

	if c.counters[name] == nil {
		c.counters[name] = make(map[string]float64)
	}
	key := labelsToKey(labels)
	c.counters[name][key] += value
}

// Observe observes a value for histogram metric
func (c *Collector) Observe(name string, value float64, labels map[string]string) {
	c.histogramsMu.Lock()
	defer c.histogramsMu.Unlock()

	h := c.histograms[name]
	if h == nil {
		return
	}
	h.count++
	h.sum += value
	for bucket := range h.buckets {
		if value <= bucket {
			h.buckets[bucket]++
		}
	}
}

// Set sets a gauge metric value
func (c *Collector) Set(name string, value float64, labels map[string]string) {
	c.gaugesMu.Lock()
	defer c.gaugesMu.Unlock()

	if c.gauges[name] == nil {
		c.gauges[name] = make(map[string]float64)
	}
	key := labelsToKey(labels)
	c.gauges[name][key] = value
}

// RegisterCounter registers a new counter metric
func (c *Collector) RegisterCounter(name, help string, labelNames []string) error {
	c.defsMu.Lock()
	defer c.defsMu.Unlock()
	c.definitions[name] = &metricDef{Name: name, Help: help, Type: MetricTypeCounter, LabelNames: labelNames}
	return nil
}

// RegisterGauge registers a new gauge metric
func (c *Collector) RegisterGauge(name, help string, labelNames []string) error {
	c.defsMu.Lock()
	defer c.defsMu.Unlock()
	c.definitions[name] = &metricDef{Name: name, Help: help, Type: MetricTypeGauge, LabelNames: labelNames}
	return nil
}

// RegisterHistogram registers a new histogram metric
func (c *Collector) RegisterHistogram(name, help string, labelNames []string, buckets []float64) error {
	c.defsMu.Lock()
	defer c.defsMu.Unlock()
	c.definitions[name] = &metricDef{Name: name, Help: help, Type: MetricTypeHistogram, LabelNames: labelNames}

	c.histogramsMu.Lock()
	c.histograms[name] = &histogram{buckets: make(map[float64]uint64)}
	for _, b := range buckets {
		c.histograms[name].buckets[b] = 0
	}
	c.histogramsMu.Unlock()
	return nil
}

func (c *Collector) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	c.countersMu.RLock()
	for name, values := range c.counters {
		for labels, value := range values {
			if labels != "" {
				fmt.Fprintf(w, "%s{%s} %g\n", name, labels, value)
			} else {
				fmt.Fprintf(w, "%s %g\n", name, value)
			}
		}
	}
	c.countersMu.RUnlock()

	c.gaugesMu.RLock()
	for name, values := range c.gauges {
		for labels, value := range values {
			if labels != "" {
				fmt.Fprintf(w, "%s{%s} %g\n", name, labels, value)
			} else {
				fmt.Fprintf(w, "%s %g\n", name, value)
			}
		}
	}
	c.gaugesMu.RUnlock()
}

func (c *Collector) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := c.HealthCheck()
	if status.Healthy {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK\n")
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "UNHEALTHY\n")
	}
}

// HealthCheck returns health status
func (c *Collector) HealthCheck() interfaces.HealthStatus {
	status := c.Module.HealthCheck()
	c.defsMu.RLock()
	status.Details["registered_metrics"] = len(c.definitions)
	c.defsMu.RUnlock()
	status.Details["listen_addr"] = c.config.ListenAddr
	return status
}

func labelsToKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	var result string
	first := true
	for k, v := range labels {
		if !first {
			result += ","
		}
		result += fmt.Sprintf("%s=\"%s\"", k, v)
		first = false
	}
	return result
}

// Factory creates metrics collector modules
func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
