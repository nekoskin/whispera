// Package dynamic provides dynamic inbound management without server restart
package dynamic

import (
	"fmt"
	"log"
	"net"
	"sync"

	"whispera/internal/modules/config"
)

// Manager manages dynamic inbound listeners
type Manager struct {
	mu        sync.RWMutex
	listeners map[string]net.Listener // key: inbound tag

	// Callbacks
	startCallback func(config.InboundConfig) error
	stopCallback  func(string) error
}

// New creates a new dynamic inbound manager
func New() *Manager {
	return &Manager{
		listeners: make(map[string]net.Listener),
	}
}

// SetCallbacks sets the start/stop callbacks (called from main.go)
func (m *Manager) SetCallbacks(start func(config.InboundConfig) error, stop func(string) error) {
	m.startCallback = start
	m.stopCallback = stop
}

// StartInbound starts a new inbound listener
func (m *Manager) StartInbound(inbound config.InboundConfig) error {
	if m.startCallback == nil {
		return fmt.Errorf("start callback not set")
	}

	log.Printf("[DynamicManager] Starting inbound %s on port %d", inbound.Tag, inbound.Port)
	return m.startCallback(inbound)
}

// StopInbound stops an inbound listener
func (m *Manager) StopInbound(tag string) error {
	if m.stopCallback == nil {
		return fmt.Errorf("stop callback not set")
	}

	log.Printf("[DynamicManager] Stopping inbound %s", tag)
	return m.stopCallback(tag)
}

// IsRunning checks if an inbound is currently running
func (m *Manager) IsRunning(tag string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.listeners[tag]
	return exists
}

// RegisterListener registers a listener (called by main.go after starting)
func (m *Manager) RegisterListener(tag string, listener net.Listener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners[tag] = listener
}

// UnregisterListener unregisters a listener
func (m *Manager) UnregisterListener(tag string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.listeners, tag)
}

// Global instance
var Global *Manager

func init() {
	Global = New()
}
