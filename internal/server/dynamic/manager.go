package dynamic

import (
	"fmt"
	"log"
	"net"
	"sync"

	"whispera/internal/modules/config"
)

type Manager struct {
	mu        sync.RWMutex
	listeners map[string]net.Listener

	startCallback func(config.InboundConfig) error
	stopCallback  func(string) error
}

func New() *Manager {
	return &Manager{
		listeners: make(map[string]net.Listener),
	}
}

func (m *Manager) SetCallbacks(start func(config.InboundConfig) error, stop func(string) error) {
	m.startCallback = start
	m.stopCallback = stop
}

func (m *Manager) StartInbound(inbound config.InboundConfig) error {
	if m.startCallback == nil {
		return fmt.Errorf("start callback not set")
	}

	log.Printf("[DynamicManager] Starting inbound %s on port %d", inbound.Tag, inbound.Port)
	return m.startCallback(inbound)
}

func (m *Manager) StopInbound(tag string) error {
	if m.stopCallback == nil {
		return fmt.Errorf("stop callback not set")
	}

	log.Printf("[DynamicManager] Stopping inbound %s", tag)
	return m.stopCallback(tag)
}

func (m *Manager) IsRunning(tag string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.listeners[tag]
	return exists
}

func (m *Manager) RegisterListener(tag string, listener net.Listener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners[tag] = listener
}

func (m *Manager) UnregisterListener(tag string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.listeners, tag)
}

var Global *Manager

func init() {
	Global = New()
}
