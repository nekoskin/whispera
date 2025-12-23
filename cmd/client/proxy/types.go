package main

import (
	"net"
	"sync"
	"sync/atomic"
)

// Connection управляет проксируемым соединением
type Connection struct {
	ID       uint32
	Client   net.Conn
	Target   net.Conn
	DataChan chan []byte
	Closed   chan struct{}
}

// Manager управляет proxy соединениями
type Manager struct {
	connections map[uint32]*Connection
	mutex       sync.RWMutex // ОПТИМИЗАЦИЯ: Используем RWMutex для лучшей производительности при чтении
	seqCounter  uint32
}

// NewManager создает новый менеджер proxy соединений
func NewManager() *Manager {
	return &Manager{
		connections: make(map[uint32]*Connection),
		seqCounter:  1000000, // Начинаем с большого числа, чтобы не конфликтовать с TUN
	}
}

// AddConnection добавляет новое proxy соединение
func (m *Manager) AddConnection(conn *Connection) uint32 {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	conn.ID = atomic.AddUint32(&m.seqCounter, 1)
	m.connections[conn.ID] = conn
	return conn.ID
}

// GetConnection получает proxy соединение по ID
// ОПТИМИЗАЦИЯ: Используем RLock для чтения
func (m *Manager) GetConnection(proxyID uint32) (*Connection, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	conn, exists := m.connections[proxyID]
	return conn, exists
}

// RemoveConnection удаляет proxy соединение
func (m *Manager) RemoveConnection(proxyID uint32) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if conn, exists := m.connections[proxyID]; exists {
		delete(m.connections, proxyID)
		close(conn.Closed)
	}
}

// GetProxyConn реализует интерфейс ProxyConnLookup для dataplane
// ОПТИМИЗАЦИЯ: Используем RLock для чтения
func (m *Manager) GetProxyConn(proxyID uint32) (dataChan chan []byte, closed chan struct{}, exists bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	conn, exists := m.connections[proxyID]
	if exists {
		return conn.DataChan, conn.Closed, true
	}
	return nil, nil, false
}

