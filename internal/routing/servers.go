package routing

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ServerConfig представляет конфигурацию сервера
type ServerConfig struct {
	Tag         string        `json:"tag"`         // Уникальный тег сервера
	Address     string        `json:"address"`     // Адрес сервера (host:port)
	Protocol    string        `json:"protocol"`    // Протокол: "udp", "tcp", "ws", "ws2"
	PublicKey   string        `json:"public_key"` // Публичный ключ сервера
	Enabled     bool          `json:"enabled"`    // Включен ли сервер
	Priority    int           `json:"priority"`   // Приоритет (для failover)
	Weight      int           `json:"weight"`     // Вес (для load-balance)
	LastCheck   time.Time     `json:"last_check"` // Время последней проверки
	Latency     time.Duration `json:"latency"`     // Задержка (для url-test)
	Available   bool          `json:"available"`   // Доступен ли сервер
	mu          sync.RWMutex
}

// ServerManager управляет множественными серверами
type ServerManager struct {
	servers map[string]*ServerConfig // tag -> server
	mu      sync.RWMutex
}

// NewServerManager создает новый менеджер серверов
func NewServerManager() *ServerManager {
	return &ServerManager{
		servers: make(map[string]*ServerConfig),
	}
}

// AddServer добавляет сервер
func (sm *ServerManager) AddServer(server *ServerConfig) error {
	if server.Tag == "" {
		return fmt.Errorf("server tag cannot be empty")
	}
	if server.Address == "" {
		return fmt.Errorf("server address cannot be empty")
	}

	// Валидация адреса
	if _, _, err := net.SplitHostPort(server.Address); err != nil {
		return fmt.Errorf("invalid server address: %w", err)
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.servers[server.Tag] = server
	return nil
}

// GetServer возвращает сервер по тегу
func (sm *ServerManager) GetServer(tag string) (*ServerConfig, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	server, exists := sm.servers[tag]
	return server, exists
}

// RemoveServer удаляет сервер
func (sm *ServerManager) RemoveServer(tag string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.servers, tag)
}

// GetAllServers возвращает все серверы
func (sm *ServerManager) GetAllServers() []*ServerConfig {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	servers := make([]*ServerConfig, 0, len(sm.servers))
	for _, server := range sm.servers {
		servers = append(servers, server)
	}
	return servers
}

// GetAvailableServers возвращает только доступные серверы
func (sm *ServerManager) GetAvailableServers() []*ServerConfig {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	servers := make([]*ServerConfig, 0)
	for _, server := range sm.servers {
		server.mu.RLock()
		if server.Enabled && server.Available {
			servers = append(servers, server)
		}
		server.mu.RUnlock()
	}
	return servers
}

// UpdateServerLatency обновляет задержку сервера
func (sm *ServerManager) UpdateServerLatency(tag string, latency time.Duration) {
	server, exists := sm.GetServer(tag)
	if !exists {
		return
	}

	server.mu.Lock()
	server.Latency = latency
	server.LastCheck = time.Now()
	server.Available = latency > 0 && latency < 10*time.Second // Считаем доступным если задержка < 10 сек
	server.mu.Unlock()
}

// SetServerAvailable устанавливает доступность сервера
func (sm *ServerManager) SetServerAvailable(tag string, available bool) {
	server, exists := sm.GetServer(tag)
	if !exists {
		return
	}

	server.mu.Lock()
	server.Available = available
	server.mu.Unlock()
}

// SelectServer выбирает сервер по стратегии
func (sm *ServerManager) SelectServer(strategy string) (*ServerConfig, error) {
	available := sm.GetAvailableServers()
	if len(available) == 0 {
		return nil, fmt.Errorf("no available servers")
	}

	switch strategy {
	case "fastest":
		// Выбираем самый быстрый
		return sm.selectFastest(available), nil
	case "priority":
		// Выбираем по приоритету
		return sm.selectByPriority(available), nil
	case "round-robin":
		// Round-robin
		return sm.selectRoundRobin(available), nil
	default:
		// По умолчанию - первый доступный
		return available[0], nil
	}
}

// selectFastest выбирает сервер с минимальной задержкой
func (sm *ServerManager) selectFastest(servers []*ServerConfig) *ServerConfig {
	if len(servers) == 0 {
		return nil
	}

	fastest := servers[0]
	minLatency := fastest.Latency

	for _, server := range servers[1:] {
		server.mu.RLock()
		latency := server.Latency
		server.mu.RUnlock()

		if latency > 0 && (minLatency == 0 || latency < minLatency) {
			minLatency = latency
			fastest = server
		}
	}

	return fastest
}

// selectByPriority выбирает сервер с наивысшим приоритетом
func (sm *ServerManager) selectByPriority(servers []*ServerConfig) *ServerConfig {
	if len(servers) == 0 {
		return nil
	}

	best := servers[0]
	maxPriority := best.Priority

	for _, server := range servers[1:] {
		server.mu.RLock()
		priority := server.Priority
		server.mu.RUnlock()

		if priority > maxPriority {
			maxPriority = priority
			best = server
		}
	}

	return best
}

// selectRoundRobin выбирает сервер по round-robin (упрощенная версия)
func (sm *ServerManager) selectRoundRobin(servers []*ServerConfig) *ServerConfig {
	if len(servers) == 0 {
		return nil
	}
	// Упрощенная версия - возвращаем первый
	// В полной реализации нужно хранить индекс
	return servers[0]
}

