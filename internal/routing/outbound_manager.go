package routing

import (
	"sync"
)

// OutboundManager управляет mapping между outbound tags и сессиями/серверами
type OutboundManager struct {
	outboundToSession map[string]uint32 // outbound tag -> session ID
	sessionToOutbound map[uint32]string // session ID -> outbound tag
	mu                sync.RWMutex
}

// NewOutboundManager создает новый менеджер outbound
func NewOutboundManager() *OutboundManager {
	return &OutboundManager{
		outboundToSession: make(map[string]uint32),
		sessionToOutbound: make(map[uint32]string),
	}
}

// RegisterOutbound регистрирует outbound tag для сессии
func (om *OutboundManager) RegisterOutbound(sessionID uint32, outboundTag string) {
	if outboundTag == "" {
		return
	}

	om.mu.Lock()
	defer om.mu.Unlock()

	// Удаляем старый mapping если был
	if oldTag, exists := om.sessionToOutbound[sessionID]; exists {
		delete(om.outboundToSession, oldTag)
	}

	// Удаляем старую сессию для этого outbound tag если была
	if oldSessionID, exists := om.outboundToSession[outboundTag]; exists {
		delete(om.sessionToOutbound, oldSessionID)
	}

	// Устанавливаем новый mapping
	om.outboundToSession[outboundTag] = sessionID
	om.sessionToOutbound[sessionID] = outboundTag
}

// UnregisterOutbound удаляет mapping для сессии
func (om *OutboundManager) UnregisterOutbound(sessionID uint32) {
	om.mu.Lock()
	defer om.mu.Unlock()

	if outboundTag, exists := om.sessionToOutbound[sessionID]; exists {
		delete(om.outboundToSession, outboundTag)
		delete(om.sessionToOutbound, sessionID)
	}
}

// GetDefaultOutboundSessionID возвращает session ID для "default" outbound, если он зарегистрирован
// Это соответствует подходу Clash/Mihomo - всегда есть явно зарегистрированный default outbound
func (om *OutboundManager) GetDefaultOutboundSessionID() (uint32, bool) {
	return om.GetSessionID("default")
}

// EnsureDefaultOutbound регистрирует сессию как "default" outbound, если default еще не зарегистрирован
// Это гарантирует, что всегда есть default outbound (как в Clash/Mihomo)
func (om *OutboundManager) EnsureDefaultOutbound(sessionID uint32) bool {
	om.mu.Lock()
	defer om.mu.Unlock()

	// Если default outbound уже зарегистрирован, не перезаписываем его
	if _, exists := om.outboundToSession["default"]; exists {
		return false
	}

	// Регистрируем эту сессию как default outbound
	om.outboundToSession["default"] = sessionID
	om.sessionToOutbound[sessionID] = "default"
	return true
}

// GetSessionID возвращает session ID для outbound tag
func (om *OutboundManager) GetSessionID(outboundTag string) (uint32, bool) {
	if outboundTag == "" {
		return 0, false
	}

	om.mu.RLock()
	defer om.mu.RUnlock()

	sessionID, exists := om.outboundToSession[outboundTag]
	return sessionID, exists
}

// GetOutboundTag возвращает outbound tag для session ID
func (om *OutboundManager) GetOutboundTag(sessionID uint32) (string, bool) {
	om.mu.RLock()
	defer om.mu.RUnlock()

	outboundTag, exists := om.sessionToOutbound[sessionID]
	return outboundTag, exists
}

// GetAllOutbounds возвращает все зарегистрированные outbound tags
func (om *OutboundManager) GetAllOutbounds() []string {
	om.mu.RLock()
	defer om.mu.RUnlock()

	outbounds := make([]string, 0, len(om.outboundToSession))
	for tag := range om.outboundToSession {
		outbounds = append(outbounds, tag)
	}
	return outbounds
}

// Clear очищает все mappings
func (om *OutboundManager) Clear() {
	om.mu.Lock()
	defer om.mu.Unlock()

	om.outboundToSession = make(map[string]uint32)
	om.sessionToOutbound = make(map[uint32]string)
}

// GetStats возвращает статистику outbound manager
func (om *OutboundManager) GetStats() map[string]interface{} {
	om.mu.RLock()
	defer om.mu.RUnlock()

	return map[string]interface{}{
		"outbound_count": len(om.outboundToSession),
		"session_count":  len(om.sessionToOutbound),
	}
}

