package policy

import (
	"sync"
	"time"
)

// Policy представляет политику для пользователя или сессии
type Policy struct {
	// Bandwidth limits
	MaxUploadSpeed   int64 // Максимальная скорость загрузки (байт/сек), 0 = без ограничений
	MaxDownloadSpeed int64 // Максимальная скорость скачивания (байт/сек), 0 = без ограничений
	MaxUploadBytes   int64 // Максимальный объем загрузки (байт), 0 = без ограничений
	MaxDownloadBytes int64 // Максимальный объем скачивания (байт), 0 = без ограничений
	
	// Connection limits
	MaxConnections      int           // Максимальное количество одновременных подключений, 0 = без ограничений
	MaxConnectionsPerIP int           // Максимальное количество подключений с одного IP, 0 = без ограничений
	
	// Time-based policies
	AllowedHours []TimeRange // Разрешенные часы работы (например, 9:00-18:00)
	AllowedDays  []time.Weekday // Разрешенные дни недели (например, [time.Monday, time.Tuesday, ...])
	
	// Expiration
	ExpiresAt *time.Time // Время истечения политики (nil = бессрочно)
	
	mu sync.RWMutex
}

// TimeRange представляет диапазон времени в течение дня
type TimeRange struct {
	Start time.Time // Время начала (используются только часы и минуты)
	End   time.Time // Время окончания (используются только часы и минуты)
}

// PolicyManager управляет политиками пользователей
type PolicyManager struct {
	policies map[string]*Policy // userID -> Policy
	mu       sync.RWMutex
}

// NewPolicyManager создает новый менеджер политик
func NewPolicyManager() *PolicyManager {
	return &PolicyManager{
		policies: make(map[string]*Policy),
	}
}

// SetPolicy устанавливает политику для пользователя
func (pm *PolicyManager) SetPolicy(userID string, policy *Policy) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.policies[userID] = policy
}

// GetPolicy возвращает политику пользователя
func (pm *PolicyManager) GetPolicy(userID string) *Policy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.policies[userID]
}

// RemovePolicy удаляет политику пользователя
func (pm *PolicyManager) RemovePolicy(userID string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.policies, userID)
}

// CheckBandwidthLimit проверяет, не превышен ли лимит пропускной способности
func (p *Policy) CheckBandwidthLimit(uploadBytes, downloadBytes int64) (uploadAllowed, downloadAllowed bool, uploadRemaining, downloadRemaining int64) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	// Проверяем лимиты объема
	if p.MaxUploadBytes > 0 {
		if uploadBytes >= p.MaxUploadBytes {
			return false, true, 0, p.MaxDownloadBytes - downloadBytes
		}
		uploadRemaining = p.MaxUploadBytes - uploadBytes
	} else {
		uploadRemaining = -1 // Без ограничений
	}
	
	if p.MaxDownloadBytes > 0 {
		if downloadBytes >= p.MaxDownloadBytes {
			return true, false, uploadRemaining, 0
		}
		downloadRemaining = p.MaxDownloadBytes - downloadBytes
	} else {
		downloadRemaining = -1 // Без ограничений
	}
	
	uploadAllowed = true
	downloadAllowed = true
	
	return
}

// CheckTimeBasedPolicy проверяет, разрешено ли использование в текущее время
func (p *Policy) CheckTimeBasedPolicy(now time.Time) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	// Проверяем истечение политики
	if p.ExpiresAt != nil && now.After(*p.ExpiresAt) {
		return false
	}
	
	// Проверяем дни недели
	if len(p.AllowedDays) > 0 {
		allowed := false
		for _, day := range p.AllowedDays {
			if now.Weekday() == day {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	
	// Проверяем часы работы
	if len(p.AllowedHours) > 0 {
		currentTime := time.Date(0, 1, 1, now.Hour(), now.Minute(), now.Second(), 0, time.UTC)
		allowed := false
		for _, tr := range p.AllowedHours {
			startTime := time.Date(0, 1, 1, tr.Start.Hour(), tr.Start.Minute(), tr.Start.Second(), 0, time.UTC)
			endTime := time.Date(0, 1, 1, tr.End.Hour(), tr.End.Minute(), tr.End.Second(), 0, time.UTC)
			
			// Обрабатываем случай, когда диапазон переходит через полночь
			if startTime.Before(endTime) {
				if currentTime.After(startTime) && currentTime.Before(endTime) {
					allowed = true
					break
				}
			} else {
				// Диапазон переходит через полночь (например, 22:00-06:00)
				if currentTime.After(startTime) || currentTime.Before(endTime) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			return false
		}
	}
	
	return true
}

// CheckConnectionLimit проверяет, не превышен ли лимит подключений
func (p *Policy) CheckConnectionLimit(currentConnections int) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	if p.MaxConnections > 0 && currentConnections >= p.MaxConnections {
		return false
	}
	
	return true
}

// NewPolicy создает новую политику с дефолтными значениями
func NewPolicy() *Policy {
	return &Policy{
		MaxUploadSpeed:   0, // Без ограничений
		MaxDownloadSpeed: 0, // Без ограничений
		MaxUploadBytes:   0, // Без ограничений
		MaxDownloadBytes: 0, // Без ограничений
		MaxConnections:   0, // Без ограничений
		MaxConnectionsPerIP: 0, // Без ограничений
		AllowedHours:     nil,
		AllowedDays:      nil,
		ExpiresAt:        nil,
	}
}

