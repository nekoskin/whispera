package monitoring

import (
	"time"
)

// updateMetrics обновляет метрики производительности
func (am *AdaptiveMonitor) updateMetrics() {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Обновляем метрики (в реальной реализации здесь был бы сбор реальных метрик)
	am.metrics.LastUpdate = time.Now()

	// Симуляция обновления метрик
	am.metrics.PacketsSent++
	am.metrics.BytesSent += 1024
	am.metrics.Latency = time.Duration(50+time.Now().UnixNano()%100) * time.Millisecond
	am.metrics.Throughput = 1024 * 1024 // 1MB/s
	am.metrics.CPUUsage = 15.0 + float64(time.Now().UnixNano()%10)
	am.metrics.MemoryUsage = 50 * 1024 * 1024 // 50MB
}

// analyzeEffectiveness анализирует эффективность обхода блокировок
func (am *AdaptiveMonitor) analyzeEffectiveness() {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Анализируем эффективность на основе метрик
	totalAttempts := am.effectiveness.BlockedAttempts + am.effectiveness.SuccessfulAttempts
	if totalAttempts > 0 {
		am.effectiveness.BypassSuccessRate = float64(am.effectiveness.SuccessfulAttempts) / float64(totalAttempts)
	}

	// Обновляем уровень угрозы
	if am.effectiveness.BypassSuccessRate < 0.5 {
		am.effectiveness.ThreatLevel = 8
	} else if am.effectiveness.BypassSuccessRate < 0.7 {
		am.effectiveness.ThreatLevel = 6
	} else if am.effectiveness.BypassSuccessRate < 0.9 {
		am.effectiveness.ThreatLevel = 4
	} else {
		am.effectiveness.ThreatLevel = 2
	}

	// Обновляем анализатор сети
	am.analyzer.UpdateThreatLevel(am.effectiveness.ThreatLevel)
}

// RecordSuccess записывает успешный обход блокировки
func (am *AdaptiveMonitor) RecordSuccess() {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.effectiveness.SuccessfulAttempts++
}

// RecordBlocked записывает заблокированную попытку
func (am *AdaptiveMonitor) RecordBlocked() {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.effectiveness.BlockedAttempts++
}

// RecordDetection записывает событие детекции
func (am *AdaptiveMonitor) RecordDetection() {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.effectiveness.DetectionEvents++
	am.effectiveness.LastDetection = time.Now()
}

// GetMetrics возвращает текущие метрики
func (am *AdaptiveMonitor) GetMetrics() *PerformanceMetrics {
	am.mu.RLock()
	defer am.mu.RUnlock()

	// Возвращаем копию метрик
	metrics := *am.metrics
	return &metrics
}

// GetEffectiveness возвращает данные об эффективности
func (am *AdaptiveMonitor) GetEffectiveness() *EffectivenessTracker {
	am.mu.RLock()
	defer am.mu.RUnlock()

	// Возвращаем копию данных об эффективности
	effectiveness := *am.effectiveness
	return &effectiveness
}
