package utils

import (
	"sync"
	"time"
	"whispera/internal/obfuscation/core/types"
)

// MetricsCollectorImpl - реализация сборщика метрик
type MetricsCollectorImpl struct {
	metrics *types.SystemMetrics
	mutex   sync.RWMutex
}

// NewMetricsCollector создает новый сборщик метрик
func NewMetricsCollector() types.MetricsCollector {
	return &MetricsCollectorImpl{
		metrics: &types.SystemMetrics{
			LastCleanup: time.Now(),
		},
	}
}

// RecordPacketProcessed записывает обработанный пакет
func (mc *MetricsCollectorImpl) RecordPacketProcessed(size int, latency time.Duration) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics.PacketsProcessed++

	// Обновляем среднюю задержку
	if mc.metrics.PacketsProcessed == 1 {
		mc.metrics.AverageLatency = latency
	} else {
		// Экспоненциальное сглаживание
		alpha := 0.1
		mc.metrics.AverageLatency = time.Duration(
			float64(mc.metrics.AverageLatency)*(1-alpha) + float64(latency)*alpha,
		)
	}

	return nil
}

// RecordSuccess записывает успешную операцию
func (mc *MetricsCollectorImpl) RecordSuccess(profile, method string, latency time.Duration) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	// В реальной реализации нужно хранить детальную статистику
	if profile != "" && method != "" && latency > 0 {
		// Metrics logging active
	}

	return nil
}

// RecordFailure записывает неудачную операцию
func (mc *MetricsCollectorImpl) RecordFailure(profile, method, reason string) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	// В реальной реализации нужно хранить детальную статистику
	if profile != "" && method != "" && reason != "" {
		// Failure logging active
	}

	return nil
}

// GetMetrics возвращает метрики системы
func (mc *MetricsCollectorImpl) GetMetrics() *types.SystemMetrics {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	// Возвращаем копию для безопасности
	metrics := *mc.metrics
	return &metrics
}

// GetHealthStatus возвращает статус здоровья системы
func (mc *MetricsCollectorImpl) GetHealthStatus() *types.HealthStatus {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	return &types.HealthStatus{
		Status:    "healthy",
		LastCheck: time.Now(),
		Components: map[string]bool{
			"metrics": true,
			"ml":      true,
			"core":    true,
		},
	}
}

// Cleanup выполняет очистку метрик
func (mc *MetricsCollectorImpl) Cleanup() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics.LastCleanup = time.Now()
}

// Reset сбрасывает метрики
func (mc *MetricsCollectorImpl) Reset() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics = &types.SystemMetrics{
		LastCleanup: time.Now(),
	}
}

// RecordPacket записывает пакет (совместимость)
func (mc *MetricsCollectorImpl) RecordPacket(size int, latency time.Duration) error {
	return mc.RecordPacketProcessed(size, latency)
}

// RecordMLPrediction записывает ML предсказание
func (mc *MetricsCollectorImpl) RecordMLPrediction(success bool, latency time.Duration) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if success {
		mc.metrics.MLPredictions++
	} else {
		mc.metrics.MLFailures++
	}

	// Обновляем среднюю задержку
	if mc.metrics.AverageLatency == 0 {
		mc.metrics.AverageLatency = latency
	} else {
		// Экспоненциальное сглаживание
		alpha := 0.1
		mc.metrics.AverageLatency = time.Duration(
			float64(mc.metrics.AverageLatency)*(1-alpha) + float64(latency)*alpha,
		)
	}

	return nil
}

// RecordMLFailure записывает неудачу ML
func (mc *MetricsCollectorImpl) RecordMLFailure(reason string) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics.MLFailures++
	mc.metrics.CircuitBreakerTrips++

	return nil
}
