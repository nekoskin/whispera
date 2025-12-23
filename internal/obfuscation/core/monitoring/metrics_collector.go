package monitoring

import (
	"fmt"
	"sync"
	"time"
	"whispera/internal/obfuscation/core/types"
)

// MetricsCollector - сборщик метрик системы
type MetricsCollector struct {
	metrics *types.SystemMetrics
	mutex   sync.RWMutex
}

// NewMetricsCollector создает новый сборщик метрик
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		metrics: &types.SystemMetrics{
			LastCleanup: time.Now(),
		},
	}
}

// RecordPacket обрабатывает запись о пакете
func (mc *MetricsCollector) RecordPacket(inputSize, outputSize int, latency time.Duration) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics.PacketsProcessed++
	mc.updateAverageLatency(latency)
	mc.updateMemoryUsage(int64(outputSize - inputSize))
}

// RecordMLPrediction записывает ML предсказание
func (mc *MetricsCollector) RecordMLPrediction(success bool, latency time.Duration) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if success {
		mc.metrics.MLPredictions++
	} else {
		mc.metrics.MLFailures++
	}
	mc.updateAverageLatency(latency)
}

// RecordCircuitBreakerTrip записывает срабатывание circuit breaker
func (mc *MetricsCollector) RecordCircuitBreakerTrip() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics.CircuitBreakerTrips++
}

// GetMetrics возвращает текущие метрики
func (mc *MetricsCollector) GetMetrics() *types.SystemMetrics {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	// Возвращаем копию для безопасности
	metrics := *mc.metrics
	return &metrics
}

// Reset сбрасывает метрики
func (mc *MetricsCollector) Reset() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics = &types.SystemMetrics{
		LastCleanup: time.Now(),
	}
}

// Cleanup выполняет очистку старых данных
func (mc *MetricsCollector) Cleanup() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	now := time.Now()
	if now.Sub(mc.metrics.LastCleanup) > 5*time.Minute {
		mc.metrics.LastCleanup = now
		// Здесь можно добавить логику очистки старых данных
	}
}

// updateAverageLatency обновляет среднюю задержку
func (mc *MetricsCollector) updateAverageLatency(latency time.Duration) {
	if mc.metrics.PacketsProcessed == 0 {
		mc.metrics.AverageLatency = latency
	} else {
		// Простое экспоненциальное сглаживание
		alpha := 0.1
		mc.metrics.AverageLatency = time.Duration(
			float64(mc.metrics.AverageLatency)*(1-alpha) + float64(latency)*alpha,
		)
	}
}

// updateMemoryUsage обновляет использование памяти
func (mc *MetricsCollector) updateMemoryUsage(delta int64) {
	mc.metrics.MemoryUsage += delta
	if mc.metrics.MemoryUsage < 0 {
		mc.metrics.MemoryUsage = 0
	}
}

// GetHealthStatus возвращает статус здоровья системы
func (mc *MetricsCollector) GetHealthStatus() *HealthStatus {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	status := &HealthStatus{
		Overall: "healthy",
		Details: make(map[string]string),
	}

	// Проверяем общую производительность
	if mc.metrics.MLPredictions > 0 {
		failureRate := float64(mc.metrics.MLFailures) / float64(mc.metrics.MLPredictions)
		if failureRate > 0.1 { // Более 10% неудач
			status.Overall = "degraded"
			status.Details["ml_failure_rate"] = fmt.Sprintf("%.2f%%", failureRate*100)
		}
	}

	// Проверяем задержку
	if mc.metrics.AverageLatency > 100*time.Millisecond {
		status.Overall = "degraded"
		status.Details["high_latency"] = mc.metrics.AverageLatency.String()
	}

	// Проверяем circuit breaker
	if mc.metrics.CircuitBreakerTrips > 0 {
		status.Overall = "unhealthy"
		status.Details["circuit_breaker_trips"] = fmt.Sprintf("%d", mc.metrics.CircuitBreakerTrips)
	}

	status.Details["packets_processed"] = fmt.Sprintf("%d", mc.metrics.PacketsProcessed)
	status.Details["ml_predictions"] = fmt.Sprintf("%d", mc.metrics.MLPredictions)
	status.Details["memory_usage"] = fmt.Sprintf("%d bytes", mc.metrics.MemoryUsage)

	return status
}

// HealthStatus - статус здоровья системы
type HealthStatus struct {
	Overall string            `json:"overall"`
	Details map[string]string `json:"details"`
}
