package monitoring

import (
	"fmt"
	"sync"
	"time"
	"whispera/internal/obfuscation/core/types"
)

type MetricsCollector struct {
	metrics *types.SystemMetrics
	mutex   sync.RWMutex
}

func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		metrics: &types.SystemMetrics{
			LastCleanup: time.Now(),
		},
	}
}

func (mc *MetricsCollector) RecordPacket(inputSize, outputSize int, latency time.Duration) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics.PacketsProcessed++
	mc.updateAverageLatency(latency)
	mc.updateMemoryUsage(int64(outputSize - inputSize))
}

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

func (mc *MetricsCollector) RecordCircuitBreakerTrip() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics.CircuitBreakerTrips++
}

func (mc *MetricsCollector) GetMetrics() *types.SystemMetrics {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	metrics := *mc.metrics
	return &metrics
}

func (mc *MetricsCollector) Reset() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics = &types.SystemMetrics{
		LastCleanup: time.Now(),
	}
}

func (mc *MetricsCollector) Cleanup() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	now := time.Now()
	if now.Sub(mc.metrics.LastCleanup) > 5*time.Minute {
		mc.metrics.LastCleanup = now
	}
}

func (mc *MetricsCollector) updateAverageLatency(latency time.Duration) {
	if mc.metrics.PacketsProcessed == 0 {
		mc.metrics.AverageLatency = latency
	} else {
		alpha := 0.1
		mc.metrics.AverageLatency = time.Duration(
			float64(mc.metrics.AverageLatency)*(1-alpha) + float64(latency)*alpha,
		)
	}
}

func (mc *MetricsCollector) updateMemoryUsage(delta int64) {
	mc.metrics.MemoryUsage += delta
	if mc.metrics.MemoryUsage < 0 {
		mc.metrics.MemoryUsage = 0
	}
}

func (mc *MetricsCollector) GetHealthStatus() *HealthStatus {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	status := &HealthStatus{
		Overall: "healthy",
		Details: make(map[string]string),
	}

	if mc.metrics.MLPredictions > 0 {
		failureRate := float64(mc.metrics.MLFailures) / float64(mc.metrics.MLPredictions)
		if failureRate > 0.1 {
			status.Overall = "degraded"
			status.Details["ml_failure_rate"] = fmt.Sprintf("%.2f%%", failureRate*100)
		}
	}

	if mc.metrics.AverageLatency > 100*time.Millisecond {
		status.Overall = "degraded"
		status.Details["high_latency"] = mc.metrics.AverageLatency.String()
	}

	if mc.metrics.CircuitBreakerTrips > 0 {
		status.Overall = "unhealthy"
		status.Details["circuit_breaker_trips"] = fmt.Sprintf("%d", mc.metrics.CircuitBreakerTrips)
	}

	status.Details["packets_processed"] = fmt.Sprintf("%d", mc.metrics.PacketsProcessed)
	status.Details["ml_predictions"] = fmt.Sprintf("%d", mc.metrics.MLPredictions)
	status.Details["memory_usage"] = fmt.Sprintf("%d bytes", mc.metrics.MemoryUsage)

	return status
}

type HealthStatus struct {
	Overall string            `json:"overall"`
	Details map[string]string `json:"details"`
}
