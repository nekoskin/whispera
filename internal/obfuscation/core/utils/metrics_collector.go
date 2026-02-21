package utils

import (
	"sync"
	"time"
	"whispera/internal/obfuscation/core/types"
)

type MetricsCollectorImpl struct {
	metrics *types.SystemMetrics
	mutex   sync.RWMutex
}

func NewMetricsCollector() types.MetricsCollector {
	return &MetricsCollectorImpl{
		metrics: &types.SystemMetrics{
			LastCleanup: time.Now(),
		},
	}
}

func (mc *MetricsCollectorImpl) RecordPacketProcessed(size int, latency time.Duration) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics.PacketsProcessed++

	if mc.metrics.PacketsProcessed == 1 {
		mc.metrics.AverageLatency = latency
	} else {
		alpha := 0.1
		mc.metrics.AverageLatency = time.Duration(
			float64(mc.metrics.AverageLatency)*(1-alpha) + float64(latency)*alpha,
		)
	}

	return nil
}

func (mc *MetricsCollectorImpl) RecordSuccess(profile, method string, latency time.Duration) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if profile != "" && method != "" && latency > 0 {
	}

	return nil
}

func (mc *MetricsCollectorImpl) RecordFailure(profile, method, reason string) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if profile != "" && method != "" && reason != "" {
	}

	return nil
}

func (mc *MetricsCollectorImpl) GetMetrics() *types.SystemMetrics {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	metrics := *mc.metrics
	return &metrics
}

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

func (mc *MetricsCollectorImpl) Cleanup() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics.LastCleanup = time.Now()
}

func (mc *MetricsCollectorImpl) Reset() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics = &types.SystemMetrics{
		LastCleanup: time.Now(),
	}
}

func (mc *MetricsCollectorImpl) RecordPacket(size int, latency time.Duration) error {
	return mc.RecordPacketProcessed(size, latency)
}

func (mc *MetricsCollectorImpl) RecordMLPrediction(success bool, latency time.Duration) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if success {
		mc.metrics.MLPredictions++
	} else {
		mc.metrics.MLFailures++
	}

	if mc.metrics.AverageLatency == 0 {
		mc.metrics.AverageLatency = latency
	} else {
		alpha := 0.1
		mc.metrics.AverageLatency = time.Duration(
			float64(mc.metrics.AverageLatency)*(1-alpha) + float64(latency)*alpha,
		)
	}

	return nil
}

func (mc *MetricsCollectorImpl) RecordMLFailure(reason string) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics.MLFailures++
	mc.metrics.CircuitBreakerTrips++

	return nil
}
