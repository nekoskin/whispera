package monitoring

import (
	"time"
)

func (am *AdaptiveMonitor) updateMetrics() {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.metrics.LastUpdate = time.Now()

	am.metrics.PacketsSent++
	am.metrics.BytesSent += 1024
	am.metrics.Latency = time.Duration(50+time.Now().UnixNano()%100) * time.Millisecond
	am.metrics.Throughput = 1024 * 1024
	am.metrics.CPUUsage = 15.0 + float64(time.Now().UnixNano()%10)
	am.metrics.MemoryUsage = 50 * 1024 * 1024
}

func (am *AdaptiveMonitor) analyzeEffectiveness() {
	am.mu.Lock()
	defer am.mu.Unlock()

	totalAttempts := am.effectiveness.BlockedAttempts + am.effectiveness.SuccessfulAttempts
	if totalAttempts > 0 {
		am.effectiveness.BypassSuccessRate = float64(am.effectiveness.SuccessfulAttempts) / float64(totalAttempts)
	}

	if am.effectiveness.BypassSuccessRate < 0.5 {
		am.effectiveness.ThreatLevel = 8
	} else if am.effectiveness.BypassSuccessRate < 0.7 {
		am.effectiveness.ThreatLevel = 6
	} else if am.effectiveness.BypassSuccessRate < 0.9 {
		am.effectiveness.ThreatLevel = 4
	} else {
		am.effectiveness.ThreatLevel = 2
	}

	am.analyzer.UpdateThreatLevel(am.effectiveness.ThreatLevel)
}

func (am *AdaptiveMonitor) RecordSuccess() {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.effectiveness.SuccessfulAttempts++
}

func (am *AdaptiveMonitor) RecordBlocked() {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.effectiveness.BlockedAttempts++
}

func (am *AdaptiveMonitor) RecordDetection() {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.effectiveness.DetectionEvents++
	am.effectiveness.LastDetection = time.Now()
}

func (am *AdaptiveMonitor) GetMetrics() *PerformanceMetrics {
	am.mu.RLock()
	defer am.mu.RUnlock()

	metrics := *am.metrics
	return &metrics
}

func (am *AdaptiveMonitor) GetEffectiveness() *EffectivenessTracker {
	am.mu.RLock()
	defer am.mu.RUnlock()

	effectiveness := *am.effectiveness
	return &effectiveness
}
