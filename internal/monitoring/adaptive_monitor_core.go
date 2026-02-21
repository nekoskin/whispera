package monitoring

import (
	"context"
	"fmt"
	"time"

	"whispera/internal/auto_detection"
	"whispera/internal/logger"
	"whispera/internal/obfuscation"
	ftepkg "whispera/internal/obfuscation/fte"
	"whispera/internal/obfuscation/russian"
)

var log = logger.Module("monitoring")

func NewAdaptiveMonitor() *AdaptiveMonitor {
	return &AdaptiveMonitor{
		analyzer:      auto_detection.NewNetworkAnalyzer(),
		fte:           ftepkg.NewFTE(),
		marionette:    obfuscation.NewMarionetteAdapter(),
		russianTunnel: russian.NewRussianTunneler(),
		metrics:       &PerformanceMetrics{},
		effectiveness: &EffectivenessTracker{},
		adaptation: &AdaptationEngine{
			LearningRate:        0.1,
			AdaptationThreshold: 0.7,
			MaxAdaptations:      10,
			AdaptationHistory:   make([]AdaptationEvent, 0),
		},
		config: &MonitorConfig{
			UpdateInterval:      30 * time.Second,
			AdaptationInterval:  5 * time.Minute,
			EffectivenessWindow: 10 * time.Minute,
			LearningRate:        0.1,
			AdaptationThreshold: 0.7,
			MaxAdaptations:      10,
			EnableAutoAdapt:     true,
			EnableMetrics:       true,
			EnableLogging:       true,
		},
	}
}

func (am *AdaptiveMonitor) Start(ctx context.Context) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if am.isRunning {
		return fmt.Errorf("monitor is already running")
	}

	am.isRunning = true
	am.lastUpdate = time.Now()

	go am.monitoringLoop(ctx)
	go am.adaptationLoop(ctx)

	if am.config.EnableLogging {
		log.Info("Adaptive monitor started")
	}

	return nil
}

func (am *AdaptiveMonitor) Stop() {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.isRunning = false

	if am.config.EnableLogging {
		log.Info("Adaptive monitor stopped")
	}
}

func (am *AdaptiveMonitor) monitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(am.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			am.updateMetrics()
			am.analyzeEffectiveness()
		}
	}
}

func (am *AdaptiveMonitor) adaptationLoop(ctx context.Context) {
	ticker := time.NewTicker(am.config.AdaptationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if am.config.EnableAutoAdapt {
				am.performAdaptation()
			}
		}
	}
}
