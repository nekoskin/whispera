package monitoring

import (
	"context"
	"fmt"
	"time"

	"whispera/internal/auto_detection"
)

func (am *AdaptiveMonitor) performAdaptation() {
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.shouldAdapt() {
		return
	}

	ctx := context.Background()
	config, err := am.analyzer.GetOptimalConfig(ctx, "example.com")
	if err != nil {
		log.Warn("Failed to get optimal config: %v", err)
		return
	}

	if err := am.applyConfiguration(config); err != nil {
		log.Warn("Failed to apply configuration: %v", err)
		return
	}

	event := AdaptationEvent{
		Timestamp:     time.Now(),
		OldProfile:    am.adaptation.CurrentProfile,
		NewProfile:    config,
		Reason:        "effectiveness_threshold",
		Effectiveness: am.effectiveness.BypassSuccessRate,
		Success:       true,
	}

	am.adaptation.AdaptationHistory = append(am.adaptation.AdaptationHistory, event)
	am.adaptation.CurrentProfile = config

	if len(am.adaptation.AdaptationHistory) > 100 {
		am.adaptation.AdaptationHistory = am.adaptation.AdaptationHistory[1:]
	}

	if am.config.EnableLogging {
		log.Info("Adaptation performed: %s -> %s (effectiveness: %.2f)",
			am.getProfileName(am.adaptation.CurrentProfile),
			am.getProfileName(config),
			am.effectiveness.BypassSuccessRate)
	}
}

func (am *AdaptiveMonitor) shouldAdapt() bool {
	if am.effectiveness.BypassSuccessRate < am.adaptation.AdaptationThreshold {
		return true
	}

	if am.effectiveness.ThreatLevel > 7 {
		return true
	}

	if time.Since(am.lastUpdate) > am.config.AdaptationInterval*2 {
		return true
	}

	return false
}

func (am *AdaptiveMonitor) applyConfiguration(config *auto_detection.AutoProfileConfig) error {
	if config.FTEProfile != "" {
		if err := am.fte.SetActiveProfile(config.FTEProfile); err != nil {
			return fmt.Errorf("failed to set FTE profile: %v", err)
		}
	}

	if config.MarionetteProfile != "" {
		if err := am.marionette.SetActiveProfile(config.MarionetteProfile); err != nil {
			return fmt.Errorf("failed to set Marionette profile: %v", err)
		}
	}

	if config.RussianService != "" {
		if err := am.russianTunnel.SetActiveService(config.RussianService); err != nil {
			return fmt.Errorf("failed to set Russian service: %v", err)
		}
	}

	return nil
}

func (am *AdaptiveMonitor) getProfileName(config *auto_detection.AutoProfileConfig) string {
	if config == nil {
		return "none"
	}
	return fmt.Sprintf("%s+%s+%s", config.FTEProfile, config.MarionetteProfile, config.RussianService)
}

func (am *AdaptiveMonitor) GetAdaptationHistory() []AdaptationEvent {
	am.mu.RLock()
	defer am.mu.RUnlock()

	history := make([]AdaptationEvent, len(am.adaptation.AdaptationHistory))
	copy(history, am.adaptation.AdaptationHistory)
	return history
}
