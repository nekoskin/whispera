package monitoring

import (
	"context"
	"fmt"
	"log"
	"time"

	"whispera/internal/auto_detection"
)

// performAdaptation выполняет адаптацию профилей
func (am *AdaptiveMonitor) performAdaptation() {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Проверяем, нужна ли адаптация
	if !am.shouldAdapt() {
		return
	}

	// Получаем оптимальную конфигурацию
	ctx := context.Background()
	config, err := am.analyzer.GetOptimalConfig(ctx, "example.com")
	if err != nil {
		log.Printf("Failed to get optimal config: %v", err)
		return
	}

	// Применяем новую конфигурацию
	if err := am.applyConfiguration(config); err != nil {
		log.Printf("Failed to apply configuration: %v", err)
		return
	}

	// Записываем событие адаптации
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

	// Ограничиваем историю
	if len(am.adaptation.AdaptationHistory) > 100 {
		am.adaptation.AdaptationHistory = am.adaptation.AdaptationHistory[1:]
	}

	if am.config.EnableLogging {
		log.Printf("Adaptation performed: %s -> %s (effectiveness: %.2f)",
			am.getProfileName(am.adaptation.CurrentProfile),
			am.getProfileName(config),
			am.effectiveness.BypassSuccessRate)
	}
}

// shouldAdapt определяет, нужна ли адаптация
func (am *AdaptiveMonitor) shouldAdapt() bool {
	// Адаптация нужна, если эффективность ниже порога
	if am.effectiveness.BypassSuccessRate < am.adaptation.AdaptationThreshold {
		return true
	}

	// Адаптация нужна, если уровень угрозы высокий
	if am.effectiveness.ThreatLevel > 7 {
		return true
	}

	// Адаптация нужна, если прошло много времени с последней адаптации
	if time.Since(am.lastUpdate) > am.config.AdaptationInterval*2 {
		return true
	}

	return false
}

// applyConfiguration применяет новую конфигурацию
func (am *AdaptiveMonitor) applyConfiguration(config *auto_detection.AutoProfileConfig) error {
	// Применяем FTE профиль
	if config.FTEProfile != "" {
		if err := am.fte.SetActiveProfile(config.FTEProfile); err != nil {
			return fmt.Errorf("failed to set FTE profile: %v", err)
		}
	}

	// Применяем Marionette профиль
	if config.MarionetteProfile != "" {
		if err := am.marionette.SetActiveProfile(config.MarionetteProfile); err != nil {
			return fmt.Errorf("failed to set Marionette profile: %v", err)
		}
	}

	// Применяем Russian service
	if config.RussianService != "" {
		if err := am.russianTunnel.SetActiveService(config.RussianService); err != nil {
			return fmt.Errorf("failed to set Russian service: %v", err)
		}
	}

	return nil
}

// getProfileName возвращает читаемое имя профиля
func (am *AdaptiveMonitor) getProfileName(config *auto_detection.AutoProfileConfig) string {
	if config == nil {
		return "none"
	}
	return fmt.Sprintf("%s+%s+%s", config.FTEProfile, config.MarionetteProfile, config.RussianService)
}

// GetAdaptationHistory возвращает историю адаптации
func (am *AdaptiveMonitor) GetAdaptationHistory() []AdaptationEvent {
	am.mu.RLock()
	defer am.mu.RUnlock()

	// Возвращаем копию истории
	history := make([]AdaptationEvent, len(am.adaptation.AdaptationHistory))
	copy(history, am.adaptation.AdaptationHistory)
	return history
}
