package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"whispera/internal/auto_detection"
	"whispera/internal/obfuscation"
	ftepkg "whispera/internal/obfuscation/fte"
	"whispera/internal/tunneling"
)

// AdaptiveMonitor отслеживает эффективность и автоматически адаптирует профили
type AdaptiveMonitor struct {
	analyzer      *auto_detection.NetworkAnalyzer
	fte           *ftepkg.FTE
	marionette    *obfuscation.MarionetteAdapter
	russianTunnel *tunneling.RussianTunneler

	// Метрики
	metrics       *PerformanceMetrics
	effectiveness *EffectivenessTracker
	adaptation    *AdaptationEngine

	// Состояние
	mu         sync.RWMutex
	isRunning  bool
	lastUpdate time.Time

	// Конфигурация
	config *MonitorConfig
}

// PerformanceMetrics отслеживает производительность
type PerformanceMetrics struct {
	PacketsSent     int64
	PacketsReceived int64
	BytesSent       int64
	BytesReceived   int64
	Latency         time.Duration
	PacketLoss      float64
	Throughput      int64 // bytes per second
	CPUUsage        float64
	MemoryUsage     int64
	ErrorRate       float64
	LastUpdate      time.Time
}

// EffectivenessTracker отслеживает эффективность обхода блокировок
type EffectivenessTracker struct {
	BlockedAttempts    int64
	SuccessfulAttempts int64
	DetectionEvents    int64
	BypassSuccessRate  float64
	ThreatLevel        int
	LastDetection      time.Time
	AdaptationCount    int64
}

// AdaptationEngine управляет адаптацией профилей
type AdaptationEngine struct {
	LearningRate        float64
	AdaptationThreshold float64
	MaxAdaptations      int
	AdaptationHistory   []AdaptationEvent
	CurrentProfile      *auto_detection.AutoProfileConfig
	BestProfile         *auto_detection.AutoProfileConfig
}

// AdaptationEvent записывает событие адаптации
type AdaptationEvent struct {
	Timestamp     time.Time
	OldProfile    *auto_detection.AutoProfileConfig
	NewProfile    *auto_detection.AutoProfileConfig
	Reason        string
	Effectiveness float64
	Success       bool
}

// MonitorConfig конфигурация мониторинга
type MonitorConfig struct {
	UpdateInterval      time.Duration
	AdaptationInterval  time.Duration
	EffectivenessWindow time.Duration
	LearningRate        float64
	AdaptationThreshold float64
	MaxAdaptations      int
	EnableAutoAdapt     bool
	EnableMetrics       bool
	EnableLogging       bool
}

// NewAdaptiveMonitor создает новый адаптивный монитор
func NewAdaptiveMonitor() *AdaptiveMonitor {
	return &AdaptiveMonitor{
		analyzer:      auto_detection.NewNetworkAnalyzer(),
		fte:           ftepkg.NewFTE(),
		marionette:    obfuscation.NewMarionetteAdapter(),
		russianTunnel: tunneling.NewRussianTunneler(),
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

// Start запускает мониторинг и адаптацию
func (am *AdaptiveMonitor) Start(ctx context.Context) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if am.isRunning {
		return fmt.Errorf("monitor is already running")
	}

	am.isRunning = true
	am.lastUpdate = time.Now()

	// Запускаем горутины мониторинга
	go am.monitoringLoop(ctx)
	go am.adaptationLoop(ctx)

	if am.config.EnableLogging {
		log.Printf("Adaptive monitor started")
	}

	return nil
}

// Stop останавливает мониторинг
func (am *AdaptiveMonitor) Stop() {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.isRunning = false

	if am.config.EnableLogging {
		log.Printf("Adaptive monitor stopped")
	}
}

// monitoringLoop основной цикл мониторинга
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

// adaptationLoop цикл адаптации
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
	// Adaptation count updated

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

// GetAdaptationHistory возвращает историю адаптации
func (am *AdaptiveMonitor) GetAdaptationHistory() []AdaptationEvent {
	am.mu.RLock()
	defer am.mu.RUnlock()

	// Возвращаем копию истории
	history := make([]AdaptationEvent, len(am.adaptation.AdaptationHistory))
	copy(history, am.adaptation.AdaptationHistory)
	return history
}

// SetConfig обновляет конфигурацию мониторинга
func (am *AdaptiveMonitor) SetConfig(config *MonitorConfig) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.config = config
}

// ExportMetrics экспортирует метрики в JSON
func (am *AdaptiveMonitor) ExportMetrics() ([]byte, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	data := map[string]interface{}{
		"metrics":       am.metrics,
		"effectiveness": am.effectiveness,
		"adaptation":    am.adaptation,
		"config":        am.config,
		"timestamp":     time.Now(),
	}

	return json.MarshalIndent(data, "", "  ")
}

// ImportMetrics импортирует метрики из JSON
func (am *AdaptiveMonitor) ImportMetrics(data []byte) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	var imported map[string]interface{}
	if err := json.Unmarshal(data, &imported); err != nil {
		return err
	}

	// Восстанавливаем метрики (упрощенная версия)
	if _, ok := imported["metrics"].(map[string]interface{}); ok {
		am.metrics = &PerformanceMetrics{}
		// Заполняем метрики из импортированных данных
	}

	return nil
}
