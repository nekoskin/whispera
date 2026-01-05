package monitoring

import (
	"sync"
	"time"

	"whispera/internal/auto_detection"
	"whispera/internal/obfuscation"
	ftepkg "whispera/internal/obfuscation/fte"
	"whispera/internal/obfuscation/russian"
)

// AdaptiveMonitor отслеживает эффективность и автоматически адаптирует профили
type AdaptiveMonitor struct {
	analyzer      *auto_detection.NetworkAnalyzer
	fte           *ftepkg.FTE
	marionette    *obfuscation.MarionetteAdapter
	russianTunnel *russian.RussianTunneler

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

// MonitorConfig концентрация мониторинга
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
