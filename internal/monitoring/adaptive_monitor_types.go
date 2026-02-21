package monitoring

import (
	"sync"
	"time"

	"whispera/internal/auto_detection"
	"whispera/internal/obfuscation"
	ftepkg "whispera/internal/obfuscation/fte"
	"whispera/internal/obfuscation/russian"
)

type AdaptiveMonitor struct {
	analyzer      *auto_detection.NetworkAnalyzer
	fte           *ftepkg.FTE
	marionette    *obfuscation.MarionetteAdapter
	russianTunnel *russian.RussianTunneler

	metrics       *PerformanceMetrics
	effectiveness *EffectivenessTracker
	adaptation    *AdaptationEngine

	mu         sync.RWMutex
	isRunning  bool
	lastUpdate time.Time

	config *MonitorConfig
}

type PerformanceMetrics struct {
	PacketsSent     int64
	PacketsReceived int64
	BytesSent       int64
	BytesReceived   int64
	Latency         time.Duration
	PacketLoss      float64
	Throughput      int64
	CPUUsage        float64
	MemoryUsage     int64
	ErrorRate       float64
	LastUpdate      time.Time
}

type EffectivenessTracker struct {
	BlockedAttempts    int64
	SuccessfulAttempts int64
	DetectionEvents    int64
	BypassSuccessRate  float64
	ThreatLevel        int
	LastDetection      time.Time
	AdaptationCount    int64
}

type AdaptationEngine struct {
	LearningRate        float64
	AdaptationThreshold float64
	MaxAdaptations      int
	AdaptationHistory   []AdaptationEvent
	CurrentProfile      *auto_detection.AutoProfileConfig
	BestProfile         *auto_detection.AutoProfileConfig
}

type AdaptationEvent struct {
	Timestamp     time.Time
	OldProfile    *auto_detection.AutoProfileConfig
	NewProfile    *auto_detection.AutoProfileConfig
	Reason        string
	Effectiveness float64
	Success       bool
}

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
