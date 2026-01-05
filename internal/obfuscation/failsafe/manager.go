package obfuscation

import (
	"time"
)

// NewFailSafe создает новый экземпляр FailSafe
func NewFailSafe() *FailSafe {
	fs := &FailSafe{
		profiles:       make(map[string]*FailSafeProfile),
		detectors:      make([]*FailureDetector, 0),
		actions:        make([]*FailSafeAction, 0),
		functionStates: make(map[string]*FunctionState),
		metrics:        &FailSafeMetrics{LastUpdate: time.Now()},
		logger:         &FailSafeLogger{Enabled: true, Level: "info"},
	}
	fs.initProfiles()
	fs.initDetectors()
	return fs
}

// initProfiles инициализирует профили fail-safe
func (fs *FailSafe) initProfiles() {
	// VK профиль fail-safe
	fs.profiles["vk"] = &FailSafeProfile{
		Name:                 "VKontakte",
		ObfuscationThreshold: 0.8, // 80% очевидности
		SessionDegradation:   0.6, // 60% деградации
		ErrorRateThreshold:   0.1, // 10% ошибок
		RollbackProfile:      "minimal",
		CloseConnection:      false,
		DisableObfuscation:   true,
		Timeout:              5 * time.Second,
		CheckInterval:        10 * time.Second,
		HistoryWindow:        5 * time.Minute,
		MaxFailures:          3,
	}

	// Yandex профиль fail-safe
	fs.profiles["yandex"] = &FailSafeProfile{
		Name:                 "Yandex",
		ObfuscationThreshold: 0.7,  // 70% очевидности
		SessionDegradation:   0.5,  // 50% деградации
		ErrorRateThreshold:   0.08, // 8% ошибок
		RollbackProfile:      "basic",
		CloseConnection:      false,
		DisableObfuscation:   true,
		Timeout:              3 * time.Second,
		CheckInterval:        8 * time.Second,
		HistoryWindow:        3 * time.Minute,
		MaxFailures:          2,
	}

	// Messenger Max профиль fail-safe
	fs.profiles["messenger_max"] = &FailSafeProfile{
		Name:                 "Messenger Max",
		ObfuscationThreshold: 0.9,  // 90% очевидности
		SessionDegradation:   0.7,  // 70% деградации
		ErrorRateThreshold:   0.15, // 15% ошибок
		RollbackProfile:      "minimal",
		CloseConnection:      true, // более агрессивный
		DisableObfuscation:   true,
		Timeout:              2 * time.Second,
		CheckInterval:        5 * time.Second,
		HistoryWindow:        2 * time.Minute,
		MaxFailures:          1,
	}
}

// initDetectors инициализирует детекторы сбоев
func (fs *FailSafe) initDetectors() {
	// Инициализируем все детекторы за один раз
	fs.detectors = append(fs.detectors,
		&FailureDetector{
			Name:      "obfuscation_detector",
			Type:      detectorTypeObfuscation,
			Threshold: 0.8,
			Window:    30 * time.Second,
		},
		&FailureDetector{
			Name:      "session_detector",
			Type:      detectorTypeSession,
			Threshold: 0.6,
			Window:    60 * time.Second,
		},
		&FailureDetector{
			Name:      "error_detector",
			Type:      detectorTypeError,
			Threshold: 0.1,
			Window:    30 * time.Second,
		},
		&FailureDetector{
			Name:      "performance_detector",
			Type:      detectorTypePerformance,
			Threshold: 0.5,
			Window:    45 * time.Second,
		})
}

// GetActiveProfile возвращает активный профиль
func (fs *FailSafe) GetActiveProfile() string {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.active
}
