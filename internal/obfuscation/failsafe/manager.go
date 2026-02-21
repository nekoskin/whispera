package obfuscation

import (
	"time"
)

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

func (fs *FailSafe) initProfiles() {
	fs.profiles["vk"] = &FailSafeProfile{
		Name:                 "VKontakte",
		ObfuscationThreshold: 0.8,
		SessionDegradation:   0.6,
		ErrorRateThreshold:   0.1,
		RollbackProfile:      "minimal",
		CloseConnection:      false,
		DisableObfuscation:   true,
		Timeout:              5 * time.Second,
		CheckInterval:        10 * time.Second,
		HistoryWindow:        5 * time.Minute,
		MaxFailures:          3,
	}

	fs.profiles["yandex"] = &FailSafeProfile{
		Name:                 "Yandex",
		ObfuscationThreshold: 0.7,
		SessionDegradation:   0.5,
		ErrorRateThreshold:   0.08,
		RollbackProfile:      "basic",
		CloseConnection:      false,
		DisableObfuscation:   true,
		Timeout:              3 * time.Second,
		CheckInterval:        8 * time.Second,
		HistoryWindow:        3 * time.Minute,
		MaxFailures:          2,
	}

	fs.profiles["messenger_max"] = &FailSafeProfile{
		Name:                 "Messenger Max",
		ObfuscationThreshold: 0.9,
		SessionDegradation:   0.7,
		ErrorRateThreshold:   0.15,
		RollbackProfile:      "minimal",
		CloseConnection:      true,
		DisableObfuscation:   true,
		Timeout:              2 * time.Second,
		CheckInterval:        5 * time.Second,
		HistoryWindow:        2 * time.Minute,
		MaxFailures:          1,
	}
}

func (fs *FailSafe) initDetectors() {
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

func (fs *FailSafe) GetActiveProfile() string {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.active
}
