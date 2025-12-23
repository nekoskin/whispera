package profiles

import (
	"fmt"
	"time"
	"whispera/internal/obfuscation/core/types"
)

// ProfileInitializerImpl - реализация инициализатора профилей
type ProfileInitializerImpl struct {
	profileManager *ProfileManager
}

// NewProfileInitializer создает новый инициализатор профилей
func NewProfileInitializer(pm *ProfileManager) types.ProfileInitializer {
	return &ProfileInitializerImpl{
		profileManager: pm,
	}
}

// InitializeDefaultProfiles инициализирует профили по умолчанию
func (pi *ProfileInitializerImpl) InitializeDefaultProfiles() error {
	// Создаем базовые профили
	profiles := []*types.TrafficProfile{
		{
			Name: "default",
			PacketSizes: types.SizeDistribution{
				Min:    64,
				Max:    1500,
				Mean:   512,
				StdDev: 256,
			},
			Intervals: types.IntervalDistribution{
				Min:     10 * time.Millisecond,
				Max:     100 * time.Millisecond,
				Mean:    50 * time.Millisecond,
				StdDev:  20 * time.Millisecond,
				Pattern: "exponential",
			},
			BurstPatterns: types.BurstProfile{
				Probability: 0.1,
				MinBurst:    3,
				MaxBurst:    10,
				BurstGap:    100 * time.Millisecond,
			},
			Coverage: types.CoverageProfile{
				Enabled:     true,
				Probability: 0.05,
				MinSize:     32,
				MaxSize:     1024,
				Interval:    5 * time.Second,
			},
			Adaptation: types.AdaptationProfile{
				Enabled:             true,
				Sensitivity:         0.5,
				LearningRate:        0.1,
				AdaptationThreshold: 0.8,
			},
			CreatedAt: time.Now(),
		},
		{
			Name: "stealth",
			PacketSizes: types.SizeDistribution{
				Min:    32,
				Max:    512,
				Mean:   128,
				StdDev: 64,
			},
			Intervals: types.IntervalDistribution{
				Min:     50 * time.Millisecond,
				Max:     500 * time.Millisecond,
				Mean:    200 * time.Millisecond,
				StdDev:  100 * time.Millisecond,
				Pattern: "uniform",
			},
			BurstPatterns: types.BurstProfile{
				Probability: 0.05,
				MinBurst:    2,
				MaxBurst:    5,
				BurstGap:    1 * time.Second,
			},
			Coverage: types.CoverageProfile{
				Enabled:     true,
				Probability: 0.1,
				MinSize:     16,
				MaxSize:     256,
				Interval:    2 * time.Second,
			},
			Adaptation: types.AdaptationProfile{
				Enabled:             true,
				Sensitivity:         0.8,
				LearningRate:        0.2,
				AdaptationThreshold: 0.6,
			},
			CreatedAt: time.Now(),
		},
	}

	// Добавляем профили в менеджер
	for _, profile := range profiles {
		pi.profileManager.AddProfile(profile.Name, profile)
	}

	return nil
}

// InitializeRussianServiceProfiles инициализирует профили российских сервисов
func (pi *ProfileInitializerImpl) InitializeRussianServiceProfiles() error {
	// Создаем профили для российских сервисов
	profiles := []*types.TrafficProfile{
		{
			Name: "vk",
			PacketSizes: types.SizeDistribution{
				Min:    128,
				Max:    1024,
				Mean:   384,
				StdDev: 192,
			},
			Intervals: types.IntervalDistribution{
				Min:     20 * time.Millisecond,
				Max:     200 * time.Millisecond,
				Mean:    80 * time.Millisecond,
				StdDev:  40 * time.Millisecond,
				Pattern: "exponential",
			},
			BurstPatterns: types.BurstProfile{
				Probability: 0.15,
				MinBurst:    5,
				MaxBurst:    15,
				BurstGap:    200 * time.Millisecond,
			},
			Coverage: types.CoverageProfile{
				Enabled:     true,
				Probability: 0.08,
				MinSize:     64,
				MaxSize:     512,
				Interval:    3 * time.Second,
			},
			Adaptation: types.AdaptationProfile{
				Enabled:             true,
				Sensitivity:         0.6,
				LearningRate:        0.15,
				AdaptationThreshold: 0.7,
			},
			CreatedAt: time.Now(),
		},
		{
			Name: "yandex",
			PacketSizes: types.SizeDistribution{
				Min:    64,
				Max:    2048,
				Mean:   512,
				StdDev: 256,
			},
			Intervals: types.IntervalDistribution{
				Min:     10 * time.Millisecond,
				Max:     100 * time.Millisecond,
				Mean:    40 * time.Millisecond,
				StdDev:  20 * time.Millisecond,
				Pattern: "exponential",
			},
			BurstPatterns: types.BurstProfile{
				Probability: 0.2,
				MinBurst:    3,
				MaxBurst:    12,
				BurstGap:    150 * time.Millisecond,
			},
			Coverage: types.CoverageProfile{
				Enabled:     true,
				Probability: 0.06,
				MinSize:     32,
				MaxSize:     1024,
				Interval:    4 * time.Second,
			},
			Adaptation: types.AdaptationProfile{
				Enabled:             true,
				Sensitivity:         0.7,
				LearningRate:        0.12,
				AdaptationThreshold: 0.75,
			},
			CreatedAt: time.Now(),
		},
	}

	// Добавляем профили в менеджер
	for _, profile := range profiles {
		pi.profileManager.AddProfile(profile.Name, profile)
	}

	return nil
}

// InitializeMobileDeviceProfiles инициализирует профили мобильных устройств
func (pi *ProfileInitializerImpl) InitializeMobileDeviceProfiles() error {
	// Создаем профили для мобильных устройств
	profiles := []*types.TrafficProfile{
		{
			Name: "mobile_android",
			PacketSizes: types.SizeDistribution{
				Min:    32,
				Max:    1500,
				Mean:   256,
				StdDev: 128,
			},
			Intervals: types.IntervalDistribution{
				Min:     5 * time.Millisecond,
				Max:     50 * time.Millisecond,
				Mean:    20 * time.Millisecond,
				StdDev:  10 * time.Millisecond,
				Pattern: "exponential",
			},
			BurstPatterns: types.BurstProfile{
				Probability: 0.25,
				MinBurst:    2,
				MaxBurst:    8,
				BurstGap:    50 * time.Millisecond,
			},
			Coverage: types.CoverageProfile{
				Enabled:     true,
				Probability: 0.12,
				MinSize:     16,
				MaxSize:     256,
				Interval:    1 * time.Second,
			},
			Adaptation: types.AdaptationProfile{
				Enabled:             true,
				Sensitivity:         0.9,
				LearningRate:        0.25,
				AdaptationThreshold: 0.5,
			},
			CreatedAt: time.Now(),
		},
		{
			Name: "mobile_ios",
			PacketSizes: types.SizeDistribution{
				Min:    32,
				Max:    1500,
				Mean:   192,
				StdDev: 96,
			},
			Intervals: types.IntervalDistribution{
				Min:     5 * time.Millisecond,
				Max:     30 * time.Millisecond,
				Mean:    15 * time.Millisecond,
				StdDev:  8 * time.Millisecond,
				Pattern: "exponential",
			},
			BurstPatterns: types.BurstProfile{
				Probability: 0.3,
				MinBurst:    1,
				MaxBurst:    6,
				BurstGap:    30 * time.Millisecond,
			},
			Coverage: types.CoverageProfile{
				Enabled:     true,
				Probability: 0.15,
				MinSize:     8,
				MaxSize:     128,
				Interval:    800 * time.Millisecond,
			},
			Adaptation: types.AdaptationProfile{
				Enabled:             true,
				Sensitivity:         0.95,
				LearningRate:        0.3,
				AdaptationThreshold: 0.4,
			},
			CreatedAt: time.Now(),
		},
	}

	// Добавляем профили в менеджер
	for _, profile := range profiles {
		pi.profileManager.AddProfile(profile.Name, profile)
	}

	return nil
}

// InitializeProfile инициализирует профиль с заданной конфигурацией
func (pi *ProfileInitializerImpl) InitializeProfile(name string, config map[string]interface{}) error {
	// Создаем профиль на основе конфигурации
	profile := &types.TrafficProfile{
		Name: name,
		// Заполняем поля на основе конфигурации
		SizeDistribution: &types.SizeDistribution{
			Bins: make([]int, 0),
		},
		IntervalDistribution: &types.IntervalDistribution{
			Bins: make([]time.Duration, 0),
		},
		BurstProfile: &types.BurstProfile{
			Enabled: true,
		},
		CoverageProfile: &types.CoverageProfile{
			Enabled: true,
		},
		AdaptationProfile: &types.AdaptationProfile{
			Enabled: true,
		},
	}

	// Применяем конфигурацию
	if enabled, ok := config["enabled"].(bool); ok {
		profile.AdaptationProfile.Enabled = enabled
	}

	// Добавляем профиль в менеджер
	pi.profileManager.AddProfile(name, profile)
	return nil
}

// ValidateProfile проверяет корректность профиля
func (pi *ProfileInitializerImpl) ValidateProfile(profile *types.TrafficProfile) error {
	if profile == nil {
		return fmt.Errorf("profile cannot be nil")
	}

	if profile.Name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}

	if profile.SizeDistribution.Min < 0 {
		return fmt.Errorf("size distribution min cannot be negative")
	}

	if profile.SizeDistribution.Max <= profile.SizeDistribution.Min {
		return fmt.Errorf("size distribution max must be greater than min")
	}

	return nil
}
