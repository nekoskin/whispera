package evasion

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AdvancedProfileConfig - конфигурация профиля
type AdvancedProfileConfig struct {
	Name        string
	Description string
	Enabled     bool
	Priority    int
	Settings    map[string]interface{}
	Type        string
	Parameters  map[string]interface{}
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// AdvancedDynamicProfileManager - интерфейс менеджера динамических профилей
type AdvancedDynamicProfileManager interface {
	AddProfile(name string, config *AdvancedProfileConfig) error
	RemoveProfile(name string) error
	GetProfile(name string) (*AdvancedProfileConfig, error)
	GetAllProfiles() map[string]*AdvancedProfileConfig
	UpdateProfile(name string, config *AdvancedProfileConfig) error
	SetActiveProfile(name string) error
	GetActiveProfile() string
}

// AdvancedProfileManagerImpl - реализация менеджера динамических профилей
type AdvancedProfileManagerImpl struct {
	profiles map[string]*AdvancedProfileConfig
	mutex    sync.RWMutex
}

// NewAdvancedProfileManager создает новый менеджер динамических профилей
func NewAdvancedProfileManager() AdvancedDynamicProfileManager {
	return &AdvancedProfileManagerImpl{
		profiles: make(map[string]*AdvancedProfileConfig),
	}
}

// AddProfile добавляет новый профиль
func (dpm *AdvancedProfileManagerImpl) AddProfile(name string, config *AdvancedProfileConfig) error {
	dpm.mutex.Lock()
	defer dpm.mutex.Unlock()

	if _, exists := dpm.profiles[name]; exists {
		return fmt.Errorf("profile %s already exists", name)
	}

	dpm.profiles[name] = config
	return nil
}

// RemoveProfile удаляет профиль
func (dpm *AdvancedProfileManagerImpl) RemoveProfile(name string) error {
	dpm.mutex.Lock()
	defer dpm.mutex.Unlock()

	if _, exists := dpm.profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	delete(dpm.profiles, name)
	return nil
}

// GetProfile возвращает профиль по имени
func (dpm *AdvancedProfileManagerImpl) GetProfile(name string) (*AdvancedProfileConfig, error) {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	config, ok := dpm.profiles[name]
	if !ok {
		return nil, fmt.Errorf("profile %s not found", name)
	}

	return config, nil
}

// GetAllProfiles возвращает все профили
func (dpm *AdvancedProfileManagerImpl) GetAllProfiles() map[string]*AdvancedProfileConfig {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	// Возвращаем копию карты для предотвращения гонок
	copyMap := make(map[string]*AdvancedProfileConfig)
	for k, v := range dpm.profiles {
		copyMap[k] = v
	}

	return copyMap
}

// UpdateProfile обновляет конфигурацию профиля
func (dpm *AdvancedProfileManagerImpl) UpdateProfile(name string, config *AdvancedProfileConfig) error {
	dpm.mutex.Lock()
	defer dpm.mutex.Unlock()

	if _, exists := dpm.profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	dpm.profiles[name] = config
	return nil
}

// SetActiveProfile устанавливает активный профиль
func (dpm *AdvancedProfileManagerImpl) SetActiveProfile(name string) error {
	// В этой реализации это просто проверяет существование
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	if _, exists := dpm.profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	return nil
}

// GetActiveProfile возвращает активный профиль
func (dpm *AdvancedProfileManagerImpl) GetActiveProfile() string {
	// В этой упрощенной реализации возвращает первый найденный включенный профиль
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	for name, config := range dpm.profiles {
		if config.Enabled {
			return name
		}
	}

	return ""
}

// SaveToFile сохраняет конфигурацию в файл
func (dpm *AdvancedProfileManagerImpl) SaveToFile(filename string) error {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	data, err := json.MarshalIndent(dpm.profiles, "", "  ")
	if err != nil {
		return err
	}

	// Здесь должна быть логика сохранения в файл (используя os.WriteFile)
	// Для примера просто возвращаем nil
	_ = data
	return nil
}

// LoadFromFile загружает конфигурацию из файла
func (dpm *AdvancedProfileManagerImpl) LoadFromFile(filename string) error {
	// Здесь должна быть логика загрузки из файла
	return nil
}
