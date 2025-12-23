package profiles

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ProfileConfig - конфигурация профиля
type ProfileConfig struct {
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

// DynamicProfileManager - интерфейс менеджера динамических профилей
type DynamicProfileManager interface {
	AddProfile(name string, config *ProfileConfig) error
	RemoveProfile(name string) error
	GetProfile(name string) (*ProfileConfig, error)
	GetAllProfiles() map[string]*ProfileConfig
	UpdateProfile(name string, config *ProfileConfig) error
	SetActiveProfile(name string) error
	GetActiveProfile() string
}

// DynamicProfileManagerImpl - реализация менеджера динамических профилей
type DynamicProfileManagerImpl struct {
	profiles map[string]*ProfileConfig
	mutex    sync.RWMutex
}

// NewDynamicProfileManager создает новый менеджер динамических профилей
func NewDynamicProfileManager() DynamicProfileManager {
	return &DynamicProfileManagerImpl{
		profiles: make(map[string]*ProfileConfig),
	}
}

// AddProfile добавляет новый профиль
func (dpm *DynamicProfileManagerImpl) AddProfile(name string, config *ProfileConfig) error {
	dpm.mutex.Lock()
	defer dpm.mutex.Unlock()

	if _, exists := dpm.profiles[name]; exists {
		return fmt.Errorf("profile %s already exists", name)
	}

	config.Name = name
	config.CreatedAt = time.Now()
	config.UpdatedAt = time.Now()

	dpm.profiles[name] = config
	return nil
}

// CreateProfile создает новый профиль
func (dpm *DynamicProfileManagerImpl) CreateProfile(name string, config *ProfileConfig) error {
	return dpm.AddProfile(name, config)
}

// UpdateProfile обновляет существующий профиль
func (dpm *DynamicProfileManagerImpl) UpdateProfile(name string, config *ProfileConfig) error {
	dpm.mutex.Lock()
	defer dpm.mutex.Unlock()

	if _, exists := dpm.profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	config.Name = name
	config.UpdatedAt = time.Now()

	dpm.profiles[name] = config
	return nil
}

// RemoveProfile удаляет профиль
func (dpm *DynamicProfileManagerImpl) RemoveProfile(name string) error {
	dpm.mutex.Lock()
	defer dpm.mutex.Unlock()

	if _, exists := dpm.profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	delete(dpm.profiles, name)
	return nil
}

// DeleteProfile удаляет профиль
func (dpm *DynamicProfileManagerImpl) DeleteProfile(name string) error {
	return dpm.RemoveProfile(name)
}

// GetProfile возвращает профиль по имени
func (dpm *DynamicProfileManagerImpl) GetProfile(name string) (*ProfileConfig, error) {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	profile, exists := dpm.profiles[name]
	if !exists {
		return nil, fmt.Errorf("profile %s not found", name)
	}

	// Возвращаем копию для безопасности
	configCopy := *profile
	return &configCopy, nil
}

// ListProfiles возвращает список всех профилей
func (dpm *DynamicProfileManagerImpl) ListProfiles() []string {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	names := make([]string, 0, len(dpm.profiles))
	for name := range dpm.profiles {
		names = append(names, name)
	}
	return names
}

// CreateProfileFromTemplate создает профиль из шаблона
func (dpm *DynamicProfileManagerImpl) CreateProfileFromTemplate(
	name, templateName string, overrides map[string]interface{},
) error {
	dpm.mutex.RLock()
	template, exists := dpm.profiles[templateName]
	dpm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("template profile %s not found", templateName)
	}

	// Создаем новый профиль на основе шаблона
	newConfig := &ProfileConfig{
		Name:       name,
		Type:       template.Type,
		Parameters: make(map[string]interface{}),
		Enabled:    template.Enabled,
		Priority:   template.Priority,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Копируем параметры из шаблона
	for key, value := range template.Parameters {
		newConfig.Parameters[key] = value
	}

	// Применяем переопределения
	for key, value := range overrides {
		newConfig.Parameters[key] = value
	}

	return dpm.CreateProfile(name, newConfig)
}

// CloneProfile клонирует существующий профиль
func (dpm *DynamicProfileManagerImpl) CloneProfile(sourceName, newName string) error {
	dpm.mutex.RLock()
	source, exists := dpm.profiles[sourceName]
	dpm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("source profile %s not found", sourceName)
	}

	// Создаем копию профиля
	newConfig := &ProfileConfig{
		Name:       newName,
		Type:       source.Type,
		Parameters: make(map[string]interface{}),
		Enabled:    source.Enabled,
		Priority:   source.Priority,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Копируем параметры
	for key, value := range source.Parameters {
		newConfig.Parameters[key] = value
	}

	return dpm.CreateProfile(newName, newConfig)
}

// ExportProfile экспортирует профиль в JSON
func (dpm *DynamicProfileManagerImpl) ExportProfile(name string) ([]byte, error) {
	dpm.mutex.RLock()
	profile, exists := dpm.profiles[name]
	dpm.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("profile %s not found", name)
	}

	return json.MarshalIndent(profile, "", "  ")
}

// ImportProfile импортирует профиль из JSON
func (dpm *DynamicProfileManagerImpl) ImportProfile(data []byte) error {
	var config ProfileConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to unmarshal profile: %w", err)
	}

	return dpm.CreateProfile(config.Name, &config)
}

// GetProfilesByType возвращает профили по типу
func (dpm *DynamicProfileManagerImpl) GetProfilesByType(profileType string) []*ProfileConfig {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	profiles := make([]*ProfileConfig, 0, len(dpm.profiles))
	for _, profile := range dpm.profiles {
		if profile.Type == profileType {
			// Возвращаем копию для безопасности
			configCopy := *profile
			profiles = append(profiles, &configCopy)
		}
	}

	return profiles
}

// GetEnabledProfiles возвращает только включенные профили
func (dpm *DynamicProfileManagerImpl) GetEnabledProfiles() []*ProfileConfig {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	profiles := make([]*ProfileConfig, 0, len(dpm.profiles))
	for _, profile := range dpm.profiles {
		if profile.Enabled {
			// Возвращаем копию для безопасности
			configCopy := *profile
			profiles = append(profiles, &configCopy)
		}
	}

	return profiles
}

// GetProfilesByPriority возвращает профили, отсортированные по приоритету
func (dpm *DynamicProfileManagerImpl) GetProfilesByPriority() []*ProfileConfig {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	profiles := make([]*ProfileConfig, 0, len(dpm.profiles))
	for _, profile := range dpm.profiles {
		// Возвращаем копию для безопасности
		configCopy := *profile
		profiles = append(profiles, &configCopy)
	}

	// Сортируем по приоритету (высший приоритет первым)
	for i := 0; i < len(profiles)-1; i++ {
		for j := i + 1; j < len(profiles); j++ {
			if profiles[i].Priority < profiles[j].Priority {
				profiles[i], profiles[j] = profiles[j], profiles[i]
			}
		}
	}

	return profiles
}

// ValidateProfile проверяет валидность профиля
func (dpm *DynamicProfileManagerImpl) ValidateProfile(config *ProfileConfig) error {
	if config.Name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}

	if config.Type == "" {
		return fmt.Errorf("profile type cannot be empty")
	}

	if config.Parameters == nil {
		config.Parameters = make(map[string]interface{})
	}

	// Проверяем обязательные параметры в зависимости от типа
	switch config.Type {
	case "protocol":
		if _, exists := config.Parameters["packet_size_min"]; !exists {
			config.Parameters["packet_size_min"] = 8
		}
		if _, exists := config.Parameters["packet_size_max"]; !exists {
			config.Parameters["packet_size_max"] = 16384
		}
	case "social":
		if _, exists := config.Parameters["burst_probability"]; !exists {
			config.Parameters["burst_probability"] = 0.2
		}
	case "mobile":
		if _, exists := config.Parameters["mobile_delay"]; !exists {
			config.Parameters["mobile_delay"] = 50
		}
	}

	return nil
}

// GetProfileStats возвращает статистику профилей
func (dpm *DynamicProfileManagerImpl) GetProfileStats() map[string]*ProfileStats {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	stats := make(map[string]*ProfileStats)
	for name, profile := range dpm.profiles {
		stats[name] = &ProfileStats{
			Name:       name,
			Type:       profile.Type,
			IsActive:   profile.Enabled,
			CreatedAt:  profile.CreatedAt,
			LastUsed:   profile.UpdatedAt,
			UsageCount: 0,
		}
	}

	return stats
}

// CleanupOldProfiles очищает старые неиспользуемые профили
func (dpm *DynamicProfileManagerImpl) CleanupOldProfiles(maxAge time.Duration) int {
	dpm.mutex.Lock()
	defer dpm.mutex.Unlock()

	cutoff := time.Now().Add(-maxAge)
	cleanedCount := 0

	for name, profile := range dpm.profiles {
		if profile.UpdatedAt.Before(cutoff) && !profile.Enabled {
			delete(dpm.profiles, name)
			cleanedCount++
		}
	}

	return cleanedCount
}

// GetAllProfiles возвращает все профили
func (dpm *DynamicProfileManagerImpl) GetAllProfiles() map[string]*ProfileConfig {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	result := make(map[string]*ProfileConfig)
	for name, profile := range dpm.profiles {
		result[name] = profile
	}
	return result
}

// SetActiveProfile устанавливает активный профиль
func (dpm *DynamicProfileManagerImpl) SetActiveProfile(name string) error {
	dpm.mutex.Lock()
	defer dpm.mutex.Unlock()

	if _, exists := dpm.profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	// Здесь можно добавить логику для установки активного профиля
	return nil
}

// GetActiveProfile возвращает имя активного профиля
func (dpm *DynamicProfileManagerImpl) GetActiveProfile() string {
	dpm.mutex.RLock()
	profile := ""
	dpm.mutex.RUnlock()

	// Здесь можно добавить логику для получения активного профиля
	return profile
}

// Reset сбрасывает все профили
func (dpm *DynamicProfileManagerImpl) Reset() {
	dpm.mutex.Lock()
	defer dpm.mutex.Unlock()

	dpm.profiles = make(map[string]*ProfileConfig)
}
