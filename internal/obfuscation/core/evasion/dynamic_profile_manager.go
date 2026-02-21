package evasion

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

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

type AdvancedDynamicProfileManager interface {
	AddProfile(name string, config *AdvancedProfileConfig) error
	RemoveProfile(name string) error
	GetProfile(name string) (*AdvancedProfileConfig, error)
	GetAllProfiles() map[string]*AdvancedProfileConfig
	UpdateProfile(name string, config *AdvancedProfileConfig) error
	SetActiveProfile(name string) error
	GetActiveProfile() string
}

type AdvancedProfileManagerImpl struct {
	profiles map[string]*AdvancedProfileConfig
	mutex    sync.RWMutex
}

func NewAdvancedProfileManager() AdvancedDynamicProfileManager {
	return &AdvancedProfileManagerImpl{
		profiles: make(map[string]*AdvancedProfileConfig),
	}
}

func (dpm *AdvancedProfileManagerImpl) AddProfile(name string, config *AdvancedProfileConfig) error {
	dpm.mutex.Lock()
	defer dpm.mutex.Unlock()

	if _, exists := dpm.profiles[name]; exists {
		return fmt.Errorf("profile %s already exists", name)
	}

	dpm.profiles[name] = config
	return nil
}

func (dpm *AdvancedProfileManagerImpl) RemoveProfile(name string) error {
	dpm.mutex.Lock()
	defer dpm.mutex.Unlock()

	if _, exists := dpm.profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	delete(dpm.profiles, name)
	return nil
}

func (dpm *AdvancedProfileManagerImpl) GetProfile(name string) (*AdvancedProfileConfig, error) {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	config, ok := dpm.profiles[name]
	if !ok {
		return nil, fmt.Errorf("profile %s not found", name)
	}

	return config, nil
}

func (dpm *AdvancedProfileManagerImpl) GetAllProfiles() map[string]*AdvancedProfileConfig {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	copyMap := make(map[string]*AdvancedProfileConfig)
	for k, v := range dpm.profiles {
		copyMap[k] = v
	}

	return copyMap
}

func (dpm *AdvancedProfileManagerImpl) UpdateProfile(name string, config *AdvancedProfileConfig) error {
	dpm.mutex.Lock()
	defer dpm.mutex.Unlock()

	if _, exists := dpm.profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	dpm.profiles[name] = config
	return nil
}

func (dpm *AdvancedProfileManagerImpl) SetActiveProfile(name string) error {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	if _, exists := dpm.profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	return nil
}

func (dpm *AdvancedProfileManagerImpl) GetActiveProfile() string {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	for name, config := range dpm.profiles {
		if config.Enabled {
			return name
		}
	}

	return ""
}

func (dpm *AdvancedProfileManagerImpl) SaveToFile(filename string) error {
	dpm.mutex.RLock()
	defer dpm.mutex.RUnlock()

	data, err := json.MarshalIndent(dpm.profiles, "", "  ")
	if err != nil {
		return err
	}

	_ = data
	return nil
}

func (dpm *AdvancedProfileManagerImpl) LoadFromFile(filename string) error {
	return nil
}
