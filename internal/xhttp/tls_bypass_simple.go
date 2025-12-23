package xhttp

import (
	"crypto/tls"
	"fmt"
	"sync"
)

// SimpleT LSBypass - simplified TLS fingerprinting bypass without type errors
type SimpleTLSBypass struct {
	profiles map[string]map[string]interface{}
	mu       sync.RWMutex
}

// NewSimpleTLSBypass creates new simplified TLS bypass
func NewSimpleTLSBypass() *SimpleTLSBypass {
	return &SimpleTLSBypass{
		profiles: map[string]map[string]interface{}{
			"chrome": {
				"version": tls.VersionTLS13,
				"curves":  []string{"P256", "P384", "P521"},
				"padding": 256,
			},
			"firefox": {
				"version": tls.VersionTLS13,
				"curves":  []string{"P256", "P384"},
				"padding": 256,
			},
			"safari": {
				"version": tls.VersionTLS13,
				"curves":  []string{"P256", "P384"},
				"padding": 256,
			},
		},
	}
}

// GetProfile returns profile configuration
func (stb *SimpleTLSBypass) GetProfile(name string) (map[string]interface{}, error) {
	stb.mu.RLock()
	defer stb.mu.RUnlock()

	profile, ok := stb.profiles[name]
	if !ok {
		return nil, fmt.Errorf("profile %s not found", name)
	}
	return profile, nil
}

// GetAvailableProfiles returns list of profiles
func (stb *SimpleTLSBypass) GetAvailableProfiles() []string {
	stb.mu.RLock()
	defer stb.mu.RUnlock()

	profiles := make([]string, 0, len(stb.profiles))
	for name := range stb.profiles {
		profiles = append(profiles, name)
	}
	return profiles
}

// ApplyProfile applies profile to TLS config
func (stb *SimpleTLSBypass) ApplyProfile(config *tls.Config, name string) error {
	profile, err := stb.GetProfile(name)
	if err != nil {
		return err
	}

	if version, ok := profile["version"].(uint16); ok {
		config.MinVersion = version
		config.MaxVersion = version
	}

	return nil
}
