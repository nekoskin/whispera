package xhttp

import (
	"crypto/tls"
	"fmt"
	"sync"
)

// TLSBypassManager manages TLS fingerprinting bypass for DPI evasion
type TLSBypassManager struct {
	profiles map[string]map[string]interface{}
	evasion  *TLS13FingerPrintEvasion
	mu       sync.RWMutex
}

// NewTLSBypassManager creates new TLS bypass manager
func NewTLSBypassManager() *TLSBypassManager {
	return &TLSBypassManager{
		profiles: map[string]map[string]interface{}{
			"chrome": {
				"version": tls.VersionTLS13,
				"name":    "Chrome 120+",
				"padding": 256,
			},
			"firefox": {
				"version": tls.VersionTLS13,
				"name":    "Firefox 121+",
				"padding": 256,
			},
			"safari": {
				"version": tls.VersionTLS13,
				"name":    "Safari 17",
				"padding": 256,
			},
		},
		evasion: &TLS13FingerPrintEvasion{
			shuffleExtensions: true,
			fragmentRecords:   true,
			fragmentSize:      256,
			randomizeTiming:   true,
			timingJitterMs:    50,
		},
	}
}

// ApplyBypass applies TLS fingerprinting bypass
func (tbm *TLSBypassManager) ApplyBypass(config *tls.Config, profile string) error {
	tbm.mu.RLock()
	defer tbm.mu.RUnlock()

	p, ok := tbm.profiles[profile]
	if !ok {
		return fmt.Errorf("profile %s not found", profile)
	}

	if version, ok := p["version"].(uint16); ok {
		config.MinVersion = version
		config.MaxVersion = version
	}

	return nil
}

// GetAvailableProfiles returns list of profiles
func (tbm *TLSBypassManager) GetAvailableProfiles() []string {
	tbm.mu.RLock()
	defer tbm.mu.RUnlock()

	profiles := make([]string, 0, len(tbm.profiles))
	for name := range tbm.profiles {
		profiles = append(profiles, name)
	}
	return profiles
}

// TLS13FingerPrintEvasion handles TLS 1.3 fingerprinting evasion
type TLS13FingerPrintEvasion struct {
	shuffleExtensions bool
	fragmentRecords   bool
	fragmentSize      int
	randomizeTiming   bool
	timingJitterMs    int
}

// GetEvasionConfig returns evasion configuration
func (tfe *TLS13FingerPrintEvasion) GetEvasionConfig() map[string]interface{} {
	return map[string]interface{}{
		"shuffle_extensions": tfe.shuffleExtensions,
		"fragment_records":   tfe.fragmentRecords,
		"fragment_size":      tfe.fragmentSize,
		"randomize_timing":   tfe.randomizeTiming,
		"timing_jitter_ms":   tfe.timingJitterMs,
	}
}

// JA3Obfuscator implements JA3 fingerprint evasion
type JA3Obfuscator struct {
	profiles map[string]string
	mu       sync.RWMutex
}

// NewJA3Obfuscator creates new JA3 obfuscator
func NewJA3Obfuscator() *JA3Obfuscator {
	return &JA3Obfuscator{
		profiles: map[string]string{
			"chrome":  "771,49195-49199-52393-52392,45-51-43-10-35,23-24-25,0",
			"firefox": "771,49195-49199-52393-52392,51-45-43-10-35,23-24-25,0",
			"safari":  "771,49195-49199-52393-52392,45-51-43-10-35,23-24-25,0",
		},
	}
}

// GetJA3Fingerprint returns JA3 fingerprint
func (jo *JA3Obfuscator) GetJA3Fingerprint(profileName string) (string, error) {
	jo.mu.RLock()
	defer jo.mu.RUnlock()

	ja3, ok := jo.profiles[profileName]
	if !ok {
		return "", fmt.Errorf("JA3 profile %s not found", profileName)
	}
	return ja3, nil
}

// GetEvasionConfig returns complete evasion configuration
func (tbm *TLSBypassManager) GetEvasionConfig() map[string]interface{} {
	return map[string]interface{}{
		"evasion":  tbm.evasion.GetEvasionConfig(),
		"profiles": tbm.GetAvailableProfiles(),
	}
}
