package obfuscation

import (
	"time"
	"whispera/internal/obfuscation/core/evasion"
	"whispera/internal/obfuscation/core/types"
)

// MarionetteAdapter provides backward compatibility for the old marionette.go interface
// This adapter allows existing code to continue working while using the new modular architecture
type MarionetteAdapter struct {
	core *evasion.Marionette
}

// NewMarionetteAdapter creates a new adapter for backward compatibility
func NewMarionetteAdapter() *MarionetteAdapter {
	return &MarionetteAdapter{
		core: evasion.NewMarionette(),
	}
}

// ProcessPacket processes a packet through the obfuscation system
func (ma *MarionetteAdapter) ProcessPacket(data []byte, direction string) ([]byte, time.Duration, error) {
	return ma.core.ProcessPacket(data, direction)
}

// SetActiveProfile sets the active traffic profile
func (ma *MarionetteAdapter) SetActiveProfile(name string) error {
	return ma.core.SetActiveProfile(name)
}

// GetState returns the current traffic state
func (ma *MarionetteAdapter) GetState() *types.TrafficState {
	return ma.core.GetState()
}

// GetProfileNames returns all available profile names
func (ma *MarionetteAdapter) GetProfileNames() []string {
	return ma.core.GetProfileNames()
}

// GetActiveProfile returns the active profile name
func (ma *MarionetteAdapter) GetActiveProfile() string {
	return ma.core.GetActiveProfile()
}

// GetAdaptiveLearning returns the adaptive learning system
func (ma *MarionetteAdapter) GetAdaptiveLearning() types.AdaptiveLearning {
	return ma.core.GetAdaptiveLearning()
}

// GetEffectivenessMetrics returns the effectiveness metrics
func (ma *MarionetteAdapter) GetEffectivenessMetrics() *evasion.EffectivenessMetrics {
	return ma.core.GetEffectivenessMetrics()
}

// GetSystemMetrics returns system performance metrics
func (ma *MarionetteAdapter) GetSystemMetrics() *evasion.SystemMetrics {
	return ma.core.GetSystemMetrics()
}

// HealthCheck performs a comprehensive health check
func (ma *MarionetteAdapter) HealthCheck() map[string]interface{} {
	return ma.core.HealthCheck()
}

// GetCore returns the underlying core Marionette instance
func (ma *MarionetteAdapter) GetCore() *evasion.Marionette {
	return ma.core
}

// SwitchProfile switches to a new profile (for API compatibility)
func (ma *MarionetteAdapter) SwitchProfile(targetProfile, reason string) error {
	return ma.core.SwitchProfile(targetProfile, reason)
}

// GetCurrentProfile returns the current active profile (for API compatibility)
func (ma *MarionetteAdapter) GetCurrentProfile() string {
	return ma.core.GetCurrentProfile()
}

// GetProfileSwitchHistory returns profile switch history (for API compatibility)
func (ma *MarionetteAdapter) GetProfileSwitchHistory() []types.ProfileSwitch {
	return ma.core.GetProfileSwitchHistory()
}

// AddProfile adds a new profile (for API compatibility)
func (ma *MarionetteAdapter) AddProfile(name string, config map[string]interface{}) error {
	return ma.core.AddProfile(name, config)
}

// RemoveProfile removes a profile (for API compatibility)
func (ma *MarionetteAdapter) RemoveProfile(name string) error {
	return ma.core.RemoveProfile(name)
}

// ApplyProductionDPIEvasion applies production DPI evasion techniques (for API compatibility)
func (ma *MarionetteAdapter) ApplyProductionDPIEvasion(data []byte, service string) ([]byte, time.Duration, error) {
	return ma.core.ApplyProductionDPIEvasion(data, service)
}

// StartDynamicManager starts the dynamic profile manager (for API compatibility)
func (ma *MarionetteAdapter) StartDynamicManager() {
	ma.core.StartDynamicManager()
}
