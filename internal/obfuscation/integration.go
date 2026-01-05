package obfuscation

import (
	"time"
	"whispera/internal/obfuscation/core/types"
	ftepkg "whispera/internal/obfuscation/fte"
	marionettepkg "whispera/internal/obfuscation/marionette"
	mlpkg "whispera/internal/obfuscation/ml"
)

const (
	statusActive   = "active"
	statusInactive = "inactive"
)

// IntegrationManager manages integration between modules
type IntegrationManager struct {
	marionette *marionettepkg.Marionette
	adapter    *marionettepkg.MarionetteAdapter
	mlSystem   *mlpkg.UnifiedMLSystem
	fte        *ftepkg.FTE
	mlEnabled  bool
	fteEnabled bool
}

// NewIntegrationManager creates a new integration manager
func NewIntegrationManager() *IntegrationManager {
	adapter := marionettepkg.NewMarionetteAdapter()
	mlSystem := mlpkg.NewUnifiedMLSystem()
	fte := ftepkg.NewFTE()

	return &IntegrationManager{
		marionette: adapter.GetCore(),
		adapter:    adapter,
		mlSystem:   mlSystem,
		fte:        fte,
		mlEnabled:  true,
		fteEnabled: true,
	}
}

// NewIntegrationManagerWithOptions creates a new integration manager with options
func NewIntegrationManagerWithOptions(enableML, enableFTE bool) *IntegrationManager {
	adapter := marionettepkg.NewMarionetteAdapter()
	im := &IntegrationManager{
		marionette: adapter.GetCore(),
		adapter:    adapter,
		mlEnabled:  enableML,
		fteEnabled: enableFTE,
	}

	if enableML {
		im.mlSystem = mlpkg.NewUnifiedMLSystem()
	}
	if enableFTE {
		im.fte = ftepkg.NewFTE()
	}

	return im
}

// ProcessTraffic processes traffic through the integrated system
// Order: FTE -> Marionette -> ML (if enabled)
func (im *IntegrationManager) ProcessTraffic(data []byte, direction string) ([]byte, time.Duration, error) {
	processed := data

	// Step 1: FTE transformation (if enabled)
	if im.fteEnabled && im.fte != nil {
		transformed, err := im.fte.Transform(processed)
		if err == nil && transformed != nil && len(transformed) > 0 {
			processed = transformed
		}
	}

	// Step 2: Marionette obfuscation
	processed, delay, err := im.adapter.ProcessPacket(processed, direction)
	if err != nil {
		return data, 0, err
	}

	// Step 3: ML processing (if enabled and packet is large enough)
	if im.mlEnabled && im.mlSystem != nil && len(processed) > 2048 {
		context := &types.UnifiedTrafficContext{
			Direction: direction,
			Protocol:  "tcp", // Will be set by caller if needed
			Size:      len(processed),
			Timestamp: time.Now(),
		}

		mlProcessed, mlErr := im.mlSystem.ProcessTraffic(processed, context)
		if mlErr == nil && mlProcessed != nil && len(mlProcessed) > 0 {
			processed = mlProcessed
		}
	}

	return processed, delay, err
}

// ProcessTrafficWithML processes traffic with explicit ML context
func (im *IntegrationManager) ProcessTrafficWithML(data []byte, direction string, protocol string) ([]byte, time.Duration, error) {
	processed := data

	// Step 1: FTE transformation (if enabled)
	if im.fteEnabled && im.fte != nil {
		transformed, err := im.fte.Transform(processed)
		if err == nil && transformed != nil && len(transformed) > 0 {
			processed = transformed
		}
	}

	// Step 2: Marionette obfuscation
	processed, delay, err := im.adapter.ProcessPacket(processed, direction)
	if err != nil {
		return data, 0, err
	}

	// Step 3: ML processing (if enabled and packet is large enough)
	if im.mlEnabled && im.mlSystem != nil && len(processed) > 2048 {
		// log.Printf("[ML] Processing %d bytes (%s, %s)", len(processed), direction, protocol)
		context := &types.UnifiedTrafficContext{
			Direction: direction,
			Protocol:  protocol,
			Size:      len(processed),
			Timestamp: time.Now(),
		}

		mlProcessed, mlErr := im.mlSystem.ProcessTraffic(processed, context)
		if mlErr == nil && mlProcessed != nil && len(mlProcessed) > 0 {
			processed = mlProcessed
		}
	}

	return processed, delay, err
}

// GetMLSystem returns the ML system instance
func (im *IntegrationManager) GetMLSystem() *mlpkg.UnifiedMLSystem {
	return im.mlSystem
}

// GetFTE returns the FTE instance
func (im *IntegrationManager) GetFTE() *ftepkg.FTE {
	return im.fte
}

// GetMarionetteAdapter returns the Marionette adapter
func (im *IntegrationManager) GetMarionetteAdapter() *marionettepkg.MarionetteAdapter {
	return im.adapter
}

// SetProfile sets the active traffic profile
func (im *IntegrationManager) SetProfile(name string) error {
	return im.adapter.SetActiveProfile(name)
}

// SetStrict enables or disables strict obfuscation mode
func (im *IntegrationManager) SetStrict(strict bool) {
	im.adapter.SetStrict(strict)
}

// GetHealthStatus returns the health status of all modules
func (im *IntegrationManager) GetHealthStatus() map[string]interface{} {
	health := make(map[string]interface{})

	// Get Marionette health
	health["marionette"] = im.adapter.HealthCheck()

	// Get ML system health
	if im.marionette.GetAdaptiveLearning() != nil {
		health["adaptive_learning"] = statusActive
	} else {
		health["adaptive_learning"] = statusInactive
	}

	// Get effectiveness metrics
	if im.marionette.GetEffectivenessMetrics() != nil {
		health["effectiveness_metrics"] = statusActive
	} else {
		health["effectiveness_metrics"] = statusInactive
	}

	// Get system metrics
	systemMetrics := im.adapter.GetSystemMetrics()
	health["system_metrics"] = map[string]interface{}{
		"packets_processed": systemMetrics.PacketsProcessed,
		"ml_predictions":    systemMetrics.MLPredictions,
		"ml_failures":       systemMetrics.MLFailures,
		"average_latency":   time.Duration(systemMetrics.AverageLatency).String(),
		"memory_usage":      systemMetrics.MemoryUsage,
	}

	return health
}

// GetAvailableProfiles returns all available traffic profiles
func (im *IntegrationManager) GetAvailableProfiles() []string {
	return im.adapter.GetProfileNames()
}

// GetTrafficState returns the current traffic state
func (im *IntegrationManager) GetTrafficState() *types.TrafficState {
	return im.adapter.GetState()
}

// GetPerformanceMetrics returns performance metrics
func (im *IntegrationManager) GetPerformanceMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})

	// Get system metrics
	systemMetrics := im.adapter.GetSystemMetrics()
	metrics["system"] = map[string]interface{}{
		"packets_processed":     systemMetrics.PacketsProcessed,
		"ml_predictions":        systemMetrics.MLPredictions,
		"ml_failures":           systemMetrics.MLFailures,
		"average_latency":       time.Duration(systemMetrics.AverageLatency).String(),
		"memory_usage":          systemMetrics.MemoryUsage,
		"circuit_breaker_trips": systemMetrics.CircuitBreakerTrips,
	}

	// Get traffic state metrics
	state := im.adapter.GetState()
	metrics["traffic"] = map[string]interface{}{
		"total_packets":       state.TotalPackets,
		"total_bytes":         state.TotalBytes,
		"outbound_packets":    state.OutboundPackets,
		"outbound_bytes":      state.OutboundBytes,
		"inbound_packets":     state.InboundPackets,
		"inbound_bytes":       state.InboundBytes,
		"average_packet_size": state.AveragePacketSize,
		"average_interval":    state.AverageInterval.String(),
		"burst_count":         state.BurstCount,
		"idle_count":          state.IdleCount,
		"session_duration":    state.SessionDuration.String(),
		"current_profile":     state.CurrentProfile,
		"ml_predictions":      state.MLPredictions,
		"ml_failures":         state.MLFailures,
		"evasion_successes":   state.EvasionSuccesses,
		"evasion_failures":    state.EvasionFailures,
	}

	return metrics
}

// ResetSystem resets the system to initial state
func (im *IntegrationManager) ResetSystem() error {
	// Reset Marionette state
	im.adapter = marionettepkg.NewMarionetteAdapter()
	im.marionette = im.adapter.GetCore()

	return nil
}

// GetModuleStatus returns the status of all modules
func (im *IntegrationManager) GetModuleStatus() map[string]string {
	status := make(map[string]string)

	// Check Marionette status
	if im.marionette != nil {
		status["marionette"] = "active"
	} else {
		status["marionette"] = "inactive"
	}

	// Check ML system status
	if im.marionette.GetAdaptiveLearning() != nil {
		status["adaptive_learning"] = "active"
	} else {
		status["adaptive_learning"] = "inactive"
	}

	// Check effectiveness metrics status
	if im.marionette.GetEffectivenessMetrics() != nil {
		status["effectiveness_metrics"] = "active"
	} else {
		status["effectiveness_metrics"] = "inactive"
	}

	return status
}
