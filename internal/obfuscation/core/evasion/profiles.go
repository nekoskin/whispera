package evasion

import (
	"fmt"
	"time"

	"whispera/internal/obfuscation/core/types"
)

const profileDefault = "default"

// SetActiveProfile sets the active traffic profile
func (m *Marionette) SetActiveProfile(name string) error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	if _, exists := m.Profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	m.Active = name
	return nil
}

// GetState returns the current traffic state
func (m *Marionette) GetState() *types.TrafficState {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()
	return m.State
}

// GetProfileNames returns all available profile names
func (m *Marionette) GetProfileNames() []string {
	m.Mutex.RLock()
	profileCount := len(m.Profiles)
	m.Mutex.RUnlock()

	names := make([]string, 0, profileCount)

	m.Mutex.RLock()
	for name := range m.Profiles {
		names = append(names, name)
	}
	m.Mutex.RUnlock()

	return names
}

// GetActiveProfile returns the active profile name
func (m *Marionette) GetActiveProfile() string {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()
	return m.Active
}

// SwitchProfile switches to a new profile (for API compatibility)
func (m *Marionette) SwitchProfile(targetProfile, reason string) error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	if targetProfile == "" {
		return fmt.Errorf("target profile cannot be empty")
	}
	if reason == "" {
		reason = "manual_switch"
	}

	oldProfile := m.Active

	if _, exists := m.Profiles[targetProfile]; !exists {
		return fmt.Errorf("profile '%s' does not exist", targetProfile)
	}

	if oldProfile == targetProfile {
		return fmt.Errorf("profile '%s' is already active", targetProfile)
	}

	m.Active = targetProfile

	if m.DynamicManager != nil {
		m.DynamicManager.SwitchProfile(targetProfile, reason)
	}

	return nil
}

// GetCurrentProfile returns the current active profile (for API compatibility)
func (m *Marionette) GetCurrentProfile() string {
	return m.GetActiveProfile()
}

// GetProfileSwitchHistory returns profile switch history (for API compatibility)
func (m *Marionette) GetProfileSwitchHistory() []types.ProfileSwitch {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()

	if m.DynamicManager == nil {
		return []types.ProfileSwitch{}
	}
	return m.DynamicManager.GetProfileSwitchHistory()
}

// AddProfile adds a new profile (for API compatibility)
func (m *Marionette) AddProfile(name string, config map[string]interface{}) error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	if _, exists := m.Profiles[name]; exists {
		return fmt.Errorf("profile %s already exists", name)
	}

	profile := &types.TrafficProfile{
		Name: name,
		Type: "custom",
	}

	if val, ok := config["type"].(string); ok {
		profile.Type = val
	}

	m.Profiles[name] = profile
	return nil
}

// RemoveProfile removes a profile (for API compatibility)
func (m *Marionette) RemoveProfile(name string) error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	if _, exists := m.Profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	if m.Active == name {
		return fmt.Errorf("cannot remove active profile %s, switch to another profile first", name)
	}

	delete(m.Profiles, name)
	return nil
}

// StartDynamicManager starts the dynamic profile manager background tasks
func (m *Marionette) StartDynamicManager() {
	if m.DynamicManager != nil {
		// Background monitoring logic if needed
	}
}

// initDefaultProfiles initializes default traffic profiles
func (m *Marionette) initDefaultProfiles() {
	profiles := make(map[string]*types.TrafficProfile, 3)
	profiles[profileDefault] = &types.TrafficProfile{Name: profileDefault}
	profiles["web"] = &types.TrafficProfile{Name: "web"}
	profiles["secure"] = &types.TrafficProfile{Name: "secure"}

	for name, profile := range profiles {
		m.Profiles[name] = profile
	}

	m.Active = profileDefault
}

// initRussianServiceProfiles initializes Russian service profiles
func (m *Marionette) initRussianServiceProfiles() {
	russianProfiles := make(map[string]*types.TrafficProfile, 3)
	russianProfiles["vk"] = &types.TrafficProfile{Name: "vk"}
	russianProfiles["yandex"] = &types.TrafficProfile{Name: "yandex"}
	russianProfiles["mailru"] = &types.TrafficProfile{Name: "mailru"}

	for name, profile := range russianProfiles {
		m.Profiles[name] = profile
	}
}

// initMobileDeviceProfiles initializes mobile device profiles
func (m *Marionette) initMobileDeviceProfiles() {
	mobileProfiles := make(map[string]*types.TrafficProfile, 2)
	mobileProfiles["android"] = &types.TrafficProfile{Name: "android"}
	mobileProfiles["ios"] = &types.TrafficProfile{Name: "ios"}

	for name, profile := range mobileProfiles {
		m.Profiles[name] = profile
	}
}

// initDynamicProfileManager initializes dynamic profile manager
func (m *Marionette) initDynamicProfileManager() {
	m.DynamicManager = &DynamicProfileManagerImpl{
		ProfileHistory: make([]types.ProfileSwitch, 0, 100),
		SwitchCooldown: 5 * time.Second,
	}
}

// getCurrentServiceProfileName возвращает имя текущего сервисного профиля
func (m *Marionette) getCurrentServiceProfileName() string {
	return m.State.CurrentProfile
}

// --- Dynamic Profile Manager ---

// DynamicProfileManagerImpl implements dynamic profile management
type DynamicProfileManagerImpl struct {
	ActiveProfile  string
	ProfileHistory []types.ProfileSwitch
	LastSwitchTime time.Time
	SwitchCooldown time.Duration
}

// CheckProfileSwitch checks if a profile switch is needed
func (dpm *DynamicProfileManagerImpl) CheckProfileSwitch() {
}

// SwitchProfile records a profile switch
func (dpm *DynamicProfileManagerImpl) SwitchProfile(targetProfile, reason string) error {
	fromProfile := dpm.ActiveProfile
	dpm.ActiveProfile = targetProfile
	dpm.LastSwitchTime = time.Now()

	switchEvent := types.ProfileSwitch{
		FromProfile:   fromProfile,
		ToProfile:     targetProfile,
		Timestamp:     dpm.LastSwitchTime,
		Reason:        reason,
		Success:       true,
		Effectiveness: 0.0,
	}
	dpm.ProfileHistory = append(dpm.ProfileHistory, switchEvent)
	return nil
}

// GetProfileSwitchHistory returns the history of profile switches
func (dpm *DynamicProfileManagerImpl) GetProfileSwitchHistory() []types.ProfileSwitch {
	return dpm.ProfileHistory
}

// GetCurrentProfile returns the current active profile
func (dpm *DynamicProfileManagerImpl) GetCurrentProfile() string {
	return dpm.ActiveProfile
}

// --- Rules Evaluation ---

// evaluateCondition evaluates a rule condition
func (m *Marionette) evaluateCondition(condition types.Condition) bool {
	switch condition.Type {
	case "packet_size":
		return m.evaluatePacketSizeCondition(condition)
	case "direction":
		return m.evaluateDirectionCondition(condition)
	case "protocol":
		return m.evaluateProtocolCondition(condition)
	case "threat_level":
		return m.evaluateThreatLevelCondition(condition)
	case "burst_detection":
		return m.evaluateBurstCondition(condition)
	case "idle_detection":
		return m.evaluateIdleCondition(condition)
	case "ml_prediction":
		return m.evaluateMLPredictionCondition(condition)
	case "composite":
		return m.evaluateCompositeCondition(condition)
	case "always":
		return true
	case "packet_count":
		if condition.Operator == ">" {
			if val, ok := condition.Value.(int); ok {
				return m.State.PacketCount > val
			}
		}
		return false
	default:
		return true
	}
}

func (m *Marionette) evaluatePacketSizeCondition(condition types.Condition) bool {
	if len(m.State.RecentPacketSizes) == 0 {
		return false
	}
	lastIdx := (m.State.RecentPacketSizesIdx - 1 + len(m.State.RecentPacketSizes)) % len(m.State.RecentPacketSizes)
	lastSize := m.State.RecentPacketSizes[lastIdx]
	expectedValue, ok := condition.Value.(int)
	if !ok {
		return false
	}

	switch condition.Operator {
	case ">":
		return lastSize > expectedValue
	case "<":
		return lastSize < expectedValue
	case ">=":
		return lastSize >= expectedValue
	case "<=":
		return lastSize <= expectedValue
	case "==":
		return lastSize == expectedValue
	case "!=":
		return lastSize != expectedValue
	default:
		return false
	}
}

func (m *Marionette) evaluateDirectionCondition(condition types.Condition) bool {
	expectedDirection, ok := condition.Value.(string)
	if !ok {
		return false
	}
	switch condition.Operator {
	case "==":
		return m.State.Direction == expectedDirection
	case "!=":
		return m.State.Direction != expectedDirection
	default:
		return false
	}
}

func (m *Marionette) evaluateProtocolCondition(condition types.Condition) bool {
	expectedProtocol, ok := condition.Value.(string)
	if !ok {
		return false
	}
	switch condition.Operator {
	case "==":
		return m.State.Protocol == expectedProtocol
	case "!=":
		return m.State.Protocol != expectedProtocol
	default:
		return false
	}
}

func (m *Marionette) evaluateThreatLevelCondition(condition types.Condition) bool {
	expectedLevel, ok := condition.Value.(int)
	if !ok {
		return false
	}
	switch condition.Operator {
	case ">":
		return m.State.ThreatLevel > expectedLevel
	case "<":
		return m.State.ThreatLevel < expectedLevel
	case ">=":
		return m.State.ThreatLevel >= expectedLevel
	case "<=":
		return m.State.ThreatLevel <= expectedLevel
	case "==":
		return m.State.ThreatLevel == expectedLevel
	case "!=":
		return m.State.ThreatLevel != expectedLevel
	default:
		return false
	}
}

func (m *Marionette) evaluateBurstCondition(condition types.Condition) bool {
	expectedCount, ok := condition.Value.(int)
	if !ok {
		return false
	}
	switch condition.Operator {
	case ">":
		return m.State.BurstCount > expectedCount
	case "<":
		return m.State.BurstCount < expectedCount
	case ">=":
		return m.State.BurstCount >= expectedCount
	case "<=":
		return m.State.BurstCount <= expectedCount
	case "==":
		return m.State.BurstCount == expectedCount
	case "!=":
		return m.State.BurstCount != expectedCount
	default:
		return false
	}
}

func (m *Marionette) evaluateIdleCondition(condition types.Condition) bool {
	expectedCount, ok := condition.Value.(int)
	if !ok {
		return false
	}
	switch condition.Operator {
	case ">":
		return m.State.IdleCount > expectedCount
	case "<":
		return m.State.IdleCount < expectedCount
	case ">=":
		return m.State.IdleCount >= expectedCount
	case "<=":
		return m.State.IdleCount <= expectedCount
	case "==":
		return m.State.IdleCount == expectedCount
	case "!=":
		return m.State.IdleCount != expectedCount
	default:
		return false
	}
}

func (m *Marionette) evaluateMLPredictionCondition(condition types.Condition) bool {
	expectedValue, ok := condition.Value.(bool)
	if !ok {
		return false
	}
	mlUsed := false
	if len(m.State.PacketHistory) > 0 {
		lastIdx := (m.State.PacketHistoryIdx - 1 + len(m.State.PacketHistory)) % len(m.State.PacketHistory)
		lastPacket := m.State.PacketHistory[lastIdx]
		mlUsed = lastPacket.MLUsed
	}
	switch condition.Operator {
	case "==":
		return mlUsed == expectedValue
	case "!=":
		return mlUsed != expectedValue
	default:
		return false
	}
}

func (m *Marionette) evaluateCompositeCondition(condition types.Condition) bool {
	if len(condition.Children) == 0 {
		return true
	}
	result := m.evaluateCondition(condition.Children[0])
	for i := 1; i < len(condition.Children); i++ {
		childResult := m.evaluateCondition(condition.Children[i])
		switch condition.LogicalOp {
		case "AND":
			result = result && childResult
		case "OR":
			result = result || childResult
		case "NOT":
			result = !childResult
		default:
			result = result && childResult
		}
	}
	return result
}

// --- Rule Creation & Initialization ---

func (m *Marionette) createRule(name, conditionType, conditionField, conditionOp string, conditionValue interface{}, actionType, actionMethod string, params map[string]interface{}, priority int) types.ObfuscationRule {
	return types.ObfuscationRule{
		Name: name,
		Condition: types.Condition{
			Type:     conditionType,
			Field:    conditionField,
			Operator: conditionOp,
			Value:    conditionValue,
		},
		Action: types.Action{
			Type:       actionType,
			Method:     actionMethod,
			Parameters: params,
			Priority:   priority,
			Enabled:    true,
		},
		Parameters: params,
		Priority:   priority,
		Enabled:    true,
	}
}

func (m *Marionette) initDefaultRules() {
	m.Rules = []types.ObfuscationRule{
		{
			Name:       "size_shaping",
			Condition:  types.Condition{Type: "always"},
			Action:     types.Action{Type: "resize", Method: "shape_size", Parameters: map[string]interface{}{"target_size": 1200}, Priority: 1, Enabled: true},
			Parameters: map[string]interface{}{"method": "weighted_random", "bins": []int{8, 32, 128, 512, 2048}, "weights": []float64{0.3, 0.25, 0.2, 0.15, 0.1}}, // Kept params for reference
			Priority:   1, Enabled: true,
		},
		{
			Name:       "timing_shaping",
			Condition:  types.Condition{Type: "always"},
			Action:     types.Action{Type: "delay", Method: "shape_timing", Parameters: map[string]interface{}{"delay_ms": 50}, Priority: 2, Enabled: true},
			Parameters: map[string]interface{}{"method": "exponential", "min_interval": 20, "max_interval": 150, "mean_interval": 50},
			Priority:   2, Enabled: true,
		},
		{
			Name:      "burst_detection",
			Condition: types.Condition{Type: "packet_count", Field: "packet_count", Operator: ">", Value: 5},
			Action:    types.Action{Type: "behavioral_mimicry", Method: "enable_burst", Parameters: map[string]interface{}{"type": "service_behavior"}, Priority: 3, Enabled: true},
			Priority:  3, Enabled: true,
		},
		m.createRule("dpi_evasion", "threat_level", "threat_level", ">", 5, "dpi_evasion", "increase_obfuscation", map[string]interface{}{"type": "ja3_evasion"}, 10),
		m.createRule("russian_service_evasion", "protocol", "protocol", "in", []string{"vk", "yandex", "mailru"}, "apply_russian_mimicry", "apply_russian_mimicry", map[string]interface{}{}, 8),
		m.createRule("advanced_ml_evasion", "threat_level", "threat_level", ">", 7, "ml_evasion", "apply_ml_evasion", map[string]interface{}{"adversarial_examples": true}, 9),
		// m.createRule("adaptive_learning", "adaptation_enabled", "", "", nil, "learn_patterns", "learn_patterns", map[string]interface{}{}, 11),
	}
}
