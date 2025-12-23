package split_tunnel //nolint:revive // Package name matches directory structure

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"whispera/internal/app_detection"
)

// SplitTunnelRule represents a single split tunneling rule
type SplitTunnelRule struct {
	Type        string `json:"type"`   // "ip", "domain", "app", "port"
	Value       string `json:"value"`  // IP, domain, app name, or port
	Action      string `json:"action"` // "tunnel" or "direct"
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority"` // Higher number = higher priority
	Created     int64  `json:"created"`
	Modified    int64  `json:"modified"`
}

// SplitTunnelConfig represents the complete split tunneling configuration
type SplitTunnelConfig struct {
	Mode          string            `json:"mode"` // "exclude" or "include"
	Rules         []SplitTunnelRule `json:"rules"`
	DefaultAction string            `json:"default_action"` // "tunnel" or "direct"
	Enabled       bool              `json:"enabled"`
	Version       string            `json:"version"`
}

// SplitTunnelManager manages split tunneling rules and decisions
type SplitTunnelManager struct {
	config      *SplitTunnelConfig
	rules       []SplitTunnelRule
	appDetector *app_detection.AppDetector
}

// NewSplitTunnelManager creates a new split tunnel manager
func NewSplitTunnelManager() *SplitTunnelManager {
	return &SplitTunnelManager{
		config: &SplitTunnelConfig{
			Mode:          "exclude",
			DefaultAction: "tunnel",
			Enabled:       false,
			Version:       "1.0",
			Rules:         []SplitTunnelRule{},
		},
		rules:       []SplitTunnelRule{},
		appDetector: app_detection.NewAppDetector(),
	}
}

// LoadConfig loads split tunneling configuration from file
func (stm *SplitTunnelManager) LoadConfig(filename string) error {
	if filename == "" {
		return nil
	}

	data, err := os.ReadFile(filename) //nolint:gosec // Filename is validated by caller
	if err != nil {
		return fmt.Errorf("failed to read split tunnel config: %w", err)
	}

	var config SplitTunnelConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse split tunnel config: %w", err)
	}

	stm.config = &config
	stm.rules = config.Rules

	return nil
}

// SaveConfig saves split tunneling configuration to file
func (stm *SplitTunnelManager) SaveConfig(filename string) error {
	if filename == "" {
		return nil
	}

	stm.config.Rules = stm.rules
	data, err := json.MarshalIndent(stm.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal split tunnel config: %w", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write split tunnel config: %w", err)
	}

	return nil
}

// AddRule adds a new split tunneling rule
func (stm *SplitTunnelManager) AddRule(rule *SplitTunnelRule) {
	rule.Created = time.Now().Unix()
	rule.Modified = time.Now().Unix()
	stm.rules = append(stm.rules, *rule)
}

// RemoveRule removes a split tunneling rule by index
func (stm *SplitTunnelManager) RemoveRule(index int) bool {
	if index < 0 || index >= len(stm.rules) {
		return false
	}
	stm.rules = append(stm.rules[:index], stm.rules[index+1:]...)
	return true
}

// UpdateRule updates an existing split tunneling rule
func (stm *SplitTunnelManager) UpdateRule(index int, rule *SplitTunnelRule) bool {
	if index < 0 || index >= len(stm.rules) {
		return false
	}
	rule.Modified = time.Now().Unix()
	stm.rules[index] = *rule
	return true
}

// GetRules returns all split tunneling rules
func (stm *SplitTunnelManager) GetRules() []SplitTunnelRule {
	return stm.rules
}

// SetMode sets the split tunneling mode
func (stm *SplitTunnelManager) SetMode(mode string) {
	stm.config.Mode = mode
}

// SetEnabled enables or disables split tunneling
func (stm *SplitTunnelManager) SetEnabled(enabled bool) {
	stm.config.Enabled = enabled
}

// ShouldTunnel determines if traffic should go through the tunnel
func (stm *SplitTunnelManager) ShouldTunnel(destIP, destPort, appName string) bool {
	if !stm.config.Enabled {
		return true // Default to tunneling everything
	}

	// Check rules in priority order (highest first)
	for _, rule := range stm.rules {
		if !rule.Enabled {
			continue
		}

		if stm.matchesRule(&rule, destIP, destPort, appName) {
			return rule.Action == "tunnel"
		}
	}

	// Default action based on mode
	return stm.config.DefaultAction == "tunnel"
}

// matchesRule checks if a rule matches the given parameters
func (stm *SplitTunnelManager) matchesRule(rule *SplitTunnelRule, destIP, destPort, appName string) bool {
	switch rule.Type {
	case "ip":
		return stm.matchesIP(rule.Value, destIP)
	case "domain":
		// For domain matching, we'd need DNS resolution
		// This is a simplified version
		return strings.Contains(destIP, rule.Value)
	case "app":
		return stm.matchesApp(rule.Value, appName)
	case "port":
		return destPort == rule.Value
	default:
		return false
	}
}

// matchesIP checks if an IP matches a rule (supports CIDR notation)
func (stm *SplitTunnelManager) matchesIP(ruleValue, destIP string) bool {
	// Direct IP match
	if ruleValue == destIP {
		return true
	}

	// CIDR match
	_, network, err := net.ParseCIDR(ruleValue)
	if err != nil {
		return false
	}

	ip := net.ParseIP(destIP)
	if ip == nil {
		return false
	}

	return network.Contains(ip)
}

// matchesApp checks if an application matches a rule
func (stm *SplitTunnelManager) matchesApp(ruleValue, appName string) bool {
	// Direct name match
	if strings.EqualFold(appName, ruleValue) {
		return true
	}

	// Pattern match (contains)
	if strings.Contains(strings.ToLower(appName), strings.ToLower(ruleValue)) {
		return true
	}

	// Check if the app is currently running
	if stm.appDetector != nil {
		return stm.appDetector.IsProcessRunning(ruleValue)
	}

	return false
}

// GetConfig returns the current configuration
func (stm *SplitTunnelManager) GetConfig() *SplitTunnelConfig {
	stm.config.Rules = stm.rules
	return stm.config
}

// CreateDefaultRules creates some default split tunneling rules
func (stm *SplitTunnelManager) CreateDefaultRules() {
	// Local network exclusions
	rule := SplitTunnelRule{
		Type:        "ip",
		Value:       "192.168.0.0/16",
		Action:      "direct",
		Description: "Local network (192.168.x.x)",
		Enabled:     true,
		Priority:    100,
	}
	stm.AddRule(&rule)

	rule = SplitTunnelRule{
		Type:        "ip",
		Value:       "10.0.0.0/8",
		Action:      "direct",
		Description: "Local network (10.x.x.x)",
		Enabled:     true,
		Priority:    100,
	}
	stm.AddRule(&rule)

	rule = SplitTunnelRule{
		Type:        "ip",
		Value:       "172.16.0.0/12",
		Action:      "direct",
		Description: "Local network (172.16-31.x.x)",
		Enabled:     true,
		Priority:    100,
	}
	stm.AddRule(&rule)

	// Localhost
	rule = SplitTunnelRule{
		Type:        "ip",
		Value:       "127.0.0.0/8",
		Action:      "direct",
		Description: "Localhost",
		Enabled:     true,
		Priority:    100,
	}
	stm.AddRule(&rule)
}

// StartAppDetection starts application detection
func (stm *SplitTunnelManager) StartAppDetection(interval time.Duration) {
	if stm.appDetector != nil {
		stm.appDetector.StartScanning(interval)
	}
}

// StopAppDetection stops application detection
func (stm *SplitTunnelManager) StopAppDetection() {
	if stm.appDetector != nil {
		stm.appDetector.StopScanning()
	}
}

// GetRunningApps returns list of currently running applications
func (stm *SplitTunnelManager) GetRunningApps() []string {
	if stm.appDetector == nil {
		return []string{}
	}
	return stm.appDetector.GetExecutableList()
}

// GetPopularApps returns list of popular applications
func (stm *SplitTunnelManager) GetPopularApps() []string {
	if stm.appDetector == nil {
		return []string{}
	}
	return stm.appDetector.GetPopularApplications()
}

// GetSystemApps returns list of system applications
func (stm *SplitTunnelManager) GetSystemApps() []string {
	if stm.appDetector == nil {
		return []string{}
	}
	return stm.appDetector.GetSystemApplications()
}

// AddAppRule adds a rule for a specific application
func (stm *SplitTunnelManager) AddAppRule(appName, action, description string) {
	rule := SplitTunnelRule{
		Type:        "app",
		Value:       appName,
		Action:      action,
		Description: description,
		Enabled:     true,
		Priority:    50,
	}
	stm.AddRule(&rule)
}

// GetAppSuggestions returns suggested applications for rules
func (stm *SplitTunnelManager) GetAppSuggestions() []string {
	if stm.appDetector == nil {
		return []string{}
	}
	return stm.appDetector.SuggestAppRules()
}

// ValidateAppRule validates an application rule
func (stm *SplitTunnelManager) ValidateAppRule(ruleValue string) error {
	if stm.appDetector == nil {
		return fmt.Errorf("app detector not initialized")
	}
	return stm.appDetector.ValidateAppRule(ruleValue)
}
