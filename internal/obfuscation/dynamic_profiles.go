package obfuscation

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"whispera/internal/obfuscation/core/types"
	"whispera/internal/util"
)

const (
	profileYandex  = "yandex"
	profileMailru  = "mailru"
	profileRutube  = "rutube"
	profileOzon    = "ozon"
	profileUnknown = "unknown"
)

// secureRandInt generates a random integer from 0 to max (exclusive) using crypto/rand
func secureRandInt(maxVal int) int {
	if maxVal <= 0 {
		return 0
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(maxVal)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

// secureRandInt63n generates a random int64 from 0 to max (exclusive) using crypto/rand
func secureRandInt63n(maxVal int64) int64 {
	if maxVal <= 0 {
		return 0
	}
	n, err := crand.Int(crand.Reader, big.NewInt(maxVal))
	if err != nil {
		return 0
	}
	return n.Int64()
}

// secureRandFloat64 generates a random float64 between 0.0 and 1.0
func secureRandFloat64() float64 {
	b := make([]byte, 8)
	if _, err := crand.Read(b); err != nil {
		return 0.0
	}
	val := binary.BigEndian.Uint64(b)
	return float64(val) / float64(^uint64(0))
}

// DynamicProfileSwitchRule - правило переключения профиля
type DynamicProfileSwitchRule struct {
	ID            string
	Name          string
	Condition     string
	TargetProfile string
	Priority      int
	Enabled       bool
	Parameters    map[string]interface{}
}

// DynamicTimeBasedRule - правило на основе времени
type DynamicTimeBasedRule struct {
	ID            string
	Name          string
	StartTime     string
	EndTime       string
	Days          []string
	TargetProfile string
	Enabled       bool
}

// DynamicContextAnalyzer - анализатор контекста
type DynamicContextAnalyzer struct {
	NetworkType  string
	Location     string
	TimeOfDay    string
	UserBehavior string
	ThreatLevel  int
	LastUpdate   time.Time
}

// DynamicNetworkAnalyzer - анализатор сети
type DynamicNetworkAnalyzer struct {
	Latency    time.Duration
	Bandwidth  int64
	PacketLoss float64
	Jitter     time.Duration
	Stability  float64
	LastUpdate time.Time
}

// DynamicProfileManagerImpl - менеджер динамических профилей
type DynamicProfileManagerImpl struct {
	profileHistory  []types.ProfileSwitch
	switchRules     []DynamicProfileSwitchRule
	timeBasedRules  []DynamicTimeBasedRule
	contextAnalyzer *DynamicContextAnalyzer
	networkAnalyzer *DynamicNetworkAnalyzer
	activeProfile   string
	lastSwitchTime  time.Time
	switchCooldown  time.Duration
	adaptiveEnabled bool
}

// ============================================================================
// DYNAMIC PROFILE MANAGEMENT FUNCTIONS
// ============================================================================

// NewDynamicProfileManager creates a new dynamic profile manager
func NewDynamicProfileManager() *DynamicProfileManagerImpl {
	return &DynamicProfileManagerImpl{
		profileHistory: make([]types.ProfileSwitch, 0),
		switchRules:    make([]DynamicProfileSwitchRule, 0),
		timeBasedRules: make([]DynamicTimeBasedRule, 0),
		contextAnalyzer: &DynamicContextAnalyzer{
			NetworkType:  "unknown",
			Location:     "unknown",
			TimeOfDay:    "unknown",
			UserBehavior: "unknown",
			ThreatLevel:  0,
			LastUpdate:   time.Now(),
		},
		networkAnalyzer: &DynamicNetworkAnalyzer{
			Latency:    50 * time.Millisecond,
			Bandwidth:  1000000, // 1MB/s
			PacketLoss: 0.0,
			Jitter:     5 * time.Millisecond,
			Stability:  0.9,
			LastUpdate: time.Now(),
		},
		lastSwitchTime:  time.Now(),
		switchCooldown:  30 * time.Second,
		adaptiveEnabled: true,
	}
}

// initDynamicProfileManager initializes dynamic profile management
func (m *Marionette) initDynamicProfileManager() {
	m.dynamicManager = NewDynamicProfileManager()

	// Initialize default switch rules
	m.initDefaultSwitchRules()

	// Initialize time-based rules
	m.initTimeBasedRules()

	// Start context monitoring
	// go m.monitorContext() // Moved to explicit Start() call
}

// StartDynamicManager starts the dynamic profile manager background tasks
func (m *Marionette) StartDynamicManager() {
	go m.monitorContext()
}

// initDefaultSwitchRules creates default profile switch rules
func (m *Marionette) initDefaultSwitchRules() {
	// High threat level -> more aggressive profiles
	m.dynamicManager.switchRules = append(m.dynamicManager.switchRules, DynamicProfileSwitchRule{
		ID:            "high_threat_switch",
		Name:          "High Threat Profile Switch",
		Condition:     "threat_level > 7",
		TargetProfile: "vk",
		Priority:      10,
		Enabled:       true,
		Parameters: map[string]interface{}{
			"min_threat_level": 7,
			"cooldown":         "5m",
		},
	})

	// Network instability -> stable profiles
	m.dynamicManager.switchRules = append(m.dynamicManager.switchRules, DynamicProfileSwitchRule{
		ID:            "network_instability_switch",
		Name:          "Network Instability Switch",
		Condition:     "network_stability < 0.5",
		TargetProfile: profileYandex,
		Priority:      8,
		Enabled:       true,
		Parameters: map[string]interface{}{
			"max_stability": 0.5,
			"cooldown":      "2m",
		},
	})

	// Mobile network -> mobile profiles
	m.dynamicManager.switchRules = append(m.dynamicManager.switchRules, DynamicProfileSwitchRule{
		ID:            "mobile_network_switch",
		Name:          "Mobile Network Switch",
		Condition:     "network_type == mobile",
		TargetProfile: "mobile_vk",
		Priority:      6,
		Enabled:       true,
		Parameters: map[string]interface{}{
			"network_types": []string{"mobile", "cellular"},
			"cooldown":      "1m",
		},
	})
}

// initTimeBasedRules creates time-based profile switching rules
func (m *Marionette) initTimeBasedRules() {
	// Morning (6-12) -> Yandex (search activity)
	m.dynamicManager.timeBasedRules = append(m.dynamicManager.timeBasedRules, DynamicTimeBasedRule{
		ID:            "morning_yandex",
		Name:          "Morning Yandex Profile",
		StartTime:     "06:00",
		EndTime:       "12:00",
		Days:          []string{"monday", "tuesday", "wednesday", "thursday", "friday"},
		TargetProfile: profileYandex,
		Enabled:       true,
	})

	// Afternoon (12-18) -> VK (social activity)
	m.dynamicManager.timeBasedRules = append(m.dynamicManager.timeBasedRules, DynamicTimeBasedRule{
		ID:            "afternoon_vk",
		Name:          "Afternoon VK Profile",
		StartTime:     "12:00",
		EndTime:       "18:00",
		Days:          []string{"monday", "tuesday", "wednesday", "thursday", "friday"},
		TargetProfile: "vk",
		Enabled:       true,
	})

	// Evening (18-24) -> Rutube (entertainment)
	m.dynamicManager.timeBasedRules = append(m.dynamicManager.timeBasedRules, DynamicTimeBasedRule{
		ID:            "evening_rutube",
		Name:          "Evening Rutube Profile",
		StartTime:     "18:00",
		EndTime:       "24:00",
		Days:          []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"},
		TargetProfile: profileRutube,
		Enabled:       true,
	})

	// Night (0-6) -> Mail.ru (email activity)
	m.dynamicManager.timeBasedRules = append(m.dynamicManager.timeBasedRules, DynamicTimeBasedRule{
		ID:            "night_mailru",
		Name:          "Night Mail.ru Profile",
		StartTime:     "00:00",
		EndTime:       "06:00",
		Days:          []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"},
		TargetProfile: profileMailru,
		Enabled:       true,
	})
}

// monitorContext continuously monitors network and user context
func (m *Marionette) monitorContext() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Use goroutine to avoid blocking
		go func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("Error in context monitoring: %v\n", r)
				}
			}()

			m.updateContext()
			m.checkProfileSwitch()
		}()
	}
}

// updateContext updates the context analyzer
func (m *Marionette) updateContext() {
	now := time.Now()

	// Update time of day
	hour := now.Hour()
	switch {
	case hour >= 6 && hour < 12:
		m.dynamicManager.contextAnalyzer.TimeOfDay = "morning"
	case hour >= 12 && hour < 18:
		m.dynamicManager.contextAnalyzer.TimeOfDay = "afternoon"
	case hour >= 18 && hour < 24:
		m.dynamicManager.contextAnalyzer.TimeOfDay = "evening"
	default:
		m.dynamicManager.contextAnalyzer.TimeOfDay = "night"
	}

	// Update user behavior based on traffic patterns
	m.dynamicManager.contextAnalyzer.UserBehavior = m.analyzeUserBehavior()

	// Update threat level based on DPI detection
	m.dynamicManager.contextAnalyzer.ThreatLevel = m.analyzeThreatLevel()

	// Update network conditions
	m.updateNetworkConditions()

	m.dynamicManager.contextAnalyzer.LastUpdate = now
}

// analyzeUserBehavior analyzes user behavior from traffic patterns
func (m *Marionette) analyzeUserBehavior() string {
	// Analyze recent traffic patterns to determine user behavior
	recentSizes := m.state.RecentPacketSizes
	if len(recentSizes) == 0 {
		return profileUnknown
	}

	avgSize := 0
	for _, size := range recentSizes {
		avgSize += size
	}
	avgSize /= len(recentSizes)

	// Classify behavior based on packet sizes and patterns
	switch {
	case avgSize < 100:
		return "browsing" // Small packets = web browsing
	case avgSize < 1000:
		return "working" // Medium packets = work applications
	case avgSize < 5000:
		return "streaming" // Large packets = video/audio streaming
	default:
		return "gaming" // Very large packets = gaming
	}
}

// analyzeThreatLevel analyzes current threat level
func (m *Marionette) analyzeThreatLevel() int {
	// Analyze recent DPI detection events
	recentDetections := m.state.RecentDPIDetections
	if len(recentDetections) == 0 {
		return 0
	}

	// Calculate threat level based on detection frequency
	detectionRate := float64(len(recentDetections)) / 100.0 // Last 100 packets

	switch {
	case detectionRate < 0.1:
		return 1 // Low threat
	case detectionRate < 0.3:
		return 3 // Medium threat
	case detectionRate < 0.5:
		return 6 // High threat
	default:
		return 9 // Very high threat
	}
}

// updateNetworkConditions updates network analyzer
func (m *Marionette) updateNetworkConditions() {
	// Simulate network condition updates
	// In real implementation, this would measure actual network conditions

	now := time.Now()

	// Simulate latency measurement
	m.dynamicManager.networkAnalyzer.Latency = 30*time.Millisecond + time.Duration(secureRandInt(40))*time.Millisecond

	// Simulate bandwidth measurement
	m.dynamicManager.networkAnalyzer.Bandwidth = 1000000 + secureRandInt63n(5000000) // 1-6 MB/s

	// Simulate packet loss
	m.dynamicManager.networkAnalyzer.PacketLoss = secureRandFloat64() * 0.05 // 0-5%

	// Simulate jitter
	m.dynamicManager.networkAnalyzer.Jitter = time.Duration(secureRandInt(20)) * time.Millisecond

	// Calculate stability
	m.dynamicManager.networkAnalyzer.Stability = 1.0 - (m.dynamicManager.networkAnalyzer.PacketLoss + float64(m.dynamicManager.networkAnalyzer.Jitter)/1000000)

	m.dynamicManager.networkAnalyzer.LastUpdate = now
}

// checkProfileSwitch checks if profile should be switched
func (m *Marionette) checkProfileSwitch() {
	// Check cooldown
	if time.Since(m.dynamicManager.lastSwitchTime) < m.dynamicManager.switchCooldown {
		return
	}

	// Check time-based rules first
	if targetProfile := m.checkTimeBasedRules(); targetProfile != "" {
		// Only switch if target is different from current
		if targetProfile != m.dynamicManager.activeProfile {
			if err := m.switchProfile(targetProfile, "time_based"); err != nil {
				// Only log if it's not the "already active" error (which is expected)
				if !strings.Contains(err.Error(), "already active") {
					fmt.Printf("Failed to switch to time-based profile: %v\n", err)
				}
			}
		}
		return
	}

	// Check context-based rules
	if targetProfile := m.checkContextBasedRules(); targetProfile != "" {
		if err := m.switchProfile(targetProfile, "context_based"); err != nil {
			fmt.Printf("Failed to switch to context-based profile: %v\n", err)
		}
		return
	}
}

// checkTimeBasedRules checks time-based switching rules
func (m *Marionette) checkTimeBasedRules() string {
	now := time.Now()
	currentTime := now.Format("15:04")
	currentDay := now.Weekday().String()

	for _, rule := range m.dynamicManager.timeBasedRules {
		if !rule.Enabled {
			continue
		}

		// Check if current day matches
		dayMatch := false
		for _, day := range rule.Days {
			if strings.EqualFold(day, currentDay) {
				dayMatch = true
				break
			}
		}
		if !dayMatch {
			continue
		}

		// Check if current time is within rule time range
		if currentTime >= rule.StartTime && currentTime <= rule.EndTime {
			return rule.TargetProfile
		}
	}

	return ""
}

// checkContextBasedRules checks context-based switching rules
func (m *Marionette) checkContextBasedRules() string {
	context := m.dynamicManager.contextAnalyzer
	network := m.dynamicManager.networkAnalyzer

	for _, rule := range m.dynamicManager.switchRules {
		if !rule.Enabled {
			continue
		}

		// Evaluate rule condition
		if m.evaluateRuleCondition(rule, context, network) {
			return rule.TargetProfile
		}
	}

	return ""
}

// evaluateRuleCondition evaluates a rule condition
func (m *Marionette) evaluateRuleCondition(rule DynamicProfileSwitchRule, context *DynamicContextAnalyzer, network *DynamicNetworkAnalyzer) bool {
	switch rule.Condition {
	case "threat_level > 7":
		return context.ThreatLevel > 7
	case "network_stability < 0.5":
		return network.Stability < 0.5
	case "network_type == mobile":
		return context.NetworkType == "mobile"
	default:
		return false
	}
}

// SwitchProfile switches to a new profile (публичный метод для API)
func (m *Marionette) SwitchProfile(targetProfile, reason string) error {
	return m.switchProfile(targetProfile, reason)
}

// switchProfile switches to a new profile (приватная реализация)
func (m *Marionette) switchProfile(targetProfile, reason string) error {
	// Validate input parameters
	if targetProfile == "" {
		return fmt.Errorf("target profile cannot be empty")
	}
	if reason == "" {
		return fmt.Errorf("switch reason cannot be empty")
	}

	oldProfile := m.dynamicManager.activeProfile

	// Check if profile exists
	if _, exists := m.profiles[targetProfile]; !exists {
		return fmt.Errorf("profile '%s' does not exist", targetProfile)
	}

	// Validate profile is different from current (double-check to prevent race conditions)
	if oldProfile == targetProfile {
		return fmt.Errorf("profile '%s' is already active", targetProfile)
	}
	
	// Additional check: if another switch just happened, skip this one
	if time.Since(m.dynamicManager.lastSwitchTime) < 100*time.Millisecond {
		return fmt.Errorf("profile switch too soon after last switch (cooldown)")
	}

	// Perform the switch
	if err := m.SetActiveProfile(targetProfile); err != nil {
		return fmt.Errorf("failed to set active profile: %w", err)
	}

	// Record the switch
	switchEvent := types.ProfileSwitch{
		FromProfile:   oldProfile,
		ToProfile:     targetProfile,
		Timestamp:     time.Now(),
		Reason:        reason,
		Success:       true,
		Effectiveness: 0.0, // Will be updated later
	}

	m.dynamicManager.profileHistory = append(m.dynamicManager.profileHistory, switchEvent)
	m.dynamicManager.activeProfile = targetProfile
	m.dynamicManager.lastSwitchTime = time.Now()

	// Log the switch (without sensitive data)
	if oldProfile == "" {
		fmt.Printf("Profile initialized: -> %s (reason: %s)\n", targetProfile, reason)
	} else {
		fmt.Printf("Profile switched: %s -> %s (reason: %s)\n", oldProfile, targetProfile, reason)
	}

	return nil
}

// GetCurrentProfile returns the current active profile
func (m *Marionette) GetCurrentProfile() string {
	return m.dynamicManager.activeProfile
}

// GetProfileSwitchHistory returns profile switch history
func (m *Marionette) GetProfileSwitchHistory() []types.ProfileSwitch {
	return m.dynamicManager.profileHistory
}

// ============================================================================
// MOBILE DEVICE PROFILES
// ============================================================================

// initMobileDeviceProfiles initializes mobile device profiles
func (m *Marionette) initMobileDeviceProfiles() {
	// Android VK mobile app
	m.profiles["mobile_vk_android"] = &types.TrafficProfile{
		Name: "VK Mobile Android",
		SizeDistribution: &types.SizeDistribution{
			Min: 32, Max: 4096, Mean: 256, StdDev: 128,
			Weights: []float64{0.4, 0.3, 0.2, 0.1},
			Bins:    []int{32, 128, 512, 2048},
		},
		IntervalDistribution: &types.IntervalDistribution{
			Min: 50 * time.Millisecond, Max: 300 * time.Millisecond,
			Mean: 100 * time.Millisecond, StdDev: 50 * time.Millisecond,
			Pattern: "exponential",
		},
	}

	// iOS VK mobile app
	m.profiles["mobile_vk_ios"] = &types.TrafficProfile{
		Name: "VK Mobile iOS",
		SizeDistribution: &types.SizeDistribution{
			Min: 32, Max: 4096, Mean: 256, StdDev: 128,
			Weights: []float64{0.4, 0.3, 0.2, 0.1},
			Bins:    []int{32, 128, 512, 2048},
		},
		IntervalDistribution: &types.IntervalDistribution{
			Min: 50 * time.Millisecond, Max: 300 * time.Millisecond,
			Mean: 100 * time.Millisecond, StdDev: 50 * time.Millisecond,
			Pattern: "exponential",
		},
	}

	// Android Yandex mobile app
	m.profiles["mobile_yandex_android"] = &types.TrafficProfile{
		Name: "Yandex Mobile Android",
		SizeDistribution: &types.SizeDistribution{
			Min: 24, Max: 4096, Mean: 200, StdDev: 100,
			Weights: []float64{0.5, 0.3, 0.15, 0.05},
			Bins:    []int{24, 96, 384, 1536},
		},
		IntervalDistribution: &types.IntervalDistribution{
			Min: 30 * time.Millisecond, Max: 200 * time.Millisecond,
			Mean: 80 * time.Millisecond, StdDev: 40 * time.Millisecond,
			Pattern: "exponential",
		},
	}
}

// ============================================================================
// REAL API INTEGRATION
// ============================================================================

// RealAPIIntegration handles integration with real Russian service APIs
type RealAPIIntegration struct {
	VKAPI      *VKAPIClient
	YandexAPI  *YandexAPIClient
	MailruAPI  *MailruAPIClient
	RutubeAPI  *RutubeAPIClient
	OzonAPI    *OzonAPIClient
	enabled    bool
	rateLimits map[string]time.Time
}

// VKAPIClient handles VK API integration
type VKAPIClient struct {
	BaseURL     string
	APIVersion  string
	AccessToken string
	UserID      string
	httpClient  *http.Client
}

// YandexAPIClient handles Yandex API integration
type YandexAPIClient struct {
	BaseURL    string
	APIKey     string
	UserID     string
	httpClient *http.Client
}

// MailruAPIClient handles Mail.ru API integration
type MailruAPIClient struct {
	BaseURL    string
	APIKey     string
	UserID     string
	httpClient *http.Client
}

// RutubeAPIClient handles Rutube API integration
type RutubeAPIClient struct {
	BaseURL    string
	APIKey     string
	UserID     string
	httpClient *http.Client
}

// OzonAPIClient handles Ozon API integration
type OzonAPIClient struct {
	BaseURL    string
	APIKey     string
	UserID     string
	httpClient *http.Client
}

// NewRealAPIIntegration creates a new real API integration
// createSecureAPIHTTPClient создает безопасный HTTP клиент для API запросов
func createSecureAPIHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
				InsecureSkipVerify: false, // Проверка сертификатов обязательна для внешних API
			},
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: timeout,
	}
}

func NewRealAPIIntegration() *RealAPIIntegration {
	return &RealAPIIntegration{
		VKAPI: &VKAPIClient{
			BaseURL:     "https://api.vk.com/method",
			APIVersion:  "5.131",
			AccessToken: "vk1.a.1234567890abcdef",
			UserID:      "12345678",
			httpClient:  createSecureAPIHTTPClient(30 * time.Second),
		},
		YandexAPI: &YandexAPIClient{
			BaseURL:    "https://api.weather.yandex.ru/v2",
			APIKey:     "yandex-api-key",
			UserID:     "yandex_user_789012",
			httpClient: createSecureAPIHTTPClient(30 * time.Second),
		},
		MailruAPI: &MailruAPIClient{
			BaseURL:    "https://cloud.mail.ru/api/v2",
			APIKey:     "mailru-api-key",
			UserID:     "mailru_user_456789",
			httpClient: createSecureAPIHTTPClient(30 * time.Second),
		},
		RutubeAPI: &RutubeAPIClient{
			BaseURL:    "https://rutube.ru/api",
			APIKey:     "rutube-api-key",
			UserID:     "rutube_user_012345",
			httpClient: createSecureAPIHTTPClient(30 * time.Second),
		},
		OzonAPI: &OzonAPIClient{
			BaseURL:    "https://api.ozon.ru/composer-api.bx",
			APIKey:     "ozon-api-key",
			UserID:     "ozon_user_678901",
			httpClient: createSecureAPIHTTPClient(30 * time.Second),
		},
		enabled:    true,
		rateLimits: make(map[string]time.Time),
	}
}

// GenerateRealisticTraffic generates realistic traffic using real APIs
func (m *Marionette) GenerateRealisticTraffic(service string, data []byte) ([]byte, error) {
	if m.realAPI == nil {
		m.realAPI = NewRealAPIIntegration()
	}

	switch service {
	case "vk":
		return m.generateVKTraffic(data)
	case profileYandex:
		return m.generateYandexTraffic(data)
	case profileMailru:
		return m.generateMailruTraffic(data)
	case profileRutube:
		return m.generateRutubeTraffic(data)
	case profileOzon:
		return m.generateOzonTraffic(data)
	default:
		return data, nil
	}
}

// generateVKTraffic generates realistic VK traffic
func (m *Marionette) generateVKTraffic(data []byte) ([]byte, error) {
	// Check rate limit
	if time.Since(m.realAPI.rateLimits["vk"]) < 1*time.Second {
		return data, nil
	}

	// Generate realistic VK API request
	requestData := map[string]interface{}{
		"method":       "users.get",
		"user_ids":     "12345678",
		"fields":       "online,last_seen",
		"access_token": m.realAPI.VKAPI.AccessToken,
		"v":            m.realAPI.VKAPI.APIVersion,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return data, err
	}

	// Create realistic VK request
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, "POST", m.realAPI.VKAPI.BaseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return data, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VKAndroidApp/7.0.1234 (Android 14; SM-G991B)")
	req.Header.Set("X-VK-Android", "7.0.1234")
	req.Header.Set("X-VK-Device", "SM-G991B")

	// Execute real VK API request
	resp, err := m.realAPI.VKAPI.httpClient.Do(req)
	if err != nil {
		// Log error but continue with fallback
		fmt.Printf("VK API request failed: %v\n", err)
		return data, nil
	}
	defer util.SafeClose("resp.Body", resp.Body.Close)

	// Read response for realistic traffic
	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// Use response data to enhance obfuscation
		if len(body) > 0 {
			enhancedData := make([]byte, len(data)+len(body))
			copy(enhancedData, data)
			copy(enhancedData[len(data):], body)
			data = enhancedData
		}
	}

	// Update rate limit
	m.realAPI.rateLimits["vk"] = time.Now()

	// Return enhanced data with VK-specific headers
	enhancedData := make([]byte, len(data)+len(jsonData))
	copy(enhancedData, data)
	copy(enhancedData[len(data):], jsonData)

	return enhancedData, nil
}

// generateYandexTraffic generates realistic Yandex traffic
func (m *Marionette) generateYandexTraffic(data []byte) ([]byte, error) {
	// Check rate limit
	if time.Since(m.realAPI.rateLimits[profileYandex]) < 2*time.Second {
		return data, nil
	}

	// Generate realistic Yandex API request
	requestData := map[string]interface{}{
		"lat":   55.7558,
		"lon":   37.6176,
		"lang":  "ru_RU",
		"limit": 1,
		"hours": false,
		"extra": false,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return data, err
	}

	// Update rate limit
	m.realAPI.rateLimits["yandex"] = time.Now()

	// Return enhanced data with Yandex-specific headers
	enhancedData := make([]byte, len(data)+len(jsonData))
	copy(enhancedData, data)
	copy(enhancedData[len(data):], jsonData)

	return enhancedData, nil
}

// generateMailruTraffic generates realistic Mail.ru traffic
func (m *Marionette) generateMailruTraffic(data []byte) ([]byte, error) {
	// Check rate limit
	if time.Since(m.realAPI.rateLimits["mailru"]) < 3*time.Second {
		return data, nil
	}

	// Generate realistic Mail.ru API request
	requestData := map[string]interface{}{
		"method":       "mail.folders",
		"access_token": m.realAPI.MailruAPI.APIKey,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return data, err
	}

	// Update rate limit
	m.realAPI.rateLimits["mailru"] = time.Now()

	// Return enhanced data with Mail.ru-specific headers
	enhancedData := make([]byte, len(data)+len(jsonData))
	copy(enhancedData, data)
	copy(enhancedData[len(data):], jsonData)

	return enhancedData, nil
}

// generateRutubeTraffic generates realistic Rutube traffic
func (m *Marionette) generateRutubeTraffic(data []byte) ([]byte, error) {
	// Check rate limit
	if time.Since(m.realAPI.rateLimits["rutube"]) < 2*time.Second {
		return data, nil
	}

	// Generate realistic Rutube API request
	requestData := map[string]interface{}{
		"method":       "video.get",
		"video_id":     "123456789",
		"access_token": m.realAPI.RutubeAPI.APIKey,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return data, err
	}

	// Update rate limit
	m.realAPI.rateLimits["rutube"] = time.Now()

	// Return enhanced data with Rutube-specific headers
	enhancedData := make([]byte, len(data)+len(jsonData))
	copy(enhancedData, data)
	copy(enhancedData[len(data):], jsonData)

	return enhancedData, nil
}

// generateOzonTraffic generates realistic Ozon traffic
func (m *Marionette) generateOzonTraffic(data []byte) ([]byte, error) {
	// Check rate limit
	if time.Since(m.realAPI.rateLimits["ozon"]) < 5*time.Second {
		return data, nil
	}

	// Generate realistic Ozon API request
	requestData := map[string]interface{}{
		"method":       "product.search",
		"query":        "смартфон",
		"limit":        20,
		"access_token": m.realAPI.OzonAPI.APIKey,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return data, err
	}

	// Update rate limit
	m.realAPI.rateLimits["ozon"] = time.Now()

	// Return enhanced data with Ozon-specific headers
	enhancedData := make([]byte, len(data)+len(jsonData))
	copy(enhancedData, data)
	copy(enhancedData[len(data):], jsonData)

	return enhancedData, nil
}
