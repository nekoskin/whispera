package marionette

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"whispera/internal/obfuscation/core/types"
	mlpkg "whispera/internal/obfuscation/ml"
	"whispera/internal/util"
)

// Reference methods to silence staticcheck unused warnings
var _ = []interface{}{
	(*Marionette).performAdaptiveLearning,
}

// --- Dynamic Manager Types (formerly marionette_dynamic_manager_types.go) ---

type DynamicProfileManagerImpl struct {
	activeProfile   string
	profileHistory  []types.ProfileSwitch
	switchRules     []DynamicProfileSwitchRule
	timeBasedRules  []DynamicTimeBasedRule
	contextAnalyzer *DynamicContextAnalyzer
	networkAnalyzer *DynamicNetworkAnalyzer
	lastSwitchTime  time.Time
	switchCooldown  time.Duration
	adaptiveEnabled bool
	mu              sync.RWMutex
}

type DynamicProfileSwitchRule struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Condition     string                 `json:"condition"`
	TargetProfile string                 `json:"target_profile"`
	Priority      int                    `json:"priority"`
	Enabled       bool                   `json:"enabled"`
	Parameters    map[string]interface{} `json:"parameters"`
}

type DynamicTimeBasedRule struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	StartTime     string   `json:"start_time"`
	EndTime       string   `json:"end_time"`
	Days          []string `json:"days"`
	TargetProfile string   `json:"target_profile"`
	Enabled       bool     `json:"enabled"`
}

type DynamicContextAnalyzer struct {
	NetworkType  string    `json:"network_type"`
	Location     string    `json:"location"`
	TimeOfDay    string    `json:"time_of_day"`
	UserBehavior string    `json:"user_behavior"`
	ThreatLevel  int       `json:"threat_level"`
	LastUpdate   time.Time `json:"last_update"`
}

type DynamicNetworkAnalyzer struct {
	Latency    time.Duration `json:"latency"`
	Bandwidth  int64         `json:"bandwidth"`
	PacketLoss float64       `json:"packet_loss"`
	Jitter     time.Duration `json:"jitter"`
	Stability  float64       `json:"stability"`
	LastUpdate time.Time     `json:"last_update"`
}

// --- Dynamic Manager Logic (formerly marionette_dynamic_manager_logic.go) ---

func (m *Marionette) checkProfileSwitch() {
	if time.Since(m.DynamicManager.lastSwitchTime) < m.DynamicManager.switchCooldown {
		return
	}

	if targetProfile := m.checkTimeBasedRules(); targetProfile != "" {
		if targetProfile != m.DynamicManager.activeProfile {
			if err := m.SwitchProfile(targetProfile, "time_based"); err != nil {
				if !strings.Contains(err.Error(), "already active") {
					fmt.Printf("Failed to switch to time-based profile: %v\n", err)
				}
			}
		}
		return
	}

	if targetProfile := m.checkContextBasedRules(); targetProfile != "" {
		if err := m.SwitchProfile(targetProfile, "context_based"); err != nil {
			fmt.Printf("Failed to switch to context-based profile: %v\n", err)
		}
	}
}

func (m *Marionette) SwitchProfile(targetProfile, reason string) error {
	m.DynamicManager.mu.Lock()
	defer m.DynamicManager.mu.Unlock()

	if targetProfile == "" || reason == "" {
		return fmt.Errorf("invalid profile or reason")
	}

	oldProfile := m.DynamicManager.activeProfile
	if _, exists := m.Profiles[targetProfile]; !exists {
		return fmt.Errorf("profile '%s' does not exist", targetProfile)
	}

	if oldProfile == targetProfile {
		return nil // Already active
	}

	if err := m.SetActiveProfile(targetProfile); err != nil {
		return err
	}

	m.DynamicManager.profileHistory = append(m.DynamicManager.profileHistory, types.ProfileSwitch{
		FromProfile: oldProfile, ToProfile: targetProfile, Timestamp: time.Now(), Reason: reason, Success: true,
	})

	m.DynamicManager.activeProfile = targetProfile
	m.DynamicManager.lastSwitchTime = time.Now()
	fmt.Printf("Profile switched: %s -> %s (%s)\n", oldProfile, targetProfile, reason)
	return nil
}

func (m *Marionette) GetProfileSwitchHistory() []types.ProfileSwitch {
	m.DynamicManager.mu.RLock()
	defer m.DynamicManager.mu.RUnlock()
	history := make([]types.ProfileSwitch, len(m.DynamicManager.profileHistory))
	copy(history, m.DynamicManager.profileHistory)
	return history
}

func (m *Marionette) GetCurrentProfile() string {
	m.DynamicManager.mu.RLock()
	defer m.DynamicManager.mu.RUnlock()
	return m.DynamicManager.activeProfile
}

func (m *Marionette) checkTimeBasedRules() string {
	now := time.Now()
	currentTime := now.Format("15:04")
	currentDay := now.Weekday().String()
	for _, rule := range m.DynamicManager.timeBasedRules {
		if !rule.Enabled {
			continue
		}
		dayMatch := false
		for _, day := range rule.Days {
			if strings.EqualFold(day, currentDay) {
				dayMatch = true
				break
			}
		}
		if dayMatch && currentTime >= rule.StartTime && currentTime <= rule.EndTime {
			return rule.TargetProfile
		}
	}
	return ""
}

func (m *Marionette) checkContextBasedRules() string {
	for _, rule := range m.DynamicManager.switchRules {
		if rule.Enabled && m.evaluateRuleCondition(rule, m.DynamicManager.contextAnalyzer, m.DynamicManager.networkAnalyzer) {
			return rule.TargetProfile
		}
	}
	return ""
}

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

// --- Dynamic Manager Monitoring (formerly marionette_dynamic_manager_monitoring.go) ---

func (m *Marionette) monitorContext() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
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

func (m *Marionette) updateContext() {
	now := time.Now()
	hour := now.Hour()
	switch {
	case hour >= 6 && hour < 12:
		m.DynamicManager.contextAnalyzer.TimeOfDay = "morning"
	case hour >= 12 && hour < 18:
		m.DynamicManager.contextAnalyzer.TimeOfDay = "afternoon"
	case hour >= 18 && hour < 24:
		m.DynamicManager.contextAnalyzer.TimeOfDay = "evening"
	default:
		m.DynamicManager.contextAnalyzer.TimeOfDay = "night"
	}
	m.DynamicManager.contextAnalyzer.UserBehavior = m.analyzeUserBehavior()
	m.DynamicManager.contextAnalyzer.ThreatLevel = m.analyzeThreatLevel()
	m.updateNetworkConditions()
	m.DynamicManager.contextAnalyzer.LastUpdate = now
}

func (m *Marionette) analyzeUserBehavior() string {
	recentSizes := m.State.RecentPacketSizes
	if len(recentSizes) == 0 {
		return "unknown"
	}
	avgSize := 0
	for _, size := range recentSizes {
		avgSize += size
	}
	avgSize /= len(recentSizes)
	switch {
	case avgSize < 100:
		return "browsing"
	case avgSize < 1000:
		return "working"
	case avgSize < 5000:
		return "streaming"
	default:
		return "gaming"
	}
}

func (m *Marionette) analyzeThreatLevel() int {
	recentDetections := m.State.RecentDPIDetections
	if len(recentDetections) == 0 {
		return 0
	}
	detectionRate := float64(len(recentDetections)) / 100.0
	switch {
	case detectionRate < 0.1:
		return 1
	case detectionRate < 0.3:
		return 3
	case detectionRate < 0.5:
		return 6
	default:
		return 9
	}
}

func (m *Marionette) updateNetworkConditions() {
	now := time.Now()
	m.DynamicManager.networkAnalyzer.Latency = 30*time.Millisecond + time.Duration(m.generateRealisticRandom(40))*time.Millisecond
	m.DynamicManager.networkAnalyzer.Bandwidth = 1000000 + int64(m.generateRealisticRandom(5000000))
	m.DynamicManager.networkAnalyzer.PacketLoss = m.generateRandomFloat() * 0.05
	m.DynamicManager.networkAnalyzer.Jitter = time.Duration(m.generateRealisticRandom(20)) * time.Millisecond
	m.DynamicManager.networkAnalyzer.Stability = 1.0 - (m.DynamicManager.networkAnalyzer.PacketLoss + float64(m.DynamicManager.networkAnalyzer.Jitter)/1000000)
	m.DynamicManager.networkAnalyzer.LastUpdate = now
}

// --- Dynamic Manager Initialization (formerly marionette_dynamic_manager_init.go) ---

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

func (m *Marionette) initDynamicProfileManager() {
	m.DynamicManager = NewDynamicProfileManager()
	m.initDefaultSwitchRules()
	m.initTimeBasedRules()
}

func (m *Marionette) StartDynamicManager() {
	go m.monitorContext()
}

// --- Dynamic Rules Initialization (formerly marionette_dynamic_rules_init.go) ---

func (m *Marionette) initDefaultSwitchRules() {
	m.DynamicManager.switchRules = append(m.DynamicManager.switchRules, DynamicProfileSwitchRule{
		ID:            "high_threat_switch",
		Name:          "High Threat Profile Switch",
		Condition:     "threat_level > 7",
		TargetProfile: "vk",
		Priority:      10,
		Enabled:       true,
		Parameters:    map[string]interface{}{"min_threat_level": 7, "cooldown": "5m"},
	})

	m.DynamicManager.switchRules = append(m.DynamicManager.switchRules, DynamicProfileSwitchRule{
		ID:            "network_instability_switch",
		Name:          "Network Instability Switch",
		Condition:     "network_stability < 0.5",
		TargetProfile: "yandex",
		Priority:      8,
		Enabled:       true,
		Parameters:    map[string]interface{}{"max_stability": 0.5, "cooldown": "2m"},
	})
}

func (m *Marionette) initTimeBasedRules() {
	m.DynamicManager.timeBasedRules = append(m.DynamicManager.timeBasedRules, DynamicTimeBasedRule{
		ID: "morning_yandex", Name: "Morning Yandex Profile", StartTime: "06:00", EndTime: "12:00",
		Days:          []string{"monday", "tuesday", "wednesday", "thursday", "friday"},
		TargetProfile: "yandex", Enabled: true,
	})

	m.DynamicManager.timeBasedRules = append(m.DynamicManager.timeBasedRules, DynamicTimeBasedRule{
		ID: "afternoon_vk", Name: "Afternoon VK Profile", StartTime: "12:00", EndTime: "18:00",
		Days:          []string{"monday", "tuesday", "wednesday", "thursday", "friday"},
		TargetProfile: "vk", Enabled: true,
	})
}

// --- Dynamic Profiles (formerly marionette_dynamic_profiles.go) ---

func (m *Marionette) createDynamicProfile(name, serviceType string) *types.TrafficProfile {
	profile := &types.TrafficProfile{
		Name:          name,
		PacketSizes:   types.SizeDistribution{Min: 32, Max: 8192, Mean: 512, StdDev: 256, Weights: []float64{0.4, 0.3, 0.2, 0.1}, Bins: []int{32, 128, 512, 2048}},
		Intervals:     types.IntervalDistribution{Min: 50 * time.Millisecond, Max: 200 * time.Millisecond, Mean: 100 * time.Millisecond, StdDev: 50 * time.Millisecond, Pattern: "exponential"},
		BurstPatterns: types.BurstProfile{Probability: 0.2, MinBurst: 2, MaxBurst: 8, BurstGap: 150 * time.Millisecond},
		Coverage:      types.CoverageProfile{Enabled: true, Probability: 0.4, MinSize: 32, MaxSize: 512, Interval: 3 * time.Second},
		Adaptation:    types.AdaptationProfile{Enabled: true, Sensitivity: 0.8, LearningRate: 0.15},
	}
	m.analyzeServiceTraffic(profile, serviceType)
	return profile
}

func (m *Marionette) analyzeServiceTraffic(profile *types.TrafficProfile, serviceType string) {
	switch serviceType {
	case "vk":
		m.analyzeVKTraffic(profile)
	case "yandex":
		m.analyzeYandexTraffic(profile)
	case "mailru":
		m.analyzeMailruTraffic(profile)
	case "ozon":
		m.analyzeOzonTraffic(profile)
	default:
		m.analyzeGenericTraffic(profile)
	}
}

func (m *Marionette) analyzeVKTraffic(profile *types.TrafficProfile) {
	profile.PacketSizes = types.SizeDistribution{Min: 32, Max: 8192, Mean: 512, StdDev: 256, Weights: []float64{0.4, 0.3, 0.2, 0.1}, Bins: []int{32, 128, 512, 2048}}
}

func (m *Marionette) analyzeYandexTraffic(profile *types.TrafficProfile) {
	profile.PacketSizes = types.SizeDistribution{Min: 24, Max: 4096, Mean: 384, StdDev: 192, Weights: []float64{0.3, 0.4, 0.2, 0.1}, Bins: []int{24, 96, 384, 1536}}
}

func (m *Marionette) analyzeMailruTraffic(profile *types.TrafficProfile) {
	profile.PacketSizes = types.SizeDistribution{Min: 28, Max: 6144, Mean: 448, StdDev: 224, Weights: []float64{0.35, 0.3, 0.25, 0.1}, Bins: []int{28, 112, 448, 1792}}
}

func (m *Marionette) analyzeOzonTraffic(profile *types.TrafficProfile) {
	profile.PacketSizes = types.SizeDistribution{Min: 36, Max: 2048, Mean: 288, StdDev: 144, Weights: []float64{0.4, 0.3, 0.2, 0.1}, Bins: []int{36, 144, 288, 1152}}
}

func (m *Marionette) analyzeGenericTraffic(profile *types.TrafficProfile) {
	profile.PacketSizes = types.SizeDistribution{Min: 32, Max: 4096, Mean: 256, StdDev: 128, Weights: []float64{0.3, 0.3, 0.3, 0.1}, Bins: []int{32, 128, 512, 2048}}
}

func (m *Marionette) updateProfileFromRealTraffic(profile *types.TrafficProfile, _ string) {
	if len(m.State.PacketSizes) > 100 {
		recent := m.State.PacketSizes[len(m.State.PacketSizes)-100:]
		sum := 0
		for _, s := range recent {
			sum += s
		}
		profile.PacketSizes.Mean = profile.PacketSizes.Mean*0.9 + float64(sum)/float64(len(recent))*0.1
	}
}

// --- Adaptive Learning Patterns (formerly marionette_adaptation.go) ---

func (m *Marionette) performAdaptiveLearning() {
	if m.Active == "" {
		return
	}
	profile := m.Profiles[m.Active]
	if profile == nil || !profile.Adaptation.Enabled {
		return
	}

	if len(m.State.PacketSizes) > 50 {
		recentSizes := m.State.PacketSizes[len(m.State.PacketSizes)-50:]
		recentIntervals := m.State.Intervals[len(m.State.Intervals)-50:]

		m.learnPacketSizePatterns(profile, recentSizes)
		m.learnTimingPatterns(profile, recentIntervals)
		m.learnBehavioralPatterns(profile)
		m.adaptToThreatLevel(profile)
	}
}

func (m *Marionette) learnPacketSizePatterns(profile *types.TrafficProfile, recentSizes []int) {
	if len(recentSizes) < 10 {
		return
	}
	mean, stdDev, _, _ := m.calculateAdvancedStats(recentSizes)
	rate := profile.Adaptation.LearningRate
	profile.PacketSizes.Mean = profile.PacketSizes.Mean*(1-rate) + mean*rate
	profile.PacketSizes.StdDev = profile.PacketSizes.StdDev*(1-rate) + stdDev*rate
	m.updateSizeDistributionWeights(profile, recentSizes)
}

func (m *Marionette) learnTimingPatterns(profile *types.TrafficProfile, recentIntervals []time.Duration) {
	if len(recentIntervals) < 10 {
		return
	}
	var sum time.Duration
	for _, interval := range recentIntervals {
		sum += interval
	}
	mean := sum / time.Duration(len(recentIntervals))

	var variance float64
	for _, interval := range recentIntervals {
		diff := float64(interval - mean)
		variance += diff * diff
	}
	variance /= float64(len(recentIntervals))

	rate := profile.Adaptation.LearningRate
	profile.Intervals.Mean = time.Duration(float64(profile.Intervals.Mean)*(1-rate) + float64(mean)*rate)
	profile.Intervals.StdDev = time.Duration(float64(profile.Intervals.StdDev)*(1-rate) + variance*rate)
}

func (m *Marionette) learnBehavioralPatterns(profile *types.TrafficProfile) {
	burstProb := m.analyzeBurstPatterns()
	profile.BurstPatterns.Probability = profile.BurstPatterns.Probability*0.9 + burstProb*0.1

	sessionLength := m.analyzeSessionPatterns()
	if sessionLength > 0 {
		profile.Adaptation.Sensitivity = m.calculateAdaptiveSensitivity(sessionLength)
	}
}

func (m *Marionette) adaptToThreatLevel(profile *types.TrafficProfile) {
	threat := float64(m.State.ThreatLevel) / 10.0
	if threat > 0.7 {
		profile.Adaptation.Sensitivity = minFloat(1.0, profile.Adaptation.Sensitivity*1.2)
		profile.Adaptation.LearningRate = minFloat(0.3, profile.Adaptation.LearningRate*1.1)
	} else if threat < 0.3 {
		profile.Adaptation.Sensitivity = maxFloat(0.1, profile.Adaptation.Sensitivity*0.9)
		profile.Adaptation.LearningRate = maxFloat(0.01, profile.Adaptation.LearningRate*0.95)
	}
}

func (m *Marionette) updateSizeDistributionWeights(profile *types.TrafficProfile, recentSizes []int) {
	for i, bin := range profile.PacketSizes.Bins {
		if i < len(profile.PacketSizes.Weights) {
			count := 0
			for _, size := range recentSizes {
				if size >= bin && (i == len(profile.PacketSizes.Bins)-1 || size < profile.PacketSizes.Bins[i+1]) {
					count++
				}
			}
			observed := float64(count) / float64(len(recentSizes))
			profile.PacketSizes.Weights[i] = profile.PacketSizes.Weights[i]*0.9 + observed*0.1
		}
	}
}

func (m *Marionette) analyzeBurstPatterns() float64 {
	if len(m.State.PacketSizes) < 20 {
		return 0.0
	}
	bursts, consecutive := 0, 0
	for i := 1; i < len(m.State.PacketSizes); i++ {
		if abs(m.State.PacketSizes[i]-m.State.PacketSizes[i-1]) < 50 {
			consecutive++
		} else {
			if consecutive > 3 {
				bursts++
			}
			consecutive = 0
		}
	}
	return float64(bursts) / float64(len(m.State.PacketSizes))
}

func (m *Marionette) analyzeSessionPatterns() time.Duration {
	if len(m.State.Intervals) < 10 {
		return 0
	}
	var total time.Duration
	for _, interval := range m.State.Intervals {
		total += interval
	}
	return total / time.Duration(len(m.State.Intervals))
}

func (m *Marionette) calculateAdaptiveSensitivity(sessionLength time.Duration) float64 {
	base := 0.5
	factor := float64(sessionLength) / float64(time.Minute)
	return minFloat(1.0, base+factor*0.1)
}

// --- Adaptive Learning (formerly marionette_learning.go) ---

type AdaptiveLearning struct {
	LearningRate    float64
	AdaptationCount int
	LastAdaptation  time.Time
	Performance     *PerformanceMetrics
}

type PerformanceMetrics struct {
	DPIEvasionSuccess float64
	FalsePositiveRate float64
	Latency           time.Duration
	Throughput        float64
}

func NewAdaptiveLearning() *AdaptiveLearning {
	return &AdaptiveLearning{
		LearningRate:   0.01,
		LastAdaptation: util.GetGlobalTimeCache().Now(),
		Performance:    &PerformanceMetrics{},
	}
}

func (al *AdaptiveLearning) AdaptToFeedback(success bool, latency time.Duration, throughput float64) {
	al.AdaptationCount++
	rate := 0.0
	if success {
		rate = 0.1
	}
	al.Performance.DPIEvasionSuccess = (al.Performance.DPIEvasionSuccess * 0.9) + rate
	al.Performance.Latency = latency
	al.Performance.Throughput = throughput

	if al.Performance.DPIEvasionSuccess < 0.7 {
		al.LearningRate = math.Min(al.LearningRate*1.1, 0.1)
	} else if al.Performance.DPIEvasionSuccess > 0.9 {
		al.LearningRate = math.Max(al.LearningRate*0.95, 0.001)
	}
	al.LastAdaptation = util.GetGlobalTimeCache().Now()
}

func (al *AdaptiveLearning) GetAdaptationRecommendations() []string {
	recs := make([]string, 0)
	if al.Performance.DPIEvasionSuccess < 0.5 {
		recs = append(recs, "Increase obfuscation intensity")
	}
	if al.Performance.Latency > 100*time.Millisecond {
		recs = append(recs, "Optimize timing patterns")
	}
	return recs
}

func (m *Marionette) GetAdaptiveLearning() *AdaptiveLearning         { return m.AdaptiveLearning }
func (m *Marionette) GetEffectivenessMetrics() *EffectivenessMetrics { return m.Effectiveness }
func (m *Marionette) GetMLSystem() *mlpkg.UnifiedMLSystem            { return m.MlSystem }

// --- Adaptive Profile Manager (formerly marionette_adaptive_manager.go) ---

// AdaptiveProfileManager manages adaptive profile learning and switching
type AdaptiveProfileManager struct {
	mu                   sync.RWMutex
	learningEnabled      bool
	mlClient             *mlpkg.PythonMLClient
	profileEffectiveness map[string]float64
	learningHistory      []LearningEvent
	adaptationRules      []AdaptationRule
}

type LearningEvent struct {
	Timestamp     time.Time
	Profile       string
	Effectiveness float64
	Context       map[string]interface{}
	Success       bool
}

type AdaptationRule struct {
	ID         string
	Condition  types.Condition
	Action     types.Action
	Threshold  float64
	Enabled    bool
	Parameters map[string]interface{}
}

func NewAdaptiveProfileManager() *AdaptiveProfileManager {
	return &AdaptiveProfileManager{
		learningEnabled:      true,
		mlClient:             mlpkg.NewPythonMLClient(mlpkg.GetEnvOrDefault("WHISPERA_ML_SERVER", "http://localhost:8080")),
		profileEffectiveness: make(map[string]float64),
		learningHistory:      make([]LearningEvent, 0),
		adaptationRules:      make([]AdaptationRule, 0),
	}
}

func (apm *AdaptiveProfileManager) LearnFromTraffic(packetData []byte, profile string, success bool) {
	apm.mu.Lock()
	defer apm.mu.Unlock()

	event := LearningEvent{
		Timestamp:     util.GetGlobalTimeCache().Now(),
		Profile:       profile,
		Effectiveness: apm.calculateEffectiveness(success),
		Context:       apm.extractContext(packetData),
		Success:       success,
	}

	apm.learningHistory = append(apm.learningHistory, event)
	apm.updateProfileEffectiveness(profile, event.Effectiveness)
	apm.checkAdaptationTriggers(profile, event)
}

func (apm *AdaptiveProfileManager) calculateEffectiveness(success bool) float64 {
	if success {
		return 1.0
	}
	return 0.0
}

func (apm *AdaptiveProfileManager) extractContext(packetData []byte) map[string]interface{} {
	context := make(map[string]interface{})
	context["packet_size"] = len(packetData)
	context["timestamp"] = util.GetGlobalTimeCache().Now().Unix()
	context["entropy"] = apm.calculateEntropy(packetData)
	return context
}

func (apm *AdaptiveProfileManager) calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}
	entropy := 0.0
	dataLen := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / dataLen
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func (apm *AdaptiveProfileManager) updateProfileEffectiveness(profile string, effectiveness float64) {
	if current, exists := apm.profileEffectiveness[profile]; exists {
		apm.profileEffectiveness[profile] = 0.7*current + 0.3*effectiveness
	} else {
		apm.profileEffectiveness[profile] = effectiveness
	}
}

func (apm *AdaptiveProfileManager) checkAdaptationTriggers(profile string, event LearningEvent) {
	if apm.profileEffectiveness[profile] < 0.7 {
		apm.triggerProfileAdaptation(profile, event)
	}
}

func (apm *AdaptiveProfileManager) triggerProfileAdaptation(profile string, event LearningEvent) {
	suggestion := apm.getMLProfileSuggestion(event.Context)
	fmt.Printf("Adapting profile %s based on ML suggestion: %s\n", profile, suggestion)
}

func (apm *AdaptiveProfileManager) getMLProfileSuggestion(_ map[string]interface{}) string {
	return "vk" // Placeholder
}

func (apm *AdaptiveProfileManager) GetBestProfile() string {
	apm.mu.RLock()
	defer apm.mu.RUnlock()
	best := ""
	bestScore := 0.0
	for profile, score := range apm.profileEffectiveness {
		if score > bestScore {
			bestScore = score
			best = profile
		}
	}
	return best
}

// SelectOptimalProfile implements types.AdaptiveProfileManager
func (apm *AdaptiveProfileManager) SelectOptimalProfile(ctx *types.TrafficContext) (string, error) {
	apm.mu.RLock()
	defer apm.mu.RUnlock()
	return "vk", nil
}

func (apm *AdaptiveProfileManager) GetProfileEffectiveness() map[string]float64 {
	apm.mu.RLock()
	defer apm.mu.RUnlock()
	result := make(map[string]float64)
	for k, v := range apm.profileEffectiveness {
		result[k] = v
	}
	return result
}

// AdaptProfile implements types.AdaptiveProfileManager
func (apm *AdaptiveProfileManager) AdaptProfile(profileID string, feedback *types.AdaptationFeedback) error {
	// Simple implementation
	apm.mu.Lock()
	defer apm.mu.Unlock()
	if profileID == "" {
		return fmt.Errorf("profileID is empty")
	}
	return nil
}

// GetProfileRecommendations implements types.AdaptiveProfileManager
func (apm *AdaptiveProfileManager) GetProfileRecommendations(ctx *types.TrafficContext) []*types.ProfileRecommendation {
	apm.mu.RLock()
	defer apm.mu.RUnlock()
	return []*types.ProfileRecommendation{}
}
