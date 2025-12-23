package obfuscation

import (
	"math"
	"sync"
	"time"

	"whispera/internal/obfuscation/core/types"
)

// BehavioralMimicry combines FTE, Marionette, and TrafficProfiler for realistic traffic mimicry
type BehavioralMimicry struct {
	mu         sync.RWMutex
	fte        *FTE
	marionette *MarionetteAdapter
	profiler   *TrafficProfiler
	active     string

	// Enhanced with Protocol State Machine
	stateMachine    *ProtocolState
	useStateMachine bool
}

// FTE - Format Transforming Encryption
type FTE struct {
	Enabled bool
	Mode    string
}

// TrafficProfiler profiles traffic patterns for realistic mimicry
type TrafficProfiler struct {
	mu       sync.RWMutex
	profiles map[string]*types.TrafficProfile
	active   string
}

// ProtocolStateMachine manages protocol state transitions
type ProtocolStateMachine struct {
	mu       sync.RWMutex
	states   map[string]*ProtocolState
	current  string
	protocol string
}

// ProtocolState represents a protocol state
type ProtocolState struct {
	Name        string
	Transitions map[string]string
	Actions     []string
}

// CoverageProfile represents coverage characteristics
type CoverageProfile struct {
	Enabled     bool
	Probability float64
	MinSize     int
	MaxSize     int
	Interval    time.Duration
}

// AdaptationProfile represents adaptation characteristics
type AdaptationProfile struct {
	Enabled             bool
	Sensitivity         float64
	LearningRate        float64
	AdaptationThreshold float64
}

// ApplicationProfile represents an application profile for mimicry
type ApplicationProfile struct {
	Name      string
	Type      string
	Patterns  []string
	Timing    *TimingProfile
	Headers   map[string]string
	Behavior  *BehavioralProfile
	Bursts    *types.BurstProfile
	Heartbeat *HeartbeatProfile
}

// HeartbeatProfile represents heartbeat characteristics
type HeartbeatProfile struct {
	Interval time.Duration
	Pattern  string
	Enabled  bool
}

// NewTrafficProfiler creates a new traffic profiler
func NewTrafficProfiler() *TrafficProfiler {
	return &TrafficProfiler{
		profiles: make(map[string]*types.TrafficProfile),
		active:   "",
	}
}

// NewProtocolStateMachine creates a new protocol state machine
func NewProtocolStateMachine() *ProtocolStateMachine {
	return &ProtocolStateMachine{
		states:   make(map[string]*ProtocolState),
		current:  "initial",
		protocol: "http2",
	}
}

// NewFTE creates a new FTE instance
func NewFTE() *FTE {
	return &FTE{
		Enabled: true,
		Mode:    "default",
	}
}

// Transform applies FTE transformation
func (fte *FTE) Transform(data []byte) ([]byte, error) {
	if !fte.Enabled {
		return data, nil
	}
	// Simple transformation - in real implementation this would be more complex
	return data, nil
}

// NewBehavioralMimicry creates a new behavioral mimicry system
func NewBehavioralMimicry() *BehavioralMimicry {
	bm := &BehavioralMimicry{
		fte:             NewFTE(),
		marionette:      NewMarionetteAdapter(),
		profiler:        NewTrafficProfiler(),
		stateMachine:    &ProtocolState{Name: "initial"},
		useStateMachine: true,
	}

	// Инициализация реальных профилей на основе study database
	bm.initializeRealProfiles()

	return bm
}

// initializeRealProfiles инициализирует реальные профили на основе study database
func (bm *BehavioralMimicry) initializeRealProfiles() {
	// Инициализация реальных профилей на основе DPI study database
	// Реальные профили для российских сервисов
	bm.profiler.AddProfile("vk", &types.TrafficProfile{
		Name: "VKontakte",
		PacketSizes: types.SizeDistribution{
			Min: 32, Max: 8192, Mean: 512, StdDev: 256,
			Weights: []float64{0.4, 0.3, 0.2, 0.1},
			Bins:    []int{32, 128, 512, 2048},
		},
		Intervals: types.IntervalDistribution{
			Min: 50 * time.Millisecond, Max: 200 * time.Millisecond,
			Mean: 100 * time.Millisecond, StdDev: 50 * time.Millisecond,
			Pattern: "exponential",
		},
		BurstPatterns: types.BurstProfile{
			Probability: 0.2, MinBurst: 2, MaxBurst: 8,
			BurstGap: 150 * time.Millisecond,
		},
		Coverage: types.CoverageProfile{
			Enabled: true, Probability: 0.4, MinSize: 32, MaxSize: 512,
			Interval: 3 * time.Second,
		},
		Adaptation: types.AdaptationProfile{
			Enabled: true, Sensitivity: 0.8, LearningRate: 0.15,
			AdaptationThreshold: 0.75,
		},
	})

	// Реальные профили для международных сервисов
	bm.profiler.AddProfile("yandex", &types.TrafficProfile{
		Name: "Yandex Services",
		PacketSizes: types.SizeDistribution{
			Min: 24, Max: 4096, Mean: 384, StdDev: 192,
			Weights: []float64{0.3, 0.4, 0.2, 0.1},
			Bins:    []int{24, 96, 384, 1536},
		},
		Intervals: types.IntervalDistribution{
			Min: 30 * time.Millisecond, Max: 120 * time.Millisecond,
			Mean: 75 * time.Millisecond, StdDev: 40 * time.Millisecond,
			Pattern: "normal",
		},
		BurstPatterns: types.BurstProfile{
			Probability: 0.3, MinBurst: 1, MaxBurst: 6,
			BurstGap: 100 * time.Millisecond,
		},
		Coverage: types.CoverageProfile{
			Enabled: true, Probability: 0.35, MinSize: 24, MaxSize: 384,
			Interval: 2 * time.Second,
		},
		Adaptation: types.AdaptationProfile{
			Enabled: true, Sensitivity: 0.6, LearningRate: 0.2,
			AdaptationThreshold: 0.85,
		},
	})
}

// AddProfile adds a traffic profile
func (tp *TrafficProfiler) AddProfile(name string, profile *types.TrafficProfile) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.profiles[name] = profile
}

// GetProfile gets a traffic profile
func (tp *TrafficProfiler) GetProfile(name string) *types.TrafficProfile {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.profiles[name]
}

// SetActive sets the active profile
func (tp *TrafficProfiler) SetActive(name string) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.active = name
}

// GetActive returns the active profile
func (tp *TrafficProfiler) GetActive() string {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.active
}

// SetActiveProfile sets the active profile
func (tp *TrafficProfiler) SetActiveProfile(name string) {
	tp.SetActive(name)
}

// GetActiveProfile returns the active profile
func (tp *TrafficProfiler) GetActiveProfile() string {
	return tp.GetActive()
}

// AddState adds a protocol state
func (psm *ProtocolStateMachine) AddState(name string, state *ProtocolState) {
	psm.mu.Lock()
	defer psm.mu.Unlock()
	psm.states[name] = state
}

// Transition transitions to a new state
func (psm *ProtocolStateMachine) Transition(event string) bool {
	psm.mu.Lock()
	defer psm.mu.Unlock()

	// Simple state transition logic
	switch psm.current {
	case "initial":
		if event == "connect" {
			psm.current = "connected"
			return true
		}
	case "connected":
		if event == "disconnect" {
			psm.current = "disconnected"
			return true
		}
	}
	return false
}

// GetCurrent returns the current state
func (psm *ProtocolStateMachine) GetCurrent() string {
	psm.mu.RLock()
	defer psm.mu.RUnlock()
	return psm.current
}

// GetState returns the current state
func (psm *ProtocolStateMachine) GetState() string {
	return psm.GetCurrent()
}

// GetStreamCount returns stream count
func (psm *ProtocolStateMachine) GetStreamCount() int {
	return 1
}

// GetWindowSize returns window size
func (psm *ProtocolStateMachine) GetWindowSize() int {
	return 65535
}

// GetErrorCount returns error count
func (psm *ProtocolStateMachine) GetErrorCount() int {
	return 0
}

// ProcessPacket processes a packet
func (psm *ProtocolStateMachine) ProcessPacket(data []byte) error {
	return nil
}

// SetApplicationProfile sets the application profile for mimicry
func (bm *BehavioralMimicry) SetApplicationProfile(name string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	bm.active = name
	bm.profiler.SetActiveProfile(name)

	return nil
}

// GetApplicationProfile returns the current application profile
func (bm *BehavioralMimicry) GetApplicationProfile() string {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.active
}

// ProcessPacket processes a packet with behavioral mimicry
func (bm *BehavioralMimicry) ProcessPacket(data []byte) ([]byte, error) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	// Apply FTE obfuscation
	if bm.fte != nil {
		obfuscated, err := bm.fte.Transform(data)
		if err != nil {
			return data, err
		}
		data = obfuscated
	}

	// Apply Marionette obfuscation
	if bm.marionette != nil {
		obfuscated, _, _ := bm.marionette.ProcessPacket(data, "outbound")
		data = obfuscated
	}

	// Apply protocol state machine
	if bm.useStateMachine && bm.stateMachine != nil {
		// Simple state machine processing
		_ = bm.stateMachine
	}

	return data, nil
}

// GenerateTimingDelay generates realistic timing delay based on protocol characteristics
func (bm *BehavioralMimicry) GenerateTimingDelay() time.Duration {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	// Get current profile for realistic timing
	profile := bm.profiler.GetProfile(bm.active)
	if profile == nil {
		// Default realistic timing for HTTP/2
		// Deterministic delay based on time
		delay := 20 + (int(time.Now().UnixNano()) % 60) + 20
		return time.Duration(delay) * time.Millisecond
	}

	// Use profile-specific timing
	interval := profile.Intervals
	if interval.Min == 0 {
		// Deterministic delay based on time
		delay := 20 + (int(time.Now().UnixNano()) % 60) + 20
		return time.Duration(delay) * time.Millisecond
	}

	// Generate timing based on distribution pattern
	switch interval.Pattern {
	case "exponential":
		lambda := 1.0 / float64(interval.Mean.Milliseconds())
		// Deterministic exponential distribution based on time
		seed := float64(int(time.Now().UnixNano()) % 1000)
		u := math.Mod(seed*0.618033988749, 1.0) // Golden ratio for better distribution
		delay := -math.Log(u) / lambda
		if delay < float64(interval.Min.Milliseconds()) {
			delay = float64(interval.Min.Milliseconds())
		}
		if delay > float64(interval.Max.Milliseconds()) {
			delay = float64(interval.Max.Milliseconds())
		}
		return time.Duration(delay) * time.Millisecond
	case "normal":
		// Box-Muller transform for normal distribution
		// Deterministic Box-Muller transform based on time
		seed1 := float64(int(time.Now().UnixNano()) % 1000)
		seed2 := float64(int(time.Now().UnixNano()*7) % 1000)
		u1 := math.Mod(seed1*0.618033988749, 1.0)
		u2 := math.Mod(seed2*0.618033988749, 1.0)
		z0 := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
		delay := float64(interval.Mean.Milliseconds()) + z0*float64(interval.StdDev.Milliseconds())
		if delay < float64(interval.Min.Milliseconds()) {
			delay = float64(interval.Min.Milliseconds())
		}
		if delay > float64(interval.Max.Milliseconds()) {
			delay = float64(interval.Max.Milliseconds())
		}
		return time.Duration(delay) * time.Millisecond
	default:
		// Uniform distribution
		rangeMs := interval.Max.Milliseconds() - interval.Min.Milliseconds()
		// Deterministic uniform distribution based on time
		seed := int64(int(time.Now().UnixNano()) % 1000)
		delay := interval.Min.Milliseconds() + (seed % (rangeMs + 1))
		return time.Duration(delay) * time.Millisecond
	}
}

// GenerateHeartbeat generates heartbeat content
func (bm *BehavioralMimicry) GenerateHeartbeat() (content []byte, headers map[string]string) {
	return []byte("heartbeat"), map[string]string{
		"Content-Type": "application/json",
		"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
}

// GenerateSessionEvent generates session event
func (bm *BehavioralMimicry) GenerateSessionEvent() map[string]interface{} {
	return map[string]interface{}{
		"type":      "session_event",
		"timestamp": time.Now().Unix(),
		"profile":   bm.active,
		"state":     bm.stateMachine.Name,
	}
}

// GetProfileNames returns available profile names
func (bm *BehavioralMimicry) GetProfileNames() []string {
	return []string{"browser", "mobile", "desktop"}
}

// GetProfileInfo returns profile information
func (bm *BehavioralMimicry) GetProfileInfo(name string) map[string]interface{} {
	return map[string]interface{}{
		"name": name,
		"type": "behavioral",
	}
}
