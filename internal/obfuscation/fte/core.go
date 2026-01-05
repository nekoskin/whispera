package fte

import (
	"fmt"
	"sync"
	"time"

	"whispera/internal/obfuscation/core/types"
)

// FTE implements Format-Transforming Encryption
// Enhanced with NetMasquerade reinforcement learning capabilities
type FTE struct {
	profiles map[string]*ProtocolProfile
	active   string
	state    *ProtocolState
	mutex    sync.RWMutex
	mlSystem types.UnifiedMLSystemInterface

	reinforcementLearning *ReinforcementLearning
	effectivenessTracker  *EffectivenessTracker
	coverTraffic          []byte
	adaptiveProfiles      map[string]*AdaptiveProfile
}

// NewFTE creates a new FTE obfuscator
func NewFTE() *FTE {
	fte := &FTE{
		profiles:              make(map[string]*ProtocolProfile),
		state:                 &ProtocolState{},
		mlSystem:              nil,
		reinforcementLearning: NewReinforcementLearning(),
		effectivenessTracker:  NewEffectivenessTracker(),
		adaptiveProfiles:      make(map[string]*AdaptiveProfile),
	}

	fte.initProfiles()
	return fte
}

func (fte *FTE) initProfiles() {
	fte.loadRealTrafficData("fixed_traffic_data.csv")
	fte.addRussianServiceProfiles()
	fte.addModernProfiles()
	fte.addSocialProfiles()
	fte.addRussianMessengerProfiles() // Max, VK Messenger, TamTam, Yandex Messenger
}

// Transform applies FTE camouflage
func (fte *FTE) Transform(data []byte) ([]byte, error) {
	fte.mutex.RLock()
	active := fte.active
	profile := fte.profiles[active]
	fte.mutex.RUnlock()

	if active == "" || profile == nil {
		return data, nil
	}

	targetSize := fte.calculateTargetSize(profile)
	obfuscated := fte.resizeToTarget(data, targetSize)
	formatted := fte.applyFormat(obfuscated, profile)

	// Apply timing obfuscation (if enabled in profile)
	formatted = fte.applyTimingObfuscation(formatted)

	fte.mutex.Lock()
	fte.updateState(targetSize)
	fte.mutex.Unlock()

	if fte.reinforcementLearning != nil {
		state := fte.GetProtocolState()
		if state == "" {
			state = "connected"
		}
		action := fte.reinforcementLearning.SelectAction(state)
		formatted = fte.applyReinforcementAction(formatted, action)
	}

	formatted, _ = fte.ApplyRealDPIEvasion(formatted, active)

	// Apply behavioral variations
	switch active {
	case "vk":
		formatted = fte.applyVKBehavioralPatterns(formatted)
	case ProfileYandexFTE:
		formatted = fte.applyYandexBehavioralPatterns(formatted)
	case ProfileMailruFTE:
		formatted = fte.applyMailruBehavioralPatterns(formatted)
	}

	return formatted, nil
}

// ProcessPacket handles higher level packet processing
func (f *FTE) ProcessPacket(data []byte, direction string) ([]byte, time.Duration, error) {
	if f == nil {
		return data, 0, fmt.Errorf("FTE not initialized")
	}

	processed, err := f.Transform(data)
	if err != nil {
		return data, 0, err
	}

	var delay time.Duration
	if len(processed) > 512 {
		delay = f.generateRealisticDelay(direction)
	}
	return processed, delay, nil
}

// SetMLSystem sets the ML system for FTE
func (fte *FTE) SetMLSystem(mlSystem types.UnifiedMLSystemInterface) {
	fte.mutex.Lock()
	defer fte.mutex.Unlock()
	fte.mlSystem = mlSystem
}

func (fte *FTE) addProfile(name string, profile *ProtocolProfile) {
	fte.profiles[name] = profile
}

// SetActiveProfile switches to a specific protocol profile
func (fte *FTE) SetActiveProfile(name string) error {
	fte.mutex.Lock()
	defer fte.mutex.Unlock()

	if _, exists := fte.profiles[name]; exists {
		fte.active = name
		fte.state = &ProtocolState{}
		return nil
	}
	return fmt.Errorf("profile %s not found", name)
}

func (fte *FTE) updateState(size int) {
	fte.state.MessageCount++
	fte.state.MessageSizes = append(fte.state.MessageSizes, size)
	if len(fte.state.MessageSizes) > 100 {
		fte.state.MessageSizes = fte.state.MessageSizes[1:]
	}

	profile := fte.profiles[fte.active]
	if profile != nil {
		timing := profile.Timing
		if !fte.state.InBurst && fte.state.MessageCount%10 == 0 {
			if timing.BurstProb > 0 && secureRandFloat64() < timing.BurstProb {
				fte.state.InBurst = true
				fte.state.BurstCount = timing.BurstMin + (fte.state.MessageCount % (timing.BurstMax - timing.BurstMin))
				fte.state.BurstStart = int64(fte.state.MessageCount)
			}
		}
		if fte.state.InBurst && fte.state.BurstCount <= 0 {
			fte.state.InBurst = false
		}
		if !fte.state.TypingPause && timing.PauseProb > 0 && secureRandFloat64() < timing.PauseProb {
			fte.state.TypingPause = true
			fte.state.PauseStart = int64(fte.state.MessageCount)
		}
	}
}

func (fte *FTE) GetHeaders() map[string]string {
	fte.mutex.RLock()
	defer fte.mutex.RUnlock()
	if fte.active == "" || fte.profiles[fte.active] == nil {
		return map[string]string{}
	}
	headers := make(map[string]string)
	for k, v := range fte.profiles[fte.active].Headers {
		headers[k] = v
	}
	return headers
}

// GetProtocolState returns current protocol state
func (fte *FTE) GetProtocolState() string {
	fte.mutex.RLock()
	defer fte.mutex.RUnlock()
	if fte.state == nil || fte.state.ProtocolState == "" {
		return "idle"
	}
	return fte.state.ProtocolState
}

func (f *FTE) generateRealisticDelay(direction string) time.Duration {
	baseDelay := 10
	if direction == "outbound" {
		baseDelay = 20
	}
	variance := 0.3
	return f.generateRealisticTiming(baseDelay, variance)
}

func (fte *FTE) applyTimingObfuscation(data []byte) []byte {
	return data // Stub
}
