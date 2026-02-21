package fte

func NewReinforcementLearning() *ReinforcementLearning {
	return &ReinforcementLearning{
		QTable:         make(map[string]map[string]float64),
		ActionSpace:    []string{ActionSizeAdapt, ActionTimingAdapt, ActionHeaderAdapt, ActionEntropyAdapt, ActionBehavioralAdapt},
		Epsilon:        0.1,
		MinEpsilon:     0.01,
		EpsilonDecay:   0.995,
		LearningRate:   0.1,
		DiscountFactor: 0.9,
		maxQTableSize:  1000,
	}
}
