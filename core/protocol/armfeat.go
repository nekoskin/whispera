package protocol

import "math"

const armDeliveryDims = 4

const armBudgetNorm = 8

func ArmFeatureLen(presets int) int { return presets + armDeliveryDims }

func fragBudgetFeature(budget int) float64 {
	if budget < 1 {
		budget = 1
	}
	return math.Log2(float64(budget)) / math.Log2(armBudgetNorm)
}

func ArmFeatures(preset, budget int, dropPQ, migrate, shaped bool, presets int) []float64 {
	f := make([]float64, ArmFeatureLen(presets))
	if preset >= 0 && preset < presets {
		f[preset] = 1
	}
	f[presets] = fragBudgetFeature(budget)
	f[presets+1] = indicator(dropPQ)
	f[presets+2] = indicator(migrate)
	f[presets+3] = indicator(shaped)
	return f
}

func JointArmFeatures(arm, presets int) []float64 {
	preset, budget := JointArmParts(arm, presets)
	return ArmFeatures(preset, budget, JointArmDropPQ(arm, presets), JointArmMigrates(arm, presets), JointArmShaped(arm, presets), presets)
}
