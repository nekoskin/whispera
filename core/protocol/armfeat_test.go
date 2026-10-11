package protocol

import (
	"fmt"
	"testing"
)

func TestJointArmFeaturesAreDistinct(t *testing.T) {
	const presets = 3
	n := JointArmCount(presets)
	seen := map[string]int{}
	for arm := 0; arm < n; arm++ {
		f := JointArmFeatures(arm, presets)
		if len(f) != ArmFeatureLen(presets) {
			t.Fatalf("arm %d has %d features, want %d", arm, len(f), ArmFeatureLen(presets))
		}
		key := fmt.Sprintf("%v", f)
		if prev, ok := seen[key]; ok {
			t.Fatalf("arms %d and %d share a feature vector %v", prev, arm, f)
		}
		seen[key] = arm
	}
}

func TestArmFeaturesEncodePresetAsOneHot(t *testing.T) {
	const presets = 3
	for preset := 0; preset < presets; preset++ {
		f := ArmFeatures(preset, 1, presets)
		for i := 0; i < presets; i++ {
			want := 0.0
			if i == preset {
				want = 1.0
			}
			if f[i] != want {
				t.Fatalf("preset %d: feature[%d] = %v, want %v", preset, i, f[i], want)
			}
		}
		if f[presets] != 0 {
			t.Fatalf("budget 1 should map to 0, got %v", f[presets])
		}
	}
}

func TestFragBudgetFeatureMonotoneInUnitRange(t *testing.T) {
	last := -1.0
	for _, b := range fragmentBudgets {
		v := fragBudgetFeature(b)
		if v < 0 || v > 1 {
			t.Fatalf("budget %d feature %v is outside [0,1]", b, v)
		}
		if v <= last {
			t.Fatalf("budget feature not increasing at %d: %v <= %v", b, v, last)
		}
		last = v
	}
}
