package protocol

import (
	"math"
	"os"
	"testing"
)

func TestGrowRepertoireExtendsAndSorts(t *testing.T) {
	os.Setenv("WHISPERA_ARM_BUDGETS", "3, 6, 2, bad, 16")
	defer os.Unsetenv("WHISPERA_ARM_BUDGETS")
	got := growRepertoire([]int{1, 2, 4, 8})
	want := []int{1, 2, 3, 4, 6, 8, 16}
	if len(got) != len(want) {
		t.Fatalf("grew to %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("grew to %v, want %v", got, want)
		}
	}
}

func TestGrowRepertoireDefaultsUntouched(t *testing.T) {
	os.Unsetenv("WHISPERA_ARM_BUDGETS")
	got := growRepertoire([]int{1, 2, 4, 8})
	if len(got) != 4 {
		t.Fatalf("without the env the base set must stand, got %v", got)
	}
}

func TestFrozenNetScoresGrownRepertoire(t *testing.T) {
	const grown = polArms + 6
	hist := []int{polBOS, 9, 2, 18, 5}
	scores := policyArmScores(hist, grown)
	if len(scores) != grown {
		t.Fatalf("scored %d arms, want %d", len(scores), grown)
	}
	for a, s := range scores {
		if s < 0 || s > 1 || math.IsNaN(s) {
			t.Fatalf("arm %d scored %.6f, not a probability", a, s)
		}
	}
	base := policyArmScores(hist, polArms)
	for a := 0; a < polArms; a++ {
		if math.Abs(base[a]-scores[a]) > 1e-12 {
			t.Fatalf("arm %d moved when the repertoire grew: %.9f vs %.9f", a, base[a], scores[a])
		}
	}
}

func TestFrozenGateAcceptsGrownRejectsWrongPresets(t *testing.T) {
	presets := polPresets()
	if !frozenJointUsable(presets) {
		t.Fatalf("frozen net should serve its own preset count %d", presets)
	}
	if frozenJointUsable(presets + 1) {
		t.Fatal("frozen net must refuse a preset count it was not trained on")
	}
}
