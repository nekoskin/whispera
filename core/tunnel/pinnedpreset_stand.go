//go:build stand

package tunnel

import (
	stdlog "log"
	"math/rand/v2"
	"os"
	"strconv"
	"sync"

	"github.com/nekoskin/whispera/core/protocol"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
)

const pinnedArmRandom = "random"

var unpinnableOnce sync.Once

func pinnedArm(chosen, presets int) (int, bool) {
	arms := protocol.JointArmCount(presets)
	switch v := os.Getenv("WHISPERA_ARM"); {
	case v == pinnedArmRandom:
		return rand.IntN(arms), true
	case v != "":
		if arm, err := strconv.Atoi(v); err == nil && arm >= 0 && arm < arms {
			return arm, true
		}
	}
	id, ok := fingerprint.Forced()
	if !ok {
		return chosen, false
	}
	preset, ok := fingerprint.PresetIndex(id)
	if !ok {
		unpinnableOnce.Do(func() {
			stdlog.Printf("[WARN] forced fingerprint %s is not one of the presets, the policy keeps choosing", id.Str())
		})
		return chosen, false
	}
	return protocol.JointArmWithPreset(chosen, preset), true
}
