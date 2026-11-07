//go:build !stand

package tunnel

func pinnedArm(chosen, _ int) (int, bool) { return chosen, false }
