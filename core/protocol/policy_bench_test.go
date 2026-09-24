package protocol

import "testing"

// Cost of one decision. Unlike the old per-record shaper, this runs once per
// dial, beside a handshake that already costs milliseconds.
func BenchmarkPolicyArmScores(b *testing.B) {
	history := make([]int, polBlock)
	for i := range history {
		history[i] = i % (polArms * 2)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		policyArmScores(history)
	}
}

// A fresh connection with almost no history: the cheap end of the range.
func BenchmarkPolicyArmScoresShort(b *testing.B) {
	history := []int{polBOS, 2, 5}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		policyArmScores(history)
	}
}
