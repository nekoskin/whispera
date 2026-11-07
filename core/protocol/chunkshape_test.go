package protocol

import (
	"testing"
)

func TestShapedPlanCarriesNoMoreDataThanIsLeft(t *testing.T) {
	for _, left := range []int{1, 9, 100, 1000} {
		for i := 0; i < 2000; i++ {
			if data, _ := shapedPlan(left); data > left {
				t.Fatalf("shapedPlan(%d) carried %d bytes of data", left, data)
			}
		}
	}
}
