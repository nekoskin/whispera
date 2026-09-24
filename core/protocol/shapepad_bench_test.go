package protocol

import "testing"

func BenchmarkAppendShapePad(b *testing.B) {
	for _, pad := range []int{64, 1024, 8192} {
		buf := make([]byte, 0, 16*1024)
		b.Run(padName(pad), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				out := AppendShapePad(buf[:0], pad)
				buf = out[:0]
			}
		})
	}
}

func padName(n int) string {
	switch n {
	case 64:
		return "pad=64"
	case 1024:
		return "pad=1k"
	default:
		return "pad=8k"
	}
}
