package quic

import (
	"testing"
)

func BenchmarkEncodeAddr(b *testing.B) {
	for _, host := range []string{"203.0.113.7", "game.example.com"} {
		b.Run(host, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				encodeAddr(host, 27015)
			}
		})
	}
}

func BenchmarkDatagramPack(b *testing.B) {
	payload := make([]byte, 80)
	for _, host := range []string{"203.0.113.7", "game.example.com"} {
		b.Run(host, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				full := make([]byte, 0, addrLen(host)+len(payload))
				full = appendAddr(full, host, 27015)
				_ = append(full, payload...)
			}
		})
	}
}

func BenchmarkFECEncode(b *testing.B) {
	s := newRTFECSender()
	full := make([]byte, 87)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.encode(full)
	}
}
