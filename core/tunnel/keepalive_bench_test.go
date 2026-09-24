package tunnel

import (
	"net"
	"testing"
)

func BenchmarkIdleSetPutTake(b *testing.B) {
	var s idleSet
	a, peer := net.Pipe()
	defer a.Close()
	defer peer.Close()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.put(a)
		if c := s.take(); c == nil {
			b.Fatal("parked connection was lost")
		}
	}
	s.closeAll()
}

func BenchmarkIdleSetTakeEmpty(b *testing.B) {
	var s idleSet
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if c := s.take(); c != nil {
			b.Fatal("empty set returned a connection")
		}
	}
}
