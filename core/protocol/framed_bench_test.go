package protocol

import (
	"net"
	rtdebug "runtime/debug"
	"strconv"
	"testing"
)

type countingConn struct {
	net.Conn
	writes int64
	wire   int64
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes++
	c.wire += int64(len(p))
	return len(p), nil
}

func benchStreamStart(b *testing.B, size int, warm bool) {
	payload := make([]byte, size)
	var wire, writes int64
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cc := &countingConn{}
		fc := NewFramedConn(cc, NewShapeBudget())
		if warm {
			for j := 0; j < shapePadRecords; j++ {
				fc.pad.take()
			}
		}
		if _, err := fc.Write(payload); err != nil {
			b.Fatal(err)
		}
		if err := fc.EndStream(); err != nil {
			b.Fatal(err)
		}
		wire += cc.wire
		writes += cc.writes
	}
	b.StopTimer()
	b.ReportMetric(float64(wire)/float64(b.N)/float64(size), "wire/payload")
	b.ReportMetric(float64(writes)/float64(b.N), "writes/op")
	b.ReportMetric(float64(wire)/float64(b.N)-float64(size), "overhead-B/op")
}

func BenchmarkStreamStart(b *testing.B) {
	for _, size := range []int{1 << 10, 4 << 10, 16 << 10, 64 << 10, 256 << 10} {
		name := strconv.Itoa(size>>10) + "KB"
		b.Run(name+"/fresh", func(b *testing.B) { benchStreamStart(b, size, false) })
		b.Run(name+"/warm", func(b *testing.B) { benchStreamStart(b, size, true) })
	}
}

func BenchmarkStreamChunked(b *testing.B) {
	const total = 256 << 10
	for _, chunk := range []int{1400, 4 << 10, 16 << 10, 32 << 10, 64 << 10} {
		b.Run(strconv.Itoa(chunk)+"B", func(b *testing.B) {
			payload := make([]byte, chunk)
			var wire, writes int64
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cc := &countingConn{}
				fc := NewFramedConn(cc, NewShapeBudget())
				for sent := 0; sent < total; sent += chunk {
					if _, err := fc.Write(payload); err != nil {
						b.Fatal(err)
					}
				}
				wire += cc.wire
				writes += cc.writes
			}
			b.StopTimer()
			b.ReportMetric(float64(wire)/float64(b.N)/float64(total), "wire/payload")
			b.ReportMetric(float64(writes)/float64(b.N), "writes/op")
		})
	}
}

func TestH2BuffersFitMemoryLimit(t *testing.T) {
	lim := rtdebug.SetMemoryLimit(-1)
	perConn, perStream := h2Buffers()

	if perStream > perConn {
		t.Fatalf("per-stream %d exceeds per-connection %d", perStream, perConn)
	}
	if lim > 0 && lim < 1<<62 && int64(perConn) > lim {
		t.Fatalf("per-connection buffer %d exceeds the process memory limit %d", perConn, lim)
	}
}
