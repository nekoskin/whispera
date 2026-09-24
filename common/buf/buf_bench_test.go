package buf

import (
	"bytes"
	"io"
	"strconv"
	"testing"
)

func BenchmarkBufferPool(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := New()
		buf.Release()
	}
}

func BenchmarkCopy(b *testing.B) {
	for _, size := range []int{1 << 10, 64 << 10, 1 << 20} {
		payload := make([]byte, size)
		b.Run(strconv.Itoa(size>>10)+"KB", func(b *testing.B) {
			src := bytes.NewReader(payload)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				src.Reset(payload)
				if _, err := Copy(NewReader(src), NewWriter(io.Discard)); err != nil && err != io.EOF {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkBufferWrite(b *testing.B) {
	chunk := make([]byte, 1400)
	b.ReportAllocs()
	b.SetBytes(int64(len(chunk)))
	for i := 0; i < b.N; i++ {
		buf := New()
		buf.Write(chunk)
		buf.Release()
	}
}
