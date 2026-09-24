package relay

import (
	"testing"
)

func benchHeaderBytes(host string) []byte {
	out := []byte{byte(len(host) + 5), 0x00, byte(len(host))}
	out = append(out, host...)
	return append(out, 0x01, 0xbb)
}

func BenchmarkReadProxyStreamHeader(b *testing.B) {
	raw := benchHeaderBytes("www.example.com")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c := &headerConn{in: raw}
		if _, ok := readProxyStreamHeader(c, 0); !ok {
			b.Fatal("header rejected")
		}
	}
}
