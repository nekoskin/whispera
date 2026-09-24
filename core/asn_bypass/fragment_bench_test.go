package asn_bypass

import (
	"net"
	"testing"
)

type discardConn struct{ net.Conn }

func (discardConn) Write(p []byte) (int, error) { return len(p), nil }

func BenchmarkSNISplitOffset(b *testing.B) {
	hello, _, _ := buildClientHello("www.example.com", 512)
	payload := hello[5:]
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if sniSplitOffset(payload) < 0 {
			b.Fatal("sni not found")
		}
	}
}

func BenchmarkWriteFragmentedTLSRecord(b *testing.B) {
	hello, _, _ := buildClientHello("www.example.com", 512)
	conn := discardConn{}
	b.ReportAllocs()
	b.SetBytes(int64(len(hello)))
	for i := 0; i < b.N; i++ {
		if err := writeFragmentedTLSRecord(conn, hello, fragmentPlan{size: defaultFragSize, maxRecords: defaultMaxHelloRecords}); err != nil {
			b.Fatal(err)
		}
	}
}
