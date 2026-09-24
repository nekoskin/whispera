package dns

import (
	"net"
	"testing"
)

func BenchmarkBuildDNSMsg(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buildDNSMsg("www.example.com", dnsTypeA)
	}
}

func BenchmarkParseDNSResponse(b *testing.B) {
	id := [2]byte{0x12, 0x34}
	resp := buildFakeResponse(id, dnsTypeA, net.ParseIP("93.184.216.34").To4())
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ips, err := parseDNSResponse(resp, id)
		if err != nil || len(ips) == 0 {
			b.Fatal("parse failed")
		}
	}
}
