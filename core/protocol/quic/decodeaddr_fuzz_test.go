package quic

import "testing"

// FuzzDecodeAddr feeds arbitrary bytes to the datagram address parser. Every
// datagram off the wire lands here before anything else looks at it.
func FuzzDecodeAddr(f *testing.F) {
	f.Add(encodeAddr("203.0.113.7", 27015))
	f.Add(encodeAddr("2001:db8::1", 443))
	f.Add(encodeAddr("game.example.com", 27015))
	f.Add([]byte{0x03, 0xff})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		host, _, rest, ok := decodeAddr(data)
		if !ok {
			return
		}
		if len(rest) > len(data) {
			t.Fatalf("payload longer than the datagram: rest %d, input %d", len(rest), len(data))
		}
		if host == "" {
			t.Fatal("accepted an address with no host")
		}
	})
}
