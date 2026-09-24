package dns

import "testing"

// FuzzParseDNSResponse feeds arbitrary bytes to the response parser. The answer
// comes from whatever upstream the user pointed us at, so a malformed or
// hostile reply must not take the resolver down.
func FuzzParseDNSResponse(f *testing.F) {
	id := [2]byte{0x12, 0x34}
	f.Add(buildFakeResponse(id, dnsTypeA, []byte{93, 184, 216, 34}))
	f.Add(buildFakeResponse(id, dnsTypeAAAA, make([]byte, 16)))
	f.Add([]byte{0x12, 0x34})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseDNSResponse(data, id)
	})
}
