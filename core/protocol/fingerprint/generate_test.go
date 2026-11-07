package fingerprint

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func helloRawFor(t *testing.T, id utls.ClientHelloID) []byte {
	t.Helper()
	c0, c1 := net.Pipe()
	defer c0.Close()
	defer c1.Close()
	u := utls.UClient(c0, &utls.Config{ServerName: "example.com", InsecureSkipVerify: true}, id)
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatalf("%v: %v", id, err)
	}
	return asRecord(u.HandshakeState.Hello.Raw)
}

func seedPool(t *testing.T) [][]byte {
	t.Helper()
	var raws [][]byte
	for _, id := range []utls.ClientHelloID{
		utls.HelloChrome_120, utls.HelloFirefox_120, utls.HelloEdge_106, utls.HelloSafari_16_0,
	} {
		raw := helloRawFor(t, id)
		spec, err := SpecFromRaw(raw)
		if err != nil {
			t.Fatalf("spec from %v: %v", id, err)
		}
		AddCollected(spec, raw)
		raws = append(raws, raw)
	}
	if collectedCount() < 2 {
		t.Fatalf("pool holds %d specs, recombination needs 2", collectedCount())
	}
	return raws
}

func TestGeneratedHelloCanHandshake(t *testing.T) {
	seedPool(t)
	raw, err := Generate(1)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	spec, err := SpecFromRaw(raw)
	if err != nil {
		t.Fatalf("generated hello does not parse back: %v", err)
	}
	if !specHandshakeReady(spec) {
		t.Fatal("generated hello cannot build a handshake — it would fail on a real dial")
	}
}

func TestDeviceFingerprintReplacesCorruptFile(t *testing.T) {
	seedPool(t)
	path := filepath.Join(t.TempDir(), "hello.bin")
	if err := os.WriteFile(path, []byte("not a hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := DeviceFingerprint(path)
	if err != nil {
		t.Fatalf("corrupt file should be replaced: %v", err)
	}
	if _, err := SpecFromRaw(raw); err != nil {
		t.Fatalf("replacement does not parse: %v", err)
	}
}
