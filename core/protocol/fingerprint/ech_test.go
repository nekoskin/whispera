package fingerprint

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

func hasECH(spec *utls.ClientHelloSpec) bool {
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.GREASEEncryptedClientHelloExtension:
			return true
		case *utls.GenericExtension:
			if e.Id == 0xfe0d {
				return true
			}
		}
	}
	return false
}

func TestDropECHRemovesBothForms(t *testing.T) {
	spec := &utls.ClientHelloSpec{Extensions: []utls.TLSExtension{
		&utls.SNIExtension{},
		&utls.GREASEEncryptedClientHelloExtension{},
		&utls.ALPNExtension{AlpnProtocols: []string{"h2"}},
		&utls.GenericExtension{Id: 0xfe0d},
		&utls.SupportedVersionsExtension{},
	}}

	if !hasECH(spec) {
		t.Fatal("seed spec must carry ECH")
	}

	DropECH(spec)

	if hasECH(spec) {
		t.Fatal("ECH survived DropECH")
	}
	if len(spec.Extensions) != 3 {
		t.Fatalf("kept %d extensions, want 3", len(spec.Extensions))
	}
}

func TestDropECHKeepsOtherGenericExtensions(t *testing.T) {
	spec := &utls.ClientHelloSpec{Extensions: []utls.TLSExtension{
		&utls.GenericExtension{Id: 0x44cd},
		&utls.GREASEEncryptedClientHelloExtension{},
	}}

	DropECH(spec)

	if len(spec.Extensions) != 1 {
		t.Fatalf("kept %d extensions, want 1", len(spec.Extensions))
	}
	e, ok := spec.Extensions[0].(*utls.GenericExtension)
	if !ok || e.Id != 0x44cd {
		t.Fatal("a non-ECH generic extension was dropped")
	}
}
