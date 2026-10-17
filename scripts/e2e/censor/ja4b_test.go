package main

import "testing"

func TestJA4CiphersExtractsMiddleComponent(t *testing.T) {
	cases := map[string]string{
		"t13d1516h2_8daaf6152771_e61dd635b2ab": "8daaf6152771",
		"t13d1517h2_8daaf6152771_97dc5c738061": "8daaf6152771",
		"t13d1715h2_5b57614c22b0_9c5a770fd319": "5b57614c22b0",
	}
	for full, want := range cases {
		if got := ja4Ciphers(full); got != want {
			t.Fatalf("ja4Ciphers(%q) = %q, want %q", full, got, want)
		}
	}
}

func TestJA4CipherHashStableWhenExtensionsJitter(t *testing.T) {
	base := helloWithExtOrder([]int{0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b})
	jittered := helloWithExtOrder([]int{0x0000, 0x000a, 0x000d, 0x0010, 0x002b})
	h1, ok1 := ja4(base)
	h2, ok2 := ja4(jittered)
	if !ok1 || !ok2 {
		t.Fatal("ja4 failed")
	}
	if h1 == h2 {
		t.Fatal("the extension set did not move the full ja4, so this proves nothing")
	}
	if ja4Ciphers(h1) != ja4Ciphers(h2) {
		t.Fatalf("cipher hash moved when only extensions changed: %s vs %s", ja4Ciphers(h1), ja4Ciphers(h2))
	}
}
