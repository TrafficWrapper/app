package device

import "testing"

func TestObfChainRejectsInvalidLengths(t *testing.T) {
	for _, spec := range []string{
		"<r -1>",
		"<rc -5>",
		"<rd -1>",
		"<dz -2>",
		"<r 65536>",
		"<rc 999999999999>",
		"<dz 9>",
		"<b 0x01><r -1>",
	} {
		if _, err := newObfChain(spec); err == nil {
			t.Fatalf("spec %q accepted", spec)
		}
	}
}

func TestObfChainAcceptsValidLengths(t *testing.T) {
	chain, err := newObfChain("<b 0xabcd><r 16><rc 4><rd 3><dz 2>")
	if err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	if got, want := chain.ObfuscatedLen(0), 2+16+4+3+2; got != want {
		t.Fatalf("obfuscated len=%d want %d", got, want)
	}
	buf := make([]byte, chain.ObfuscatedLen(0))
	chain.Obfuscate(buf, nil)
}
