package report

import (
	"net/netip"
	"strings"
	"testing"
)

func TestMaskAddr(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9":       "203.0.*.*",
		"2a00:1450:4001::1": "2a00:1450:*:*",
	} {
		if got := MaskAddr(netip.MustParseAddr(in), true); got != want {
			t.Errorf("MaskAddr(%s) = %s, want %s", in, got, want)
		}
		if got := MaskAddr(netip.MustParseAddr(in), false); got != in {
			t.Errorf("unmasked %s = %s", in, got)
		}
	}
}

func TestMaskText(t *testing.T) {
	in := "dial tcp4 203.0.113.5:0->198.51.100.7:443: connect: refused; [2a00:1450:4001::1]:443 v1.2 ok"
	got := MaskText(in)
	for _, leak := range []string{"203.0.113.5", "198.51.100.7", "4001::1"} {
		if strings.Contains(got, leak) {
			t.Fatalf("MaskText leaked %s: %s", leak, got)
		}
	}
	if !strings.Contains(got, "203.0.*.*") || !strings.Contains(got, "connect: refused") || !strings.Contains(got, "v1.2 ok") {
		t.Fatalf("MaskText mangled text: %s", got)
	}
}
