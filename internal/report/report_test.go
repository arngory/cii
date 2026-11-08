package report

import (
	"net/netip"
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
