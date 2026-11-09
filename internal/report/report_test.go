package report

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/risk"
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

func TestSetServicesMasksMailBanner(t *testing.T) {
	results := func() []probe.Result {
		return []probe.Result{
			{Group: risk.Mail, Service: "smtp", Detail: "554 5.7.1 Client host [203.0.113.5] blocked", Reason: "from 203.0.113.5"},
			{Group: risk.DNSBL, Service: "zen.spamhaus.org", Detail: "127.0.0.4 exploits"},
		}
	}
	var masked, plain Host
	masked.SetServices(results(), true)
	plain.SetServices(results(), false)
	if d := masked.Services[0].Detail; d != "554 5.7.1 Client host [203.0.*.*] blocked" {
		t.Errorf("masked mail detail = %q", d)
	}
	if r := masked.Services[0].Reason; strings.Contains(r, "113.5") {
		t.Errorf("masked mail reason = %q", r)
	}
	if d := masked.Services[1].Detail; d != "127.0.0.4 exploits" {
		t.Errorf("masked DNSBL detail = %q", d)
	}
	if d := plain.Services[0].Detail; !strings.Contains(d, "203.0.113.5") {
		t.Errorf("plain mail detail = %q", d)
	}
}

func TestMaskText(t *testing.T) {
	in := "dial tcp4 203.0.113.5:0->198.51.100.7:443: connect: refused; [2a00:1450:4001::1]:443 [2a01:4f8::]:0 ::ffff:9.9.9.9 v1.2 ok"
	got := MaskText(in)
	for _, leak := range []string{"203.0.113.5", "198.51.100.7", "4001::1", "2a01:4f8::", "9.9.9"} {
		if strings.Contains(got, leak) {
			t.Fatalf("MaskText leaked %s: %s", leak, got)
		}
	}
	if !strings.Contains(got, "203.0.*.*") || !strings.Contains(got, "connect: refused") || !strings.Contains(got, "v1.2 ok") {
		t.Fatalf("MaskText mangled text: %s", got)
	}
}
