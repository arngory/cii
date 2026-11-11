package main

import (
	"testing"

	"github.com/arngory/cii/internal/netx"
)

func TestParseSize(t *testing.T) {
	good := map[string]int64{
		"1":                   1,
		"4k":                  4 << 10,
		" 64M ":               64 << 20,
		"1G":                  1 << 30,
		"8589934591G":         8589934591 << 30,
		"9223372036854775807": 9223372036854775807,
	}
	for in, want := range good {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "x", "0", "-1G", "G", "1T", "8589934592G", "9999999999G", "9007199254740992K", "99999999999999999999"} {
		if got, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) = %d, want error", in, got)
		}
	}
}

func TestClipRunes(t *testing.T) {
	if got := clipRunes("… 12 more lines", 6); got != "… 12 …" {
		t.Errorf("clipRunes = %q", got)
	}
	if got := clipRunes("short", 10); got != "short" {
		t.Errorf("clipRunes = %q", got)
	}
}

func TestExitsAndProxyLabel(t *testing.T) {
	c := common{proxy: "socks5://user:secret@203.0.113.9:1080, http://proxy.example:3128"}
	ex := c.exits()
	if len(ex) != 2 || ex[0].label != "exit 1" || ex[1].c.proxy != "http://proxy.example:3128" || ex[0].via != "socks5://203.0.113.9:1080" {
		t.Fatalf("exits = %+v", ex)
	}
	if one := (&common{proxy: " http://p.example:1, "}).exits(); len(one) != 1 || one[0].label != "" || one[0].c.proxy != "http://p.example:1" {
		t.Errorf("single proxy = %+v", one)
	}
	if v6 := (&common{v6: true, proxy: "http://a.example:1,http://b.example:1"}).exits(); v6[0].family != netx.IPv6 || v6[1].family != netx.IPv6 {
		t.Errorf("-6 exits = %+v", v6)
	}
	if got := proxyLabel("socks5://u:p@203.0.113.9:1080"); got != "socks5://203.0.113.9:1080" {
		t.Errorf("masked label = %q", got)
	}
}
