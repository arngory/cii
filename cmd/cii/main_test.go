package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/report"
	"github.com/arngory/cii/internal/runlog"
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

func TestLoadReportFromLogAndJSON(t *testing.T) {
	dir := t.TempDir()
	rep := report.Demo("online")
	var js bytes.Buffer
	if err := rep.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	logPath, err := runlog.Write(dir, time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), []byte("frame text\n\n"), []byte(runlog.JSONMarker), js.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	jsonPath := filepath.Join(dir, "r.json")
	if err := os.WriteFile(jsonPath, js.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{logPath, jsonPath} {
		r, err := loadReport(p)
		if err != nil || r.IPv4 == nil || r.IPv4.Address != "203.0.113.7" {
			t.Fatalf("loadReport(%s) = %+v, %v", p, r, err)
		}
		if m := r.Scrubbed(); m.IPv4.Address != "•••" || !m.Masked {
			t.Errorf("masked past report = %+v", m.IPv4)
		}
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"schema":"other/v9"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadReport(bad); err == nil || !strings.Contains(err.Error(), "unsupported report schema") {
		t.Errorf("foreign schema = %v", err)
	}
}

func TestParseChoice(t *testing.T) {
	for in, want := range map[string]string{
		"":    "ip",
		" 1 ": "ip",
		"2m":  "ip --extended --mask",
		"2M":  "ip --extended --mask",
		"3":   "ip --extended --route --bench",
		"5m":  "censor --mask",
		"10":  "data update",
		"10m": "data update",
		"09":  "analyze",
	} {
		got, err := parseChoice(in)
		if err != nil || strings.Join(got, " ") != want {
			t.Errorf("parseChoice(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
	if !choicePattern.MatchString("2M") || choicePattern.MatchString("route") {
		t.Error("the command-line gate must accept 2M and leave command names alone")
	}
	if _, err := parseChoice("0"); !errors.Is(err, errMenuExit) {
		t.Errorf("0 = %v", err)
	}
	for _, bad := range []string{"11", "99", "m", "2x", "1 2", "-1", "123"} {
		if got, err := parseChoice(bad); err == nil {
			t.Errorf("parseChoice(%q) = %v, want error", bad, got)
		}
	}
	for i, it := range menu {
		if it.title["en"] == "" || it.title["ru"] == "" || it.hint["en"] == "" || it.hint["ru"] == "" || len(it.args) == 0 {
			t.Errorf("menu item %d incomplete: %+v", i+1, it)
		}
	}
}
