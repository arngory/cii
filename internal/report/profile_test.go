package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/risk"
)

func facts(usage string, score int, flags map[probe.Flag]bool) *probe.Facts {
	f := &probe.Facts{Usage: usage, Flags: flags}
	if score >= 0 {
		f.Score = &score
	}
	return f
}

func sampleProfileHost() *Host {
	h := &Host{Address: "203.0.113.7"}
	h.SetServices([]probe.Result{
		{Group: risk.Reputation, Service: "proxycheck.io", Status: probe.No, Detail: "VPN; risk 66", Facts: facts("", 66, map[probe.Flag]bool{probe.VPN: true, probe.Proxy: false})},
		{Group: risk.Reputation, Service: "AbuseIPDB", Status: probe.Yes, Facts: facts("isp", 0, map[probe.Flag]bool{probe.Abuser: false})},
		{Group: risk.Reputation, Service: "ipdata", Status: probe.Failed, Reason: "key rejected (HTTP 401)"},
		{Group: risk.DNSBL, Service: "bl.spamcop.net", Status: probe.Yes},
	})
	h.SetRegion(region.Summarize([]probe.Result{
		{Group: region.GeoIP, Service: "ipquery.io", Status: probe.OK, Country: "DE", Facts: facts("isp", 3, map[probe.Flag]bool{probe.VPN: false, probe.Hosting: false})},
		{Group: region.GeoIP, Service: "ip-api.com", Status: probe.OK, Country: "DE", Facts: facts("hosting", -1, map[probe.Flag]bool{probe.Proxy: true, probe.Hosting: true})},
		{Group: region.Registry, Service: "RDAP (RIR)", Status: probe.OK, Country: "US"},
	}))
	return h
}

func TestProfileSummary(t *testing.T) {
	p := sampleProfileHost().Profile
	if p == nil || p.Registered != "US" || p.GeoConsistent == nil || *p.GeoConsistent {
		t.Fatalf("profile = %+v", p)
	}
	if len(p.Usage) != 2 || p.Usage[0].Value != "isp" || len(p.Usage[0].Sources) != 2 || p.Usage[1].Sources[0] != "ip-api.com" {
		t.Errorf("usage = %+v", p.Usage)
	}
	if len(p.Scores) != 3 {
		t.Errorf("scores = %+v", p.Scores)
	}
	want := map[probe.Flag]string{probe.Proxy: "1/2", probe.VPN: "1/2", probe.Hosting: "1/2", probe.Abuser: "0/1"}
	if len(p.Factors) != len(want) {
		t.Fatalf("factors = %+v", p.Factors)
	}
	for _, f := range p.Factors {
		if got := fmt.Sprintf("%d/%d", len(f.Hits), f.Checked); got != want[f.Flag] {
			t.Errorf("%s = %s, want %s", f.Flag, got, want[f.Flag])
		}
	}
	if (&Host{}).Profile != nil {
		t.Error("empty host has a profile")
	}
	var empty Host
	empty.SetServices([]probe.Result{{Group: risk.DNSBL, Service: "z", Status: probe.Yes}})
	if empty.Profile != nil {
		t.Errorf("profile without facts = %+v", empty.Profile)
	}
}

func TestProfileOutput(t *testing.T) {
	r := &Report{Tool: Tool{Name: "cii"}, IPv4: sampleProfileHost()}
	out := strings.Join(r.Screen(Style{Width: 200, Unicode: true}, "", nil), "\n")
	for _, s := range []string{
		"Registry US  ⚠ geo-discrepant",
		"ipquery.io    [ISP ]   ",
		"ip-api.com    [HOST]   ",
		"ipquery.io      3 ■□□□□ very low",
		"proxycheck.io  66 ■■■■□ high",
		"cc proxy   VPN   Tor  host abuse   bot",
		"ipquery.io     DE     ·     ✓     ·     ✓     ·     ·",
		"proxycheck.io  —      ✓     ✗     ·     ·     ·     ·",
		"AbuseIPDB      —      ·     ·     ·     ·     ✓     ·",
		"bl.spamcop.net",
		"! ipdata: key rejected (HTTP 401)",
		"✗ proxycheck.io: VPN; risk 66",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("%q missing in screen:\n%s", s, out)
		}
	}
	if strings.Contains(out, "✓ AbuseIPDB") {
		t.Errorf("clean reputation answers should stay in the factor table only:\n%s", out)
	}
	var detailed strings.Builder
	r.WriteDetailed(&detailed, false)
	plain := detailed.String()
	for _, s := range []string{"IP profile (IPv4) · registered US, geo-discrepant", "source", "abuser", "RDAP (RIR)", "Registry"} {
		if !strings.Contains(plain, s) {
			t.Errorf("%q missing in detailed output:\n%s", s, plain)
		}
	}
	if strings.Contains(out, "company") || strings.Contains(plain, "company") {
		t.Errorf("company column shown though no source reports a company type:\n%s\n%s", out, plain)
	}
}

func TestProfileCompanyColumn(t *testing.T) {
	h := sampleProfileHost()
	h.SetServices(append(h.Services, probe.Result{Group: risk.Reputation, Service: "ipinfo.io", Status: probe.Yes,
		Facts: &probe.Facts{Usage: "isp", Company: "business"}}))
	r := &Report{Tool: Tool{Name: "cii"}, IPv4: h}
	out := strings.Join(r.Screen(Style{Width: 200, Unicode: true}, "", nil), "\n")
	for _, s := range []string{"usage  company", "ipquery.io    [ISP ]  —", "ipinfo.io     [ISP ] [BIZ ]"} {
		if !strings.Contains(out, s) {
			t.Errorf("%q missing in screen:\n%s", s, out)
		}
	}
	var detailed strings.Builder
	r.WriteDetailed(&detailed, false)
	if plain := detailed.String(); !strings.Contains(plain, "company") || !strings.Contains(plain, "business") {
		t.Errorf("company column missing in detailed output:\n%s", plain)
	}
	if p := h.Profile; len(p.Company) != 1 || p.Company[0].Value != "business" || p.Company[0].Sources[0] != "ipinfo.io" {
		t.Errorf("company votes = %+v", p.Company)
	}
}
