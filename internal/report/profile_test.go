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
	}, false)
	h.SetRegion(region.Summarize([]probe.Result{
		{Group: region.GeoIP, Service: "ipquery.io", Status: probe.OK, Country: "DE", Facts: facts("isp", 3, map[probe.Flag]bool{probe.VPN: false, probe.Hosting: false})},
		{Group: region.GeoIP, Service: "ip-api.com", Status: probe.OK, Country: "DE", Facts: facts("hosting", -1, map[probe.Flag]bool{probe.Proxy: true, probe.Hosting: true})},
		{Group: region.Registry, Service: "RDAP (RIR)", Status: probe.OK, Country: "US"},
	}), false)
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
	empty.SetServices([]probe.Result{{Group: risk.DNSBL, Service: "z", Status: probe.Yes}}, false)
	if empty.Profile != nil {
		t.Errorf("profile without facts = %+v", empty.Profile)
	}
}

func TestProfileOutput(t *testing.T) {
	r := &Report{Tool: Tool{Name: "cii"}, IPv4: sampleProfileHost()}
	out := strings.Join(r.Screen(Style{Width: 200, Unicode: true}, "", nil), "\n")
	for _, s := range []string{
		"US, geo-discrepant",
		"Type     ISP 2/3 · hosting: ip-api.com",
		"ipquery.io        3     —    no     —    no     —     —",
		"proxycheck.io    66    no   yes     —     —     —     —",
		"AbuseIPDB         0     —     —     —     —    no     —",
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
	out = detailed.String()
	for _, s := range []string{"IP profile (IPv4) · registered US, geo-discrepant", "source", "abuser", "RDAP (RIR)", "Registry"} {
		if !strings.Contains(out, s) {
			t.Errorf("%q missing in detailed output:\n%s", s, out)
		}
	}
}
