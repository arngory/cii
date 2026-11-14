package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/ipdetect"
	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/report"
	"github.com/arngory/cii/internal/risk"
	"github.com/arngory/cii/internal/services"
)

type recording struct {
	status int
	header http.Header
	body   string
}

type cassette struct {
	mu        sync.Mutex
	entries   map[string]recording
	played    map[string]int
	unmatched []string
	agents    []string
}

func loadCassette(t *testing.T, path string) *cassette {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c := &cassette{entries: map[string]recording{}, played: map[string]int{}}
	for _, block := range strings.Split("\n"+string(raw), "\n=== ")[1:] {
		head, rest, _ := strings.Cut(block, "\n")
		f := strings.Fields(head)
		if len(f) != 3 {
			t.Fatalf("%s: bad entry line %q", path, head)
		}
		status, err := strconv.Atoi(f[2])
		if err != nil {
			t.Fatalf("%s: bad status in %q", path, head)
		}
		headers, body, _ := strings.Cut(rest, "\n\n")
		rec := recording{status: status, header: http.Header{}, body: strings.TrimSuffix(body, "\n")}
		for _, line := range strings.Split(headers, "\n") {
			if k, v, ok := strings.Cut(line, ": "); ok {
				rec.header.Add(k, v)
			}
		}
		key := f[0] + " " + f[1]
		if _, dup := c.entries[key]; dup {
			t.Fatalf("%s: %s is recorded twice", path, key)
		}
		c.entries[key] = rec
	}
	return c
}

func (c *cassette) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.Method + " " + req.URL.String()
	c.mu.Lock()
	rec, ok := c.entries[key]
	if ok {
		c.played[key]++
	} else {
		c.unmatched = append(c.unmatched, key)
		rec = recording{status: http.StatusServiceUnavailable, header: http.Header{}}
	}
	c.agents = append(c.agents, req.Header.Get("User-Agent"))
	c.mu.Unlock()
	body := rec.body
	if req.Method == http.MethodHead {
		body = ""
	}
	return &http.Response{
		StatusCode: rec.status, Status: fmt.Sprintf("%d %s", rec.status, http.StatusText(rec.status)),
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: rec.header.Clone(), Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: req,
	}, nil
}

func TestRecordedRun(t *testing.T) {
	tape := loadCassette(t, "testdata/de-residential.replay")
	keys := config.Keys{}
	checks := append(region.Select(keys, false), services.Select(keys, false)...)
	checks = append(checks, risk.Checks(keys, false)...)
	led := ledger.New()
	n := netx.New(netx.Options{Family: netx.IPv4, Transport: tape}, netx.NewPolicy(probe.Rules(checks)...), led)
	ip := netip.MustParseAddr("203.0.113.7")
	results := probe.Run(context.Background(), probe.Env{Nets: map[netx.Family]*netx.Net{netx.IPv4: n}, Keys: keys}, netx.IPv4, ip, checks)

	for key := range tape.entries {
		if tape.played[key] == 0 {
			t.Errorf("recorded but never requested (the check changed its request?): %s", key)
		}
	}
	for _, key := range tape.unmatched {
		if strings.Contains(key, "{ip}") || strings.Contains(key, "%7Bip%7D") {
			t.Errorf("address placeholder was not filled in: %s", key)
		}
	}
	for _, ua := range tape.agents {
		if ua != netx.DefaultUserAgent() {
			t.Fatalf("a request went out with User-Agent %q", ua)
		}
	}
	for _, e := range led.Entries() {
		if e.Blocked > 0 {
			t.Errorf("a default check contacts a host its rules do not declare: %+v", e)
		}
	}
	if len(led.Entries()) < len(tape.entries)/2 {
		t.Errorf("ledger has %d entries for %d recordings", len(led.Entries()), len(tape.entries))
	}

	var regional, other []probe.Result
	for _, r := range results {
		if region.Owns(r.Group) {
			regional = append(regional, r)
		} else {
			other = append(other, r)
		}
	}
	host := report.NewHost(ipdetect.Address{Address: ip, Source: "echo:test"}, nil)
	host.SetServices(other)
	host.SetRegion(region.Summarize(regional))
	if !slices.Equal(host.Region.Verdict, []string{"DE"}) {
		t.Errorf("verdict = %v", host.Region.Verdict)
	}
	find := func(group probe.Group, service string) probe.Result {
		t.Helper()
		for _, r := range results {
			if r.Group == group && r.Service == service {
				return r
			}
		}
		t.Errorf("no result for %s / %s", group, service)
		return probe.Result{}
	}
	for _, want := range []struct {
		group   probe.Group
		service string
		status  probe.Status
		country string
	}{
		{region.Registry, "RIPEstat", probe.OK, "DE"}, {region.Registry, "RDAP (RIR)", probe.OK, "DE"},
		{region.GeoIP, "DB-IP", probe.OK, "DE"}, {region.GeoIP, "ifconfig.co", probe.OK, "DE"}, {region.GeoIP, "geojs.io", probe.OK, "DE"},
		{region.GeoIP, "ipwho.is", probe.OK, "AT"}, {region.GeoIP, "ip-api.com", probe.OK, "DE"}, {region.GeoIP, "ipbase.com", probe.Failed, ""},
		{region.Platform, "Cloudflare", probe.OK, "DE"}, {region.CDN, "Cloudflare", probe.OK, "DE"}, {region.Platform, "Apple", probe.OK, "DE"},
		{region.Platform, "Steam", probe.OK, "DE"}, {region.Platform, "JetBrains", probe.OK, "DE"}, {region.Platform, "Google", probe.Failed, ""},
		{services.Streaming, "Netflix", probe.Yes, "DE"}, {services.Web, "Reddit", probe.Yes, ""}, {services.Web, "Wikipedia editing", probe.Yes, ""},
		{services.AI, "OpenAI API", probe.Yes, ""}, {services.AI, "Anthropic API", probe.Yes, ""}, {services.AI, "Kimi API (CN)", probe.IPBlock, ""},
		{risk.Reputation, "proxycheck.io", probe.Yes, "DE"},
	} {
		if got := find(want.group, want.service); got.Status != want.status || got.Country != want.country {
			t.Errorf("%s / %s = %s %q (%s), want %s %q", want.group, want.service, got.Status, got.Country, got.Reason, want.status, want.country)
		}
	}
	if got := find(region.Registry, "RIPEstat"); !strings.Contains(got.Detail, "AS64500") {
		t.Errorf("RIPEstat detail = %q", got.Detail)
	}
	if got := find(region.CDN, "Cloudflare"); got.IATA != "FRA" {
		t.Errorf("Cloudflare edge = %+v", got)
	}
	if p := host.Profile; p == nil || p.Registered != "DE" || p.GeoConsistent == nil || !*p.GeoConsistent ||
		len(p.Usage) == 0 || p.Usage[0].Value != "isp" || len(p.Scores) != 2 {
		t.Errorf("profile = %+v", p)
	}

	rep := report.New("online")
	rep.IPv4 = host
	rep.Network = led.Entries()
	screen := strings.Join(rep.Screen(report.Style{Unicode: true, Width: 160}, "", nil), "\n")
	for _, want := range []string{"203.0.113.7", "DE Germany", "Cloudflare FRA DE", "Registry DE  ✓ geo-consistent", "✓ Netflix", "✓ OpenAI API"} {
		if !strings.Contains(screen, want) {
			t.Errorf("%q missing on screen:\n%s", want, screen)
		}
	}
	var js bytes.Buffer
	if err := rep.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	masked := strings.Join(rep.Scrubbed().Screen(report.Style{Unicode: true, Width: 160}, "", nil), "\n")
	for _, leak := range []string{"203.0.113", "64500", "EXAMPLE-NET"} {
		if strings.Contains(masked, leak) {
			t.Errorf("masked screen of the recorded run leaks %q", leak)
		}
	}
}
