package report

import (
	"strings"
	"testing"

	"github.com/arngory/cii/internal/bench"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/services"
)

func TestDiff(t *testing.T) {
	old := &Report{IPv4: sampleProfileHost(), Censor: []probe.Result{{Group: "telegram", Service: "DC2", Status: probe.Yes}}, Bench: &bench.Report{Speed: &bench.Speed{DownMbps: 100, UpMbps: 20}}}
	cur := sampleProfileHost()
	cur.Address = "198.51.100.7"
	cur.SetServices(append(cur.Services, probe.Result{Group: services.Streaming, Service: "Netflix", Status: probe.No}))
	cur.SetRegion(region.Summarize([]probe.Result{{Group: region.GeoIP, Service: "ipquery.io", Status: probe.OK, Country: "NL"}}))
	now := &Report{IPv4: cur, Censor: []probe.Result{{Group: "telegram", Service: "DC2", Status: probe.No}}, Bench: &bench.Report{Speed: &bench.Speed{DownMbps: 100, UpMbps: 5}}}
	got := map[string]Change{}
	for _, ch := range Diff(old, now) {
		got[ch.Section+"|"+ch.Item] = ch
	}
	for key, want := range map[string][2]string{
		"IPv4|address":                     {"203.0.113.7", "198.51.100.7"},
		"IPv4|verdict":                     {"DE", "NL"},
		"IPv4|registry":                    {"US", "—"},
		"IPv4 services|Streaming: Netflix": {"—", "no"},
		"IPv4 region|GeoIP: ip-api.com":    {"ok DE", "—"},
		"IPv4 region|GeoIP: ipquery.io":    {"ok DE", "ok NL"},
		"Censorship|Telegram: DC2":         {"yes", "no"},
		"Benchmark|Cloudflare upload":      {"20.0 Mbit/s", "5.0 Mbit/s"},
	} {
		ch, ok := got[key]
		if !ok || ch.Before != want[0] || ch.After != want[1] {
			t.Errorf("%s = %+v, want %v", key, ch, want)
		}
	}
	if _, ok := got["Benchmark|Cloudflare download"]; ok {
		t.Error("unchanged download reported")
	}
	if len(Diff(old, old)) != 0 {
		t.Error("a report differs from itself")
	}
	var b strings.Builder
	WriteDiff(&b, false, "a.log", "b.log", Diff(old, now))
	if out := b.String(); !strings.Contains(out, "cii diff a.log → b.log") || !strings.Contains(out, "Telegram: DC2") {
		t.Errorf("diff output:\n%s", out)
	}
	b.Reset()
	WriteDiff(&b, false, "a", "b", nil)
	if !strings.Contains(b.String(), "no changes") {
		t.Errorf("empty diff = %q", b.String())
	}
}

func TestDiffAndDetailedExits(t *testing.T) {
	exit := func(addr string) *Host { return &Host{Query: "exit 1", Via: "http://p.example:1", Address: addr} }
	a, b := &Report{Exits: []*Host{exit("203.0.113.7")}}, &Report{Exits: []*Host{exit("198.51.100.7")}}
	ch := Diff(a, b)
	if len(ch) != 1 || ch[0].Section != "exit 1" || ch[0].After != "198.51.100.7" {
		t.Errorf("exit diff = %+v", ch)
	}
	var out strings.Builder
	b.WriteDetailed(&out, false)
	if !strings.Contains(out.String(), "exit 1") || !strings.Contains(out.String(), "198.51.100.7") {
		t.Errorf("detailed report misses the exit:\n%s", out.String())
	}
}
