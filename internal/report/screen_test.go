package report

import (
	"slices"
	"strings"
	"testing"

	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/risk"
)

func TestColumnWidths(t *testing.T) {
	for width, want := range map[int][]int{
		80: {80}, 109: {109}, 110: {60, 49}, 150: {60, 89}, 199: {76, 122}, 200: {66, 74, 58}, 240: {66, 114, 58},
	} {
		if got := columnWidths(width, columnCount(width)); !slices.Equal(got, want) {
			t.Errorf("columnWidths(%d) = %v, want %v", width, got, want)
		}
	}
	if got := columnWidths(240, 2); !slices.Equal(got, []int{76, 163}) {
		t.Errorf("two panels on a wide screen = %v", got)
	}
}

func TestClipVisible(t *testing.T) {
	c := paint(true)
	s := c.green("abcdef") + "gh"
	if visibleLen(s) != 8 {
		t.Fatalf("visibleLen = %d", visibleLen(s))
	}
	got := clipVisible(s, 4)
	if visibleLen(got) != 4 || !strings.HasSuffix(got, "…\x1b[0m") {
		t.Errorf("clipVisible = %q", got)
	}
	if clipVisible("abc", 5) != "abc" || padVisible("ab", 4) != "ab  " {
		t.Error("short strings changed")
	}
}

func screenReport() *Report {
	return &Report{Tool: Tool{Name: "cii", Version: "test"}, IPv4: sampleProfileHost(), IPv6: &Host{Error: "no IPv6"}}
}

func TestScreenLayouts(t *testing.T) {
	titles := []string{"IP quality · IPv4", "Region & services", "Reputation lists & mail"}
	for _, c := range []struct {
		width   int
		perLine int
	}{{80, 1}, {150, 2}, {220, 3}} {
		lines := screenReport().Screen(Style{Unicode: true, Width: c.width}, "cii test", []string{"footer note"})
		out := strings.Join(lines, "\n")
		for _, l := range lines {
			if visibleLen(l) > c.width {
				t.Errorf("width %d: line too long (%d): %q", c.width, visibleLen(l), l)
			}
		}
		best := 0
		for _, l := range lines {
			n := 0
			for _, title := range titles {
				if strings.Contains(l, title) {
					n++
				}
			}
			best = max(best, n)
		}
		if best != c.perLine {
			t.Errorf("width %d: %d panel titles side by side, want %d\n%s", c.width, best, c.perLine, out)
		}
		for _, s := range []string{"cii test", "IP quality · IPv6", "unavailable", "⚠ geo-discrepant", "Type ─", "Score ─", "Factors ─", "■■■■□ high", "abuse", "✗ proxycheck.io: VPN; risk 66", "bl.spamcop.net", "footer note"} {
			if !strings.Contains(out, s) {
				t.Errorf("width %d: %q missing\n%s", c.width, s, out)
			}
		}
		if strings.Contains(out, "registered US") {
			t.Errorf("width %d: registry repeated in the region line\n%s", c.width, out)
		}
	}
	ascii := strings.Join(screenReport().Screen(Style{Width: 80}, "", nil), "\n")
	if strings.ContainsAny(ascii, "┌│└✓✗") || !strings.Contains(ascii, "+- IP quality") {
		t.Errorf("ASCII frame:\n%s", ascii)
	}
}

func TestScreenPendingAndProgress(t *testing.T) {
	h := &Host{Address: "203.0.113.7"}
	h.SetServices([]probe.Result{
		{Group: risk.Reputation, Service: "proxycheck.io", Status: probe.Pending},
		{Group: risk.DNSBL, Service: "bl.spamcop.net", Status: probe.Pending},
		{Group: risk.DNSBL, Service: "psbl.surriel.com", Status: probe.Yes},
	}, false)
	r := &Report{IPv4: h}
	if done, total := Progress(r); done != 1 || total != 3 {
		t.Errorf("progress = %d/%d", done, total)
	}
	out := strings.Join(r.Screen(Style{Unicode: true, Width: 100}, "", nil), "\n")
	if !strings.Contains(out, "◌ waiting: proxycheck.io") || !strings.Contains(out, "◌ bl.spamcop.net") {
		t.Errorf("pending output:\n%s", out)
	}
}

func TestScreenNarrowAndOffline(t *testing.T) {
	r := screenReport()
	r.IPv6 = &Host{Error: "offline: no global IPv6 address on local interfaces"}
	for _, w := range []int{40, 59} {
		lines := r.Screen(Style{Unicode: true, Width: w}, "cii test with a long header line", []string{"footer"})
		for _, l := range lines {
			if visibleLen(l) > w {
				t.Errorf("width %d: line too long (%d): %q", w, visibleLen(l), l)
			}
		}
		if out := strings.Join(lines, "\n"); !strings.Contains(out, "not on local interfaces") {
			t.Errorf("width %d: offline reason missing\n%s", w, out)
		}
	}
}

func TestScreenCensorAndBenchPanels(t *testing.T) {
	censorResults := []probe.Result{{Group: "dns", Service: "Cloudflare DoH", Status: probe.Yes}, {Group: "telegram", Service: "DC2", Status: probe.No}}
	full := screenReport()
	full.Censor = censorResults
	full.Bench = sampleBench()
	out := strings.Join(full.Screen(Style{Unicode: true, Width: 220}, "", nil), "\n")
	for _, s := range []string{"Censorship", "DNS       ✓ 1", "Telegram  ✗ 1", "✗ Telegram: DC2", "Benchmark", "Cloudflare FRA"} {
		if !strings.Contains(out, s) {
			t.Errorf("%q missing in the full screen\n%s", s, out)
		}
	}
	if out := strings.Join((&Report{Mode: "censor", Censor: censorResults}).Screen(Style{Unicode: true, Width: 150}, "", nil), "\n"); !strings.Contains(out, "✓ Cloudflare DoH") {
		t.Errorf("cii censor should list every check\n%s", out)
	}
	for _, r := range []*Report{{Mode: "censor", Censor: censorResults}, {Mode: "bench", Bench: sampleBench()}} {
		lines := r.Screen(Style{Unicode: true, Width: 150}, "", nil)
		if len(lines) == 0 || visibleLen(lines[0]) != 150 {
			t.Errorf("%s: a single panel should take the whole width\n%s", r.Mode, strings.Join(lines, "\n"))
		}
	}
	if strings.Contains(out, "Cloudflare DoH") {
		t.Errorf("clean censorship results should only be counted\n%s", out)
	}
	if lines := (&Report{Mode: "bench"}).Screen(Style{Width: 100}, "cii · benchmark: disk", nil); len(lines) != 1 {
		t.Errorf("empty bench screen = %q", lines)
	}
}

func TestQualityRouteAndPTR(t *testing.T) {
	build := func(mask bool) string {
		h := &Host{Address: "203.0.113.7"}
		level := 1
		score := 62
		h.SetServices([]probe.Result{
			{Group: risk.Network, Service: risk.PTRService, Status: probe.Yes, Detail: "host-203-0-113-7.example.net"},
			{Group: risk.Reputation, Service: "IPQualityScore", Status: probe.Yes, Facts: &probe.Facts{Score: &score, Level: &level}},
		}, mask)
		h.SetRegion(region.Summarize([]probe.Result{
			{Group: region.GeoIP, Service: "a", Status: probe.OK, Country: "DE"},
			{Group: region.Registry, Service: "RIPEstat", Status: probe.OK, Country: "DE", Detail: "203.0.112.0/20 · AS64500 Example"},
		}), mask)
		return strings.Join((&Report{IPv4: h}).Screen(Style{Unicode: true, Width: 200}, "", nil), "\n")
	}
	out := build(false)
	for _, s := range []string{"Route    203.0.112.0/20 · AS64500 Example", "PTR      host-203-0-113-7.example.net", "62 ■■□□□ low"} {
		if !strings.Contains(out, s) {
			t.Errorf("%q missing\n%s", s, out)
		}
	}
	if strings.Count(out, "Reverse DNS") != 0 {
		t.Errorf("PTR repeated in the lists panel\n%s", out)
	}
	masked := build(true)
	if strings.Contains(masked, "113-7") || strings.Contains(masked, "203.0.112.0") || !strings.Contains(masked, "PTR      hidden (--mask)") {
		t.Errorf("masked output leaks\n%s", masked)
	}
}

func TestScreenExits(t *testing.T) {
	exit := func(label, via, netflix string) *Host {
		h := &Host{Address: "203.0.113.7", Query: label, Via: via}
		h.SetServices([]probe.Result{{Group: "streaming", Service: "Netflix", Status: probe.Status(netflix)}}, false)
		return h
	}
	r := &Report{Exits: []*Host{exit("exit 1", "socks5://a.example:1080", "yes"), exit("exit 2", "http://b.example:3128", "no")}}
	out := strings.Join(r.Screen(Style{Unicode: true, Width: 160}, "", nil), "\n")
	for _, s := range []string{"IP quality · exit 1", "IP quality · exit 2", "Via      socks5://a.example:1080", "marks: exit 1 exit 2", "✓✗ Netflix"} {
		if !strings.Contains(out, s) {
			t.Errorf("%q missing\n%s", s, out)
		}
	}
}

func TestScreenRussian(t *testing.T) {
	out := strings.Join(screenReport().Screen(Style{Unicode: true, Width: 160, Lang: "ru"}, "", nil), "\n")
	for _, s := range []string{"Качество IP · IPv4", "Регион и сервисы", "Адрес", "Реестр", "не совпадает с геолокацией", "Факторы", "прокси", "высокая", "чисто, ✗ обнаружено"} {
		if !strings.Contains(out, s) {
			t.Errorf("%q missing\n%s", s, out)
		}
	}
	if Translate("xx", "Address") != "Address" || Legend(&Report{}, true, "ru") != "" {
		t.Error("fallbacks broken")
	}
}
