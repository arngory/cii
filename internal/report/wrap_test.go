package report

import (
	"strings"
	"testing"

	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/risk"
	"github.com/arngory/cii/internal/route"
	"github.com/arngory/cii/internal/services"
)

func TestWrapVisible(t *testing.T) {
	c := paint(true)
	line := c.dim("DNSBL ") + " " + c.yellow("?") + " zen.spamhaus.org " + c.dim("127.255.255.254 refused: query via public/open resolver, use your own resolver to get an answer")
	got := wrapVisible(line, 40)
	if len(got) < 3 {
		t.Fatalf("not wrapped: %q", got)
	}
	var plain []string
	for _, l := range got {
		if visibleLen(l) > 40 {
			t.Errorf("line too long (%d): %q", visibleLen(l), l)
		}
		if esc := ansiSeq.FindAllString(l, -1); len(esc) > 0 && esc[len(esc)-1] != "\x1b[0m" {
			t.Errorf("style left open: %q", l)
		}
		plain = append(plain, ansiSeq.ReplaceAllString(l, ""))
	}
	joined := strings.Join(strings.Fields(strings.Join(plain, " ")), " ")
	if strings.Contains(joined, "…") || !strings.HasSuffix(joined, "use your own resolver to get an answer") {
		t.Errorf("text lost:\n%s", joined)
	}
	for _, l := range plain[1:] {
		if !strings.HasPrefix(l, "       ") || strings.HasPrefix(l, "        ") {
			t.Errorf("continuation not aligned under the text after the label: %q", l)
		}
	}
	if !strings.HasPrefix(got[1], "       \x1b[2m") {
		t.Errorf("continuation does not reopen the dim style: %q", got[1])
	}
	for _, l := range wrapVisible(c.dim(strings.Repeat("a", 39))+" bbbb cccc", 40) {
		if esc := ansiSeq.FindAllString(l, -1); len(esc) > 0 && esc[len(esc)-1] != "\x1b[0m" {
			t.Errorf("style left open at a break on the closing space: %q", l)
		}
	}
	if w := wrapVisible("short", 40); len(w) != 1 || w[0] != "short" {
		t.Errorf("short line = %q", w)
	}
	long := strings.Repeat("x", 95)
	for _, l := range wrapVisible(long, 40) {
		if visibleLen(l) > 40 {
			t.Errorf("unbroken word overflows: %q", l)
		}
	}
}

func TestLongDetailKeepsOtherGroupsInColumns(t *testing.T) {
	rs := []probe.Result{
		{Group: services.Streaming, Service: "Netflix", Status: probe.Yes},
		{Group: services.Streaming, Service: "Disney+", Status: probe.Yes},
		{Group: services.Streaming, Service: "Hulu", Status: probe.No},
		{Group: services.Streaming, Service: "Max", Status: probe.Yes},
		{Group: risk.DNSBL, Service: "zen.spamhaus.org", Status: probe.Unknown, Detail: "refused: query via public/open resolver, use your own resolver to get an answer"},
	}
	var b strings.Builder
	writeGrid2(&b, paint(false), unicodeMarks, 100, []column{newColumn("result", rs)}, [][]string{nil})
	out := b.String()
	paired := false
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "Netflix") && strings.Contains(l, "Disney+") {
			paired = true
		}
	}
	if !paired || !strings.Contains(out, "use your own resolver to get an answer") {
		t.Errorf("streaming collapsed to one column or detail cut:\n%s", out)
	}
}

func TestRegionNotesEdgeCountry(t *testing.T) {
	s := region.Summarize([]probe.Result{
		{Group: region.GeoIP, Service: "a", Status: probe.OK, Country: "KG"},
		{Group: region.GeoIP, Service: "b", Status: probe.OK, Country: "KG"},
		{Group: region.GeoIP, Service: "c", Status: probe.OK, Country: "KG"},
		{Group: region.Platform, Service: "Google", Status: probe.OK, Country: "KG"},
		{Group: region.Platform, Service: "Apple", Status: probe.OK, Country: "KG"},
		{Group: region.Platform, Service: "ChatGPT", Status: probe.OK, Country: "PL"},
		{Group: region.CDN, Service: "Cloudflare", Status: probe.OK, Country: "PL", IATA: "WAW"},
	})
	var text []string
	for _, p := range regionParts(paint(false), unicodeMarks, &s) {
		text = append(text, p.text)
	}
	if got := strings.Join(text, " | "); !strings.Contains(got, "ChatGPT says PL (= CDN edge Cloudflare WAW)") {
		t.Errorf("region parts = %s", got)
	}
}

func TestSmallScreens(t *testing.T) {
	r := Demo("online")
	r.Route = &route.Report{Method: "icmp", FloorMs: 0.9, Paths: []route.Path{
		{Target: route.Target{Name: "Telegram DC2", Group: route.Messaging}, RTTms: 30.5, Verdict: route.Distant, Reason: "single-location service, +30 ms away"},
		{Target: route.Target{Name: "Google", Group: route.Search}, RTTms: 1, Verdict: route.Direct},
	}}
	for _, lang := range []string{"en", "ru"} {
		for _, width := range []int{50, 60, 80} {
			for _, line := range r.Screen(Style{Unicode: true, Width: width, Lang: lang}, "cii test", []string{"footer"}) {
				if visibleLen(line) > width {
					t.Errorf("%s width %d: line too long: %q", lang, width, line)
				}
				if strings.Contains(line, "…") {
					t.Errorf("%s width %d: content clipped: %q", lang, width, line)
				}
			}
		}
	}
	narrow := strings.Join(r.Screen(Style{Unicode: true, Width: 50}, "", nil), "\n")
	if !strings.Contains(narrow, "cc prx VPN Tor hst abu bot") || !strings.Contains(narrow, "ip2location.io  DE") {
		t.Errorf("narrow factor table:\n%s", narrow)
	}
	wide := strings.Join(r.Screen(Style{Unicode: true, Width: 80}, "", nil), "\n")
	if !strings.Contains(wide, "cc proxy   VPN   Tor  host abuse   bot") {
		t.Errorf("wide factor table changed:\n%s", wide)
	}
}
