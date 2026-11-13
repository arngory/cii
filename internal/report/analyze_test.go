package report

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/cii/internal/censor"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/risk"
	"github.com/arngory/cii/internal/route"
	"github.com/arngory/cii/internal/services"
)

func analysed(t *testing.T, r *Report, lang string) string {
	t.Helper()
	var b strings.Builder
	for _, f := range Analyze(r, lang) {
		b.WriteString(f.Level + " | " + f.Title + " | " + f.Detail + "\n")
	}
	return b.String()
}

func TestAnalyzeFindings(t *testing.T) {
	r := New("online")
	h := &Host{Address: "203.0.113.7"}
	h.SetServices([]probe.Result{
		{Group: services.Streaming, Service: "Disney+", Status: probe.No},
		{Group: services.AI, Service: "ChatGPT app", Status: probe.IPBlock},
		{Group: risk.DNSBL, Service: "zen.spamhaus.org", Status: probe.Unknown, Reason: "refused: query via public/open resolver"},
		{Group: risk.DNSBL, Service: "bl.spamcop.net", Status: probe.No},
		{Group: risk.Mail, Service: "Outbound SMTP (25)", Status: probe.No, Detail: "connection timed out, port 25 likely filtered (mx.example)"},
		{Group: risk.Reputation, Service: "proxycheck.io", Status: probe.No, Facts: demoFacts("hosting", "", 80, 3, map[probe.Flag]bool{probe.VPN: true, probe.Hosting: true})},
	})
	h.SetRegion(region.Summarize([]probe.Result{
		{Group: region.GeoIP, Service: "a", Status: probe.OK, Country: "DE"},
		{Group: region.GeoIP, Service: "b", Status: probe.OK, Country: "DE"},
		{Group: region.GeoIP, Service: "c", Status: probe.OK, Country: "DE"},
		{Group: region.Platform, Service: "Google", Status: probe.OK, Country: "DE"},
		{Group: region.Platform, Service: "Apple", Status: probe.OK, Country: "DE"},
		{Group: region.Platform, Service: "ChatGPT", Status: probe.OK, Country: "PL"},
		{Group: region.CDN, Service: "Cloudflare", Status: probe.OK, Country: "PL", IATA: "WAW"},
		{Group: region.Registry, Service: "RDAP (RIR)", Status: probe.OK, Country: "US"},
	}))
	r.IPv4 = h
	r.IPv6 = &Host{Error: "the resolver returns no AAAA records for any echo service: IPv6 is off or filtered on this network"}
	r.SetCensor([]probe.Result{
		{Group: censor.DNS, Service: "Port 53 interception (OpenDNS)", Status: probe.No, Detail: "I am not an OpenDNS resolver."},
		{Group: censor.DNS, Service: "Example 192.0.2.53 spoofing", Status: probe.Yes},
		{Group: censor.DNS, Service: "Example 192.0.2.53 DoH", Status: probe.No},
		{Group: censor.DPI, Service: "blocked.example HTTP", Status: probe.No},
		{Group: censor.DPI, Service: "blocked.example HTTPS", Status: probe.No},
		{Group: censor.Geoblock, Service: "geo.example HTTPS", Status: probe.No},
		{Group: censor.Telegram, Service: "DC2", Status: probe.No},
		{Group: censor.Telegram, Service: "DC4", Status: probe.Yes},
		{Group: censor.Portal, Service: "Google", Status: probe.No, Reason: "redirected (HTTP 302): captive portal or filter page"},
		{Group: censor.Portal, Service: "Ubuntu", Status: probe.No, Reason: "timeout"},
		{Group: censor.Local, Service: "Default route", Status: probe.Partial},
	})
	r.Route = &route.Report{Method: "icmp", Paths: []route.Path{
		{Target: route.Target{Name: "X"}, Verdict: route.Detour}, {Target: route.Target{Name: "Quad9"}, Verdict: route.Unreachable},
	}}
	out := analysed(t, r, "en")
	for _, want := range []string{
		"alert | Port 53 DNS is intercepted on the path | OpenDNS: I am not an OpenDNS resolver.. Answers match the reference",
		"alert | Listed in 1 DNSBL: bl.spamcop.net",
		"alert | Plain HTTP or TLS is altered on the path | Google: redirected (HTTP 302): captive portal or filter page\n",
		"warn | Connectivity check endpoints did not answer: 1 | Ubuntu: timeout",
		"warn | Address is classed as hosting (proxycheck.io)",
		"warn | VPN flagged by 1 of 1 sources: proxycheck.io",
		"warn | High risk score: proxycheck.io 80",
		"warn | Registration country US differs",
		"info | ChatGPT reports PL, the country of its CDN edge (Cloudflare WAW)",
		"info | Not available from here: Disney+",
		"warn | Refuse this address or network, not the country: ChatGPT app",
		"info | Spamhaus was not checked",
		"info | Outbound port 25 is closed",
		"info | No IPv6: the resolver returns no AAAA records",
		"warn | Encrypted DNS is blocked: Example 192.0.2.53 DoH",
		"warn | Blocked on the path (DPI): blocked.example |",
		"info | Refuse this country or network: geo.example",
		"warn | Telegram data centres unreachable: 1 of 2 | DC2",
		"warn | Traffic leaves through a tunnel",
		"warn | Detours: X",
		"warn | Unreachable: Quad9",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "Nothing unusual") || strings.Index(out, "alert") > strings.Index(out, "warn") {
		t.Errorf("order or summary wrong:\n%s", out)
	}
	for _, detail := range []string{"554 5.7.1 Client host blocked", "554", "", "connected to mx.example, closed without banner"} {
		h.Services[4].Detail = detail
		if refused := analysed(t, r, "en"); strings.Contains(refused, "port 25 is closed") || !strings.Contains(refused, "warn | Port 25 is open, but the mail server did not accept this address | "+detail) {
			t.Errorf("detail %q: an open port was reported as closed:\n%s", detail, refused)
		}
	}
	r.Censor = r.Censor[:1]
	if alone := analysed(t, r, "en"); strings.Contains(alone, "transparent forwarder") || !strings.Contains(alone, "| OpenDNS: I am not an OpenDNS resolver.\n") {
		t.Errorf("forwarder claimed without a clean spoofing check:\n%s", alone)
	}
	ru := analysed(t, r, "ru")
	if !strings.Contains(ru, "DNS на 53-м порту перехватывается по пути") || strings.Contains(ru, "%!") {
		t.Errorf("russian output:\n%s", ru)
	}
	for k, v := range analysisRU {
		if strings.Count(k, "%") != strings.Count(v, "%") {
			t.Errorf("translation of %q has different placeholders: %q", k, v)
		}
	}
	if clean := analysed(t, Demo("lookup"), "en"); !strings.HasPrefix(clean, "info | Nothing unusual found") {
		t.Errorf("clean report:\n%s", clean)
	}
}

func TestStats(t *testing.T) {
	mk := func(status probe.Status) *Report {
		r := New("online")
		h := &Host{Address: "203.0.113.7"}
		h.SetServices([]probe.Result{
			{Group: services.AI, Service: "Flaky API", Status: status},
			{Group: services.AI, Service: "Dead API", Status: probe.Failed},
			{Group: services.AI, Service: "Fine API", Status: probe.No},
		})
		r.IPv4 = h
		return r
	}
	dual := mk(probe.Yes)
	dual.IPv6 = &Host{Address: "2001:db8::7", Services: []probe.Result{{Group: services.AI, Service: "Fine API", Status: probe.Failed}}}
	if st := Stats([]*Report{dual}); !slices.ContainsFunc(st, func(s CheckStat) bool { return s.Service == "Fine API" && s.Failed == 1 }) {
		t.Errorf("a check failing only on IPv6 is hidden: %+v", st)
	}
	st := Stats([]*Report{mk(probe.Yes), mk(probe.Unknown), mk(probe.Yes)})
	if len(st) != 2 || st[0].Service != "Dead API" || st[0].Answered != 0 || st[0].Failed != 3 || st[1].Service != "Flaky API" || st[1].Answered != 2 || st[1].Unknown != 1 {
		t.Errorf("stats = %+v", st)
	}
	if empty := Stats([]*Report{New("bench")}); empty == nil || len(empty) != 0 {
		t.Errorf("stats without checks = %#v, want an empty non-nil slice", empty)
	}
	var b strings.Builder
	WriteStats(&b, false, "en", 3, st)
	if !strings.Contains(b.String(), "Dead API") || !strings.Contains(b.String(), "0/3") || !strings.Contains(b.String(), "2/3") {
		t.Errorf("stats output:\n%s", b.String())
	}
}

func TestCompare(t *testing.T) {
	a, b := Demo("online"), Demo("online")
	b.IPv4.Address = "198.51.100.9"
	b.IPv4.Services[0].Status = probe.No
	c, err := Compare([]*Report{a, b}, []string{"home", "vps"})
	if err != nil || len(c.Exits) != 2 || c.Exits[0].Query != "A" || c.Exits[1].Query != "B" || !strings.HasPrefix(c.Exits[1].Via, "vps · ") {
		t.Fatalf("Compare = %+v, %v", c, err)
	}
	if a.IPv4.Query != "" || a.IPv4.Via != "" {
		t.Error("Compare modified a source report")
	}
	screen := strings.Join(c.Screen(Style{Unicode: true, Width: 150}, "", nil), "\n")
	for _, want := range []string{"IP quality · A", "IP quality · B", "marks: A B", "✓✗ Netflix"} {
		if !strings.Contains(screen, want) {
			t.Errorf("%q missing in\n%s", want, screen)
		}
	}
	if _, err := Compare([]*Report{a, New("bench")}, []string{"a", "b"}); err == nil {
		t.Error("a report without an address must be rejected")
	}
}

func TestWritePrometheus(t *testing.T) {
	r := Demo("online")
	r.IPv4.Services[0].Service = "Net\"flix\\\n"
	r.Route = &route.Report{Method: "icmp", Paths: []route.Path{{Target: route.Target{Name: "Google"}, RTTms: 1.5, Verdict: route.Direct}}}
	var b strings.Builder
	if err := r.WritePrometheus(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	line := regexp.MustCompile(`^(# (HELP|TYPE) cii_[a-z_]+ .+|cii_[a-z_]+(\{[a-z_]+="(\\.|[^"\\])*"(,[a-z_]+="(\\.|[^"\\])*")*\})? -?[0-9.e+-]+)$`)
	types := map[string]int{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if !line.MatchString(l) {
			t.Errorf("not exposition format: %q", l)
		}
		if strings.HasPrefix(l, "# TYPE ") {
			types[strings.Fields(l)[2]]++
		}
	}
	for name, n := range types {
		if n != 1 {
			t.Errorf("metric family %s declared %d times", name, n)
		}
	}
	for _, want := range []string{
		`cii_address_info{point="IPv4",address="203.0.113.7",asn="3320",country="DE"} 1`,
		`cii_check_available{point="IPv4",group="Streaming",service="Net\"flix\\\n"} 1`,
		`cii_check_available{point="IPv4",group="AI",service="Kimi API (CN)"} 0`,
		`cii_check_answered{group="DNS",service="Cloudflare 1.1.1.1"} 1`,
		`cii_risk_score{point="IPv4",source="proxycheck.io"} 0`,
		`cii_route_rtt_ms{target="Google"} 1.5`,
		`cii_route_verdict{target="Google",verdict="direct"} 1`,
		`cii_bench_speed_mbps{direction="down"} 930`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %s\n%s", want, out)
		}
	}
	b.Reset()
	r.Scrubbed().WritePrometheus(&b)
	if strings.Contains(b.String(), "203.0.113") || strings.Contains(b.String(), "3320") {
		t.Errorf("masked metrics leak:\n%s", b.String())
	}
}

func TestAnalyzeResolverExit(t *testing.T) {
	r := Demo("online")
	r.Bench = nil
	exit := func(country, reason string) probe.Result {
		return probe.Result{Group: censor.DNS, Service: censor.EgressPrefix + " (Google)", Status: probe.Yes, Country: country,
			Reason: reason, Detail: "198.51.100.53 AS64500 Example DNS"}
	}
	if same := analysed(t, r, "en"); strings.Contains(same, "resolver") {
		t.Errorf("a resolver in the address country was reported:\n%s", same)
	}
	r.Censor = append(r.Censor, exit("NL", "the resolver that asks on your behalf; it passes the client subnet on (ECS)"))
	abroad := analysed(t, r, "en")
	for _, want := range []string{
		"info | DNS queries leave through a resolver in NL, while the address is in DE | Behind a VPN or proxy this is a DNS leak",
		"info | The resolver passes your subnet on to name servers (ECS)",
	} {
		if !strings.Contains(abroad, want) {
			t.Errorf("%q missing:\n%s", want, abroad)
		}
	}
	r.Censor = append(r.Censor, probe.Result{Group: censor.Local, Service: "Default route", Status: probe.Partial, Reason: "through tunnel wg0"})
	if tunnel := analysed(t, r, "ru"); !strings.Contains(tunnel, "warn | DNS-запросы уходят через резолвер в NL, а адрес находится в DE") {
		t.Errorf("a leak behind a tunnel should be a warning:\n%s", tunnel)
	}
	screen := strings.Join(r.Screen(Style{Unicode: true, Width: 220}, "", nil), "\n")
	for _, want := range []string{"DNS exit  DE 203.0.113.53 AS3320 Deutsche Telekom", "DNS exit  NL 198.51.100.53 AS64500 Example DNS"} {
		if !strings.Contains(screen, want) {
			t.Errorf("%q missing on screen:\n%s", want, screen)
		}
	}
	masked := strings.Join(r.Scrubbed().Screen(Style{Unicode: true, Width: 220}, "", nil), "\n")
	var js strings.Builder
	r.Scrubbed().WriteJSON(&js)
	for _, leak := range []string{"198.51.100", "203.0.113", "Example DNS", "64500", "Telekom"} {
		if strings.Contains(masked, leak) || strings.Contains(js.String(), leak) {
			t.Errorf("masked report leaks %q", leak)
		}
	}
	if !strings.Contains(masked, "DNS exit  DE •••") || !strings.Contains(masked, "DNS exit  NL •••") {
		t.Errorf("masked screen lost the resolver country:\n%s", masked)
	}
}

func TestResolverExitLines(t *testing.T) {
	exit := func(service, country, detail string) probe.Result {
		return probe.Result{Group: censor.DNS, Service: censor.EgressPrefix + service, Status: probe.Yes, Country: country, Detail: detail}
	}
	for name, c := range map[string]struct {
		rs   []probe.Result
		want []string
	}{
		"bare addresses": {[]probe.Result{exit(" (Akamai)", "", "203.0.113.53"), exit(" (Google)", "", "203.0.113.5")}, []string{"203.0.113.53", "203.0.113.5"}},
		"same resolver":  {[]probe.Result{exit(" (Akamai)", "DE", "203.0.113.53 AS64500 Example"), exit(" (Google)", "DE", "203.0.113.53 AS64500 Example")}, []string{"DE 203.0.113.53 AS64500 Example"}},
		"client subnet": {[]probe.Result{exit(" (Akamai)", "", "203.0.113.53"), exit(" (Google)", "", "203.0.113.53; client subnet 192.0.2.0/24")},
			[]string{"203.0.113.53"}},
		"not answered": {[]probe.Result{{Group: censor.DNS, Service: censor.EgressPrefix + " (Akamai)", Status: probe.Unknown, Detail: "198.18.0.7"}}, nil},
	} {
		if got := resolverExits(c.rs); !slices.Equal(got, c.want) {
			t.Errorf("%s = %q, want %q", name, got, c.want)
		}
	}
}
