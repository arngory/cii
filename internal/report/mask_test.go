package report

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/arngory/cii/internal/geodb"
	"github.com/arngory/cii/internal/ipdetect"
	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/risk"
	"github.com/arngory/cii/internal/route"
	"github.com/arngory/cii/internal/services"
)

func maskedSample() *Report {
	r := New("full")
	geo := []geodb.Record{{
		Source: "dbip-asn-lite", Network: netip.MustParsePrefix("203.0.113.0/24"),
		Country: "DE", CountryName: "Germany", City: "Berlin",
		ASN: 3320, ASOrg: "Deutsche Telekom AG Cable Content", ASDomain: "telekom.de",
	}}
	h := NewHost(ipdetect.Address{
		Address: netip.MustParseAddr("203.0.113.7"), Source: "echo:test",
		Interface: []netip.Addr{netip.MustParseAddr("203.0.113.7")},
	}, geo)
	h.SetServices([]probe.Result{
		{Group: risk.DNSBL, Service: risk.PTRService, Status: probe.Yes, Detail: "p203-0-113-7.dip0.t-ipconnect.de"},
		{Group: risk.DNSBL, Service: "zen.spamhaus.org", Status: probe.Unknown, Reason: "127.255.255.254 refused"},
		{Group: risk.Mail, Service: "Outbound SMTP (25)", Status: probe.No, Detail: "554 Client host [203.0.113.7] blocked"},
		{Group: risk.Network, Service: "PeeringDB", Status: probe.Yes, Detail: "AS3320 Cable/DSL/ISP Content"},
		{Group: risk.Reputation, Service: "ipapi.is", Status: probe.No, Detail: "VPN (ExampleVPN), proxy; datacenter Telekom Cloud; mobile"},
	})
	h.SetRegion(region.Summarize([]probe.Result{
		{Group: region.GeoIP, Service: "ipquery.io", Status: probe.OK, Country: "DE"},
		{Group: region.Registry, Service: "RIPEstat", Status: probe.OK, Country: "DE", Detail: "203.0.113.0/24 · AS3320 DTAG"},
	}))
	r.IPv4 = h
	r.IPv6 = NewHost(ipdetect.Address{Address: netip.MustParseAddr("2001:db8:1234::7"), Source: "echo:test"}, nil)
	r.SetCensor([]probe.Result{
		{Group: "dpi", Service: "instagram.com", Status: probe.IPBlock, Detail: "31.13.66.174"},
		{Group: "dns", Service: "Cloudflare 1.1.1.1", Status: probe.Yes},
		{Group: "dns", Service: "Cloudflare 1.0.0.1", Status: probe.Yes},
		{Group: "streaming", Service: "Netflix CDN", Status: probe.OK, IATA: "BER", Node: "c012-ber001-dtag-isp"},
	})
	r.Route = &route.Report{Method: "tcp", Note: "no hop data: listen ip4:icmp 203.0.113.7: bind: permission denied", OwnASN: 3320,
		Paths: []route.Path{{Target: route.Target{Name: "Google", Host: "www.google.com"}, Addr: "192.0.2.80", ASN: 15169, Org: "Google LLC",
			Hops: []route.Hop{{TTL: 1, Addr: "203.0.113.1", ASN: 3320, Org: "Deutsche Telekom AG"}}, Transit: []string{"AS1299 Arelion"}}}}
	r.Network = []ledger.Entry{
		{Module: "censor", Host: "1.1.1.1", Proto: "dns"},
		{Module: "region", Host: "www.telekom.de", Proto: "https", Purpose: "Telekom check"},
	}
	return r
}

func TestScrubbedLeaksNothing(t *testing.T) {
	orig := maskedSample()
	m := orig.Scrubbed()
	var js strings.Builder
	if err := m.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	var det strings.Builder
	m.WriteDetailed(&det, false)
	screen := strings.Join(m.Screen(Style{Unicode: true, Width: 200}, "", nil), "\n")
	for name, out := range map[string]string{"json": js.String(), "detailed": det.String(), "screen": screen} {
		for _, leak := range []string{"203.0.113", "203-0-113", "2001:db8", "3320", "Telekom", "telekom", "Deutsche", "DTAG", "dtag", "Arelion", "t-ipconnect", "ExampleVPN", "31.13.66", "127.255"} {
			if strings.Contains(strings.NewReplacer("www.telekom.de", "", "Telekom check", "").Replace(out), leak) {
				t.Errorf("%s leaks %q", name, leak)
			}
		}
		for _, keep := range []string{"DE", "Berlin", "Cable/DSL/ISP Content", "VPN", "datacenter"} {
			if !strings.Contains(out, keep) {
				t.Errorf("%s lost %q", name, keep)
			}
		}
	}
	if e := m.Network[1]; e.Host != "www.telekom.de" || e.Purpose != "Telekom check" || m.Network[0].Host != "1.1.1.1" {
		t.Errorf("ledger rewritten: %+v", m.Network)
	}
	if m.Censor[1].Service != "Cloudflare 1.1.1.1" || m.Censor[2].Service != "Cloudflare 1.0.0.1" || m.Censor[3].Node != "" || m.Censor[3].IATA != "BER" {
		t.Errorf("check names rewritten: %+v", m.Censor)
	}
	if !m.Masked || orig.Masked {
		t.Errorf("Masked flag: scrubbed %v, original %v", m.Masked, orig.Masked)
	}
	if orig.IPv4.Address != "203.0.113.7" || orig.IPv4.Geo[0].ASN != 3320 || !strings.Contains(orig.IPv4.Services[0].Detail, "t-ipconnect") {
		t.Errorf("Scrubbed modified the original report: %+v", orig.IPv4)
	}
}

func TestMaskTextLegacyPartialMasks(t *testing.T) {
	got := MaskText("from 203.0.*.* and 2001:db8:*:* at 12:30")
	if strings.Contains(got, "203.0") || strings.Contains(got, "2001:db8") || !strings.Contains(got, "12:30") {
		t.Errorf("legacy masks = %q", got)
	}
}

func TestMaskTextKeepsPlainText(t *testing.T) {
	in := "dial tcp4 203.0.113.5:0->198.51.100.7:443: connect: refused; [2001:db8::1]:443 ::ffff:192.0.2.9 v1.2 ok 12:30:00 AS-path"
	got := MaskText(in)
	for _, leak := range []string{"203.0.113.5", "198.51.100.7", "2001:db8", "192.0.2.9"} {
		if strings.Contains(got, leak) {
			t.Errorf("MaskText leaked %s: %s", leak, got)
		}
	}
	for _, keep := range []string{"connect: refused", "v1.2 ok", "12:30:00", "AS-path"} {
		if !strings.Contains(got, keep) {
			t.Errorf("MaskText lost %q: %s", keep, got)
		}
	}
}

func TestScrubbedRouteOnly(t *testing.T) {
	r := New("route")
	r.Route = &route.Report{Method: "icmp", Paths: []route.Path{{
		Target: route.Target{Name: "Google", Expect: 15169}, ASN: 15169, Org: "Google LLC", Verdict: route.Transit,
		Reason: "via AS1299 Arelion", Transit: []string{"AS1299 Arelion"},
		Hops: []route.Hop{{TTL: 2, Addr: "198.51.100.1", ASN: 64500, Org: "Example Access Networks"}, {TTL: 3, ASN: 1299, Org: "Arelion Sweden AB"}},
	}}}
	var js strings.Builder
	r.Scrubbed().WriteJSON(&js)
	if !strings.Contains(js.String(), `"reason": "via a transit network"`) {
		t.Errorf("masked transit reason should read as plain text:\n%s", js.String())
	}
	for _, leak := range []string{"Arelion", "Example Access", "198.51.100", "1299", "64500"} {
		if strings.Contains(js.String(), leak) {
			t.Errorf("route-only masked report leaks %q", leak)
		}
	}
	r.Route.Paths = append(r.Route.Paths,
		route.Path{Target: route.Target{Name: "office", Host: "office.example.net", Group: route.Custom}, Verdict: route.Transit,
			Reason:  "via AS1299 Arelion, AS3356 Lumen, AS6453 Tata Communications; served from AS64999, not AS64998",
			Transit: []string{"AS1299 Arelion", "AS3356 Lumen", "AS6453 Tata Communications"},
			Hops:    []route.Hop{{TTL: 4, ASN: 3356, Org: "Level 3 Parent, LLC"}}},
		route.Path{Target: route.Target{Name: "home", Host: "vps.example.org", Expect: 64512, Group: route.Custom}},
		route.Path{Target: route.Target{Name: "example.org", Host: "example.org", Group: route.Custom}},
		route.Path{Target: route.Target{Name: "192.0.2.77", Host: "192.0.2.77", Group: route.Custom}},
		route.Path{Target: route.Target{Name: "nx.example.org", Host: "nx.example.org", Group: route.Custom},
			Reason: "lookup nx.example.org on 192.0.2.53:53: no such host", Error: "lookup nx.example.org on 192.0.2.53:53: no such host"})
	r.IPv4 = &Host{Address: "203.0.113.7", Geo: []geodb.Record{{Source: "dbip-asn-lite", ASN: 64500, ASOrg: "Hostwerk Online GmbH"}}}
	r.Route.Paths = append(r.Route.Paths,
		route.Path{Target: route.Target{Name: "box.hostwerk.example", Host: "box.hostwerk.example", Group: route.Custom},
			Reason: "lookup box.hostwerk.example: no such host"},
		route.Path{Target: route.Target{Name: "10.0.0.1.nip.io", Host: "10.0.0.1.nip.io", Group: route.Custom},
			Error: "lookup 10.0.0.1.nip.io: no such host"})
	r.Network = []ledger.Entry{
		{Module: "route", Host: "vps.example.org", Proto: "icmp", Purpose: "route: path to home"},
		{Module: "route", Host: "nx.example.org", Proto: "dns", Purpose: "route: path to nx.example.org"},
		{Module: "route", Host: "example.org", Proto: "dns", Purpose: "route: path to example.org"},
		{Module: "route", Host: "www.google.com", Proto: "icmp"},
	}
	js.Reset()
	r.Scrubbed().WriteJSON(&js)
	for _, leak := range []string{"vps.example.org", "192.0.2.77", "nx.example.org", "192.0.2.53", "example.org", "64512", "nx.", "box.", ".example", "nip.io", "Lumen", "Tata", "Level 3", "64999", "64998", "office.example"} {
		if strings.Contains(js.String(), leak) {
			t.Errorf("own route target leaks %q", leak)
		}
	}
	for _, keep := range []string{`"name": "home"`, `"name": "target 4"`, "www.google.com", `"reason": "via a transit network; served from •••, not •••"`} {
		if !strings.Contains(js.String(), keep) {
			t.Errorf("masked route report lost %s", keep)
		}
	}
	if !strings.Contains(js.String(), `"name": "Google"`) {
		t.Errorf("target name lost:\n%s", js.String())
	}
}

func TestScrubbedOwnServiceChecks(t *testing.T) {
	r := New("full")
	h := &Host{Address: "203.0.113.7"}
	own := func(group probe.Group, name, host string, status probe.Status, reason string) probe.Result {
		return probe.Result{Group: group, Service: name, Custom: true, Host: host, Status: status, Reason: reason}
	}
	h.SetServices([]probe.Result{
		own(services.Custom, "wiki.example.org", "wiki.example.org", probe.Failed, "dial tcp: lookup wiki.example.org: no such host"),
		own("custom:Work", "Shop", "shop.example.org", probe.No, "HTTP 403"),
		own(services.Custom, "192.0.2.10", "192.0.2.10", probe.Failed, "no ipv4 connectivity"),
		own(services.Custom, "Odd", "wiki.example.org", probe.Failed, "unexpected reply from gateway-7 at site alpha"),
		own(services.Custom, "Bare", "wiki.example.org", probe.Failed, "x509: certificate is valid for localhost, router-backup, not wiki.example.org"),
		own(services.Custom, "shop.example.org mirror", "shop.example.org", probe.Yes, ""),
		own(services.Custom, "Portal", "portal.example.net", probe.Failed, "lookup Portal.Example.NET: no such host"),
		own(services.Custom, "intra.corp.example", "198.51.100.5", probe.Yes, ""),
		own(services.Custom, "xn--b1aajm.example", "xn--b1aajm.example", probe.Failed, "lookup xn--b1aajm.example: no such host"),
		own(services.Custom, "Films", "www.netflix.com", probe.Yes, ""),
		own(services.Custom, "Cert", "wiki.example.org", probe.Failed, "tls: failed to verify certificate: x509: certificate is valid for *.Corp.Example, corp.example, not wiki.example.org"),
		own("custom:files.corp.example", "Files", "files.corp.example", probe.Yes, ""),
		own("custom:Shop.Example.org mirrors", "Mirror", "shop.example.org", probe.Yes, ""),
		{Group: services.Streaming, Service: "Netflix", Status: probe.Yes},
		{Group: services.Streaming, Service: "Prime Video", Status: probe.Yes},
	})
	r.IPv4 = h
	v6 := &Host{Address: "2001:db8::7"}
	v6.SetServices([]probe.Result{own(services.Custom, "wiki.example.org", "wiki.example.org", probe.Yes, "")})
	r.IPv6 = v6
	r.Network = []ledger.Entry{
		{Module: "services", Host: "wiki.example.org", Proto: "https", Purpose: "services: wiki.example.org"},
		{Module: "services", Host: "shop.example.org", Proto: "https", Purpose: "services: Shop; services: shop.example.org mirror"},
		{Module: "services", Host: "www.netflix.com", Proto: "https", Purpose: "services: Netflix; services: Films"},
		{Module: "services", Host: "www.primevideo.com", Proto: "https", Purpose: "services: Prime Video"},
		{Module: "services", Host: "portal.example.net", Proto: "https", Purpose: "services: Portal"},
		{Module: "services", Host: "198.51.100.5", Proto: "https", Purpose: "services: intra.corp.example"},
		{Module: "services", Host: "xn--b1aajm.example", Proto: "dns", Purpose: "services: xn--b1aajm.example"},
		{Module: "region", Host: "wiki.example.org", Proto: "https", Purpose: "region: other"},
	}
	m := r.Scrubbed()
	var js strings.Builder
	if err := m.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	out := strings.ReplaceAll(js.String(), `"host": "wiki.example.org"`, "")
	for _, leak := range []string{"wiki.example", "shop.example", "192.0.2.10", "portal.example", "corp.example", "198.51.100", "xn--", "netflix.com", "localhost", "router", "gateway", "alpha"} {
		if strings.Contains(strings.ToLower(out), leak) {
			t.Errorf("own service check leaks %q:\n%s", leak, out)
		}
	}
	for _, keep := range []string{`"service": "check 1"`, `"service": "check 2"`, `"service": "check 3"`, `"service": "check 4"`, `"service": "check 5"`,
		`"service": "Shop"`, `"service": "Films"`, `"service": "Files"`, `"service": "Mirror"`, `"group": "custom:Work"`, `"service": "Netflix"`, `"reason": "HTTP 403"`, `"reason": "certificate"`, `"reason": "no such host"`, `"reason": "no ipv4 connectivity"`, `"reason": "request failed"`,
		"www.primevideo.com", `"purpose": "services: Shop; services: check 3"`, `"purpose": "services: check 4"`, `"purpose": "region: other"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("masked report lost %s:\n%s", keep, out)
		}
	}
	if m.IPv6.Services[0].Service != m.IPv4.Services[0].Service || m.IPv6.Services[0].Host != Hidden {
		t.Errorf("one check got two names or kept its host: %+v and %+v", m.IPv4.Services[0], m.IPv6.Services[0])
	}
	if r.IPv4.Services[0].Service != "wiki.example.org" || r.IPv4.Services[0].Host != "wiki.example.org" || r.Network[0].Host != "wiki.example.org" {
		t.Errorf("Scrubbed modified the original report")
	}
}
