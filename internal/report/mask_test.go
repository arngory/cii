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
)

func maskedSample() *Report {
	r := New("full")
	geo := []geodb.Record{{
		Source: "dbip-asn-lite", Network: netip.MustParsePrefix("203.0.113.0/24"),
		Country: "DE", CountryName: "Germany", City: "Berlin",
		ASN: 3320, ASOrg: "Deutsche Telekom AG", ASDomain: "telekom.de",
	}}
	h := NewHost(ipdetect.Address{
		Address: netip.MustParseAddr("203.0.113.7"), Source: "echo:test",
		Interface: []netip.Addr{netip.MustParseAddr("203.0.113.7")},
	}, geo)
	h.SetServices([]probe.Result{
		{Group: risk.DNSBL, Service: risk.PTRService, Status: probe.Yes, Detail: "p203-0-113-7.dip0.t-ipconnect.de"},
		{Group: risk.DNSBL, Service: "zen.spamhaus.org", Status: probe.Unknown, Reason: "127.255.255.254 refused"},
		{Group: risk.Mail, Service: "Outbound SMTP (25)", Status: probe.No, Detail: "554 Client host [203.0.113.7] blocked"},
		{Group: risk.Network, Service: "PeeringDB", Status: probe.Yes, Detail: "AS3320 Cable/DSL/ISP"},
		{Group: risk.Reputation, Service: "ipapi.is", Status: probe.No, Detail: "VPN (ExampleVPN), proxy; datacenter Telekom Cloud; mobile"},
	})
	h.SetRegion(region.Summarize([]probe.Result{
		{Group: region.GeoIP, Service: "ipquery.io", Status: probe.OK, Country: "DE"},
		{Group: region.Registry, Service: "RIPEstat", Status: probe.OK, Country: "DE", Detail: "203.0.113.0/24 · AS3320 DTAG"},
	}))
	r.IPv4 = h
	r.IPv6 = NewHost(ipdetect.Address{Address: netip.MustParseAddr("2001:db8:1234::7"), Source: "echo:test"}, nil)
	r.SetCensor([]probe.Result{{Group: "dpi", Service: "instagram.com", Status: probe.IPBlock, Detail: "31.13.66.174"}})
	r.Network = []ledger.Entry{{Module: "risk", Host: "7.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.3.2.1.8.b.d.0.1.0.0.2.ip6.arpa", Proto: "dns"}}
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
		for _, leak := range []string{"203.0.113", "203-0-113", "2001:db8", "1.2.3.4.8.b.d", "3320", "Telekom", "telekom", "Deutsche", "DTAG", "t-ipconnect", "ExampleVPN", "31.13.66", "127.255"} {
			if strings.Contains(out, leak) {
				t.Errorf("%s leaks %q", name, leak)
			}
		}
		for _, keep := range []string{"DE", "Berlin", "Cable/DSL/ISP", "VPN", "datacenter"} {
			if !strings.Contains(out, keep) {
				t.Errorf("%s lost %q", name, keep)
			}
		}
	}
	if !m.Masked || orig.Masked {
		t.Errorf("Masked flag: scrubbed %v, original %v", m.Masked, orig.Masked)
	}
	if orig.IPv4.Address != "203.0.113.7" || orig.IPv4.Geo[0].ASN != 3320 || !strings.Contains(orig.IPv4.Services[0].Detail, "t-ipconnect") {
		t.Errorf("Scrubbed modified the original report: %+v", orig.IPv4)
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
