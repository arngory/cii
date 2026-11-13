package route

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

func TestSeqRoundTrip(t *testing.T) {
	for _, c := range [][3]int{{1, 0, 1}, {3, 18, 24}, {15, 63, 31}} {
		if r, ti, ttl := unseq(seqOf(c[0], c[1], c[2])); r != c[0] || ti != c[1] || ttl != c[2] {
			t.Errorf("unseq(seqOf(%v)) = %d %d %d", c, r, ti, ttl)
		}
		if seqOf(c[0], c[1], c[2]) > 0xffff {
			t.Errorf("seq overflows 16 bits: %v", c)
		}
	}
}

func TestInner(t *testing.T) {
	ip := make([]byte, 20)
	ip[0], ip[9] = 0x45, 1
	echo := []byte{8, 0, 0, 0, 0x12, 0x34, 0x08, 0x05}
	if id, seq, ok := inner(append(ip, echo...), false); !ok || id != 0x1234 || seq != 0x0805 {
		t.Errorf("inner = %x %x %v", id, seq, ok)
	}
	if _, _, ok := inner(ip, false); ok {
		t.Error("short packet accepted")
	}
	ip6 := make([]byte, 40)
	ip6[0], ip6[6] = 0x60, 58
	echo6 := []byte{128, 0, 0, 0, 0x12, 0x34, 0x08, 0x05}
	if id, seq, ok := inner(append(ip6, echo6...), true); !ok || id != 0x1234 || seq != 0x0805 {
		t.Errorf("inner v6 = %x %x %v", id, seq, ok)
	}
	if _, _, ok := inner(append(ip6, echo...), true); ok {
		t.Error("an ICMPv4 echo inside IPv6 accepted")
	}
	udp := append([]byte(nil), ip...)
	udp[9] = 17
	if _, _, ok := inner(append(udp, echo...), false); ok {
		t.Error("non-ICMP inner packet accepted")
	}
}

func path(name string, expect uint, rtt float64, asn uint, hops ...Hop) *Path {
	return &Path{Target: Target{Name: name, Expect: expect}, RTTms: rtt, ASN: asn, Org: "Org", Hops: hops}
}

func TestJudge(t *testing.T) {
	cases := []struct {
		p      *Path
		want   string
		reason string
	}{
		{path("a", 15169, 4, 15169), Direct, ""},
		{path("b", 15169, 20, 15169), Near, ""},
		{path("c", 15169, 50, 15169), Regional, "+46 ms"},
		{path("d", 15169, 120, 15169), Detour, "+116 ms"},
		{path("e", 15169, 30, 15169, Hop{TTL: 1, Addr: "192.0.2.1", RTTms: 1, ASN: 64500}, Hop{TTL: 2, Addr: "198.51.100.1", RTTms: 5, ASN: 1299}, Hop{TTL: 3, Addr: "203.0.113.1", RTTms: 30, ASN: 15169}), Transit, "via AS1299 Arelion"},
		{path("f", 15169, 60, 15169, Hop{TTL: 1, Addr: "192.0.2.1", RTTms: 1}, Hop{TTL: 2, Addr: "198.51.100.1", RTTms: 55}), Detour, "one hop adds 54 ms"},
		{path("f2", 15169, 5, 15169, Hop{TTL: 1, Addr: "192.0.2.1", RTTms: 1}, Hop{TTL: 2, Addr: "198.51.100.1", RTTms: 95}, Hop{TTL: 3, Addr: "198.51.100.2", RTTms: 4}), Direct, ""},
		{&Path{Target: Target{Name: "u", Expect: 62041, Unicast: true}, RTTms: 180, ASN: 62041, Hops: []Hop{{TTL: 1, Addr: "192.0.2.1", RTTms: 1}, {TTL: 2, Addr: "198.51.100.1", RTTms: 150}}}, Distant, "single-location service, +176 ms away"},
		{&Path{Target: Target{Name: "u2", Expect: 62041, Unicast: true}, RTTms: 8, ASN: 62041}, Direct, ""},
		{path("tail", 15169, 50, 15169, Hop{TTL: 1, Addr: "192.0.2.1", RTTms: 1}, Hop{TTL: 2, Addr: "198.51.100.1", RTTms: 3}), Regional, "+46 ms"},
		{path("g", 13335, 0.4, 13335, Hop{TTL: 1}, Hop{TTL: 2, Addr: "1.1.1.1", RTTms: 0.4}), Intercepted, "local proxy"},
		{path("h", 15169, 4, 64500), Direct, "cache inside your network"},
		{path("i", 15169, 4, 20940), Direct, "served from AS20940, not AS15169"},
		{&Path{Target: Target{Name: "j"}, Error: "timeout"}, Unreachable, "timeout"},
	}
	for _, c := range cases {
		judge(c.p, 4, 64500)
		if c.p.Verdict != c.want || !strings.Contains(c.p.Reason, c.reason) {
			t.Errorf("%s: %s %q, want %s %q", c.p.Target.Name, c.p.Verdict, c.p.Reason, c.want, c.reason)
		}
	}
}

func TestFloorAndOwnASN(t *testing.T) {
	ps := []*Path{path("a", 0, 30, 0), path("b", 0, 3, 0), path("c", 0, 10, 0), path("d", 0, 12, 0)}
	if f := floor(ps); f != 10 {
		t.Errorf("floor with an outlier = %v, want the second fastest", f)
	}
	if f := floor(ps[:2]); f != 3 {
		t.Errorf("floor = %v", f)
	}
	hops := []*Path{
		path("a", 0, 1, 0, Hop{TTL: 1}, Hop{TTL: 2, ASN: 64500}, Hop{TTL: 3, ASN: 1299}),
		path("b", 0, 1, 0, Hop{TTL: 2, ASN: 64500}),
		path("c", 0, 1, 0, Hop{TTL: 1, ASN: 64501}),
	}
	if a := firstHopASN(hops); a != 64500 {
		t.Errorf("own ASN = %d", a)
	}
}

func TestResults(t *testing.T) {
	r := &Report{Paths: []Path{
		{Target: Target{Name: "Google", Group: Search}, RTTms: 4.25, Verdict: Direct},
		{Target: Target{Name: "X", Group: Social}, RTTms: 90, Verdict: Detour, Reason: "+86 ms over the fastest path"},
		{Target: Target{Name: "Quad9", Group: Resolver}, Verdict: Unreachable, Reason: "timeout"},
	}}
	rs := r.Results()
	if rs[0].Status != probe.Yes || rs[0].Detail != "4.2 ms direct" && rs[0].Detail != "4.3 ms direct" {
		t.Errorf("direct = %+v", rs[0])
	}
	if rs[1].Status != probe.No || rs[1].Detail != "90.0 ms detour: +86 ms over the fastest path" {
		t.Errorf("detour = %+v", rs[1])
	}
	if rs[2].Status != probe.Failed || rs[2].Reason != "timeout" || rs[2].Group != Resolver {
		t.Errorf("unreachable = %+v", rs[2])
	}
}

func TestAnsweredLocally(t *testing.T) {
	var ps []*Path
	for i, asn := range []uint{15169, 32934, 13335, 36459, 62041, 19281} {
		ps = append(ps, path(string(rune('a'+i)), asn, 0.8, asn))
	}
	if !answeredLocally(ps) {
		t.Error("six networks under 2 ms not flagged")
	}
	ps[3].RTTms = 80
	if answeredLocally(ps) {
		t.Error("a real 80 ms path still flagged")
	}
	if answeredLocally(ps[:3]) {
		t.Error("three fast targets are not enough evidence")
	}
}

func TestResolveLiteralFamily(t *testing.T) {
	n6 := netx.New(netx.Options{Family: netx.IPv6}, netx.NewPolicy(Rules(Targets)...), ledger.New())
	p := &Path{Target: Target{Name: "Quad9", Host: "9.9.9.9"}}
	resolve(context.Background(), n6, p)
	if p.addr.IsValid() || p.Error != "no ipv6 address" {
		t.Errorf("IPv4 literal on IPv6 = %v %q", p.addr, p.Error)
	}
	p = &Path{Target: Target{Name: "Quad9", Host: "9.9.9.9", Host6: "2620:fe::fe"}}
	resolve(context.Background(), n6, p)
	if p.addr.String() != "2620:fe::fe" || p.host != "2620:fe::fe" || p.Error != "" {
		t.Errorf("IPv6 literal for an IPv4 target = %v %q %q", p.addr, p.host, p.Error)
	}
	n4 := netx.New(netx.Options{Family: netx.IPv4}, netx.NewPolicy(Rules(Targets)...), ledger.New())
	p = &Path{Target: Target{Name: "Quad9", Host: "9.9.9.9"}}
	resolve(context.Background(), n4, p)
	if p.addr.String() != "9.9.9.9" || p.Error != "" {
		t.Errorf("IPv4 literal on IPv4 = %v %q", p.addr, p.Error)
	}
}

func TestAttributed(t *testing.T) {
	reached := &Path{addr: netip.MustParseAddr("8.8.8.8")}
	if attributed([]*Path{reached}) {
		t.Error("a reached path without any ASN counts as attributed")
	}
	if !attributed([]*Path{reached, {Hops: []Hop{{TTL: 2, ASN: 64500}}}}) {
		t.Error("a hop ASN does not count")
	}
	if !attributed([]*Path{{Target: Target{Name: "x"}}}) {
		t.Error("nothing resolved should not claim missing ASN data")
	}
	if !attributed([]*Path{{addr: netip.MustParseAddr("198.18.0.7")}}) {
		t.Error("fake-IP answers should not claim missing ASN data")
	}
}

func TestRealHopsAreNotLocal(t *testing.T) {
	var ps []*Path
	for i, asn := range []uint{15169, 32934, 13335, 36459, 62041, 19281} {
		p := path(string(rune('a'+i)), asn, 0.9, asn, Hop{TTL: 1, Addr: "192.0.2.1", RTTms: 0.4}, Hop{TTL: 2, Addr: "192.0.2.2", RTTms: 0.5}, Hop{TTL: 3, Addr: "192.0.2.3", RTTms: 0.8})
		p.Timing = "icmp"
		ps = append(ps, p)
	}
	if answeredLocally(ps) {
		t.Error("a well-peered datacentre with real hops was flagged as answered locally")
	}
}

func TestParseTargets(t *testing.T) {
	ts, add, err := ParseTargets("+home=VPS.Example.org@AS64500, 192.0.2.9 ,b.example.net@64501")
	if err != nil || !add || len(ts) != 3 {
		t.Fatalf("ParseTargets = %+v %v %v", ts, add, err)
	}
	if ts[0] != (Target{Name: "home", Host: "vps.example.org", Expect: 64500, Group: Custom, Unicast: true}) || ts[1].Name != "192.0.2.9" || ts[2].Expect != 64501 {
		t.Errorf("targets = %+v", ts)
	}
	if _, add, _ := ParseTargets("a.example.org"); add {
		t.Error("no + means replace")
	}
	for _, bad := range []string{"", "+", "http://a.example", "a.example/path", "*.example.org", "name=", "a.example@x", "a.example@0", "single"} {
		if got, _, err := ParseTargets(bad); err == nil {
			t.Errorf("ParseTargets(%q) = %+v, want error", bad, got)
		}
	}
	merged, err := Merge(Targets, append(ts, Target{Name: "dup", Host: "www.google.com"}))
	if err != nil || len(merged) != len(Targets)+3 {
		t.Errorf("Merge = %d, %v", len(merged), err)
	}
	many := make([]Target, MaxTargets)
	for i := range many {
		many[i].Host = "h" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example"
	}
	if _, err := Merge(Targets, many); err == nil {
		t.Error("exceeding the target limit must fail")
	}
}
