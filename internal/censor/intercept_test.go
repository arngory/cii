package censor

import (
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

func txtReply(t *testing.T, id uint16, class dnsmessage.Class, txt ...string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true})
	b.EnableCompression()
	name := dnsmessage.MustNewName("which.opendns.com.")
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeTXT, Class: class})
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if len(txt) > 0 {
		if err := b.TXTResource(dnsmessage.ResourceHeader{Name: name, Class: class, TTL: 0}, dnsmessage.TXTResource{TXT: txt}); err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestParseAnswerTXT(t *testing.T) {
	got, err := parseAnswer(txtReply(t, 7, dnsmessage.ClassINET, "I am ", "r3001.lon"), 7, dnsmessage.TypeTXT)
	if err != nil || got.RCode != dnsmessage.RCodeSuccess || len(got.TXT) != 1 || got.TXT[0] != "I am r3001.lon" || len(got.IPs) != 0 {
		t.Fatalf("parseAnswer TXT = %+v %v", got, err)
	}
	if _, err := parseAnswer(txtReply(t, 7, dnsmessage.ClassINET), 8, dnsmessage.TypeTXT); err != errMismatch {
		t.Errorf("wrong id: %v", err)
	}
}

func TestInterceptionVerdicts(t *testing.T) {
	cases := []struct {
		res  probe.Result
		want probe.Status
	}{
		{openDNSResult([]string{"r3001.lon"}, 0, nil), probe.Yes},
		{openDNSResult([]string{"I am not an OpenDNS resolver."}, 0, nil), probe.No},
		{openDNSResult(nil, dnsmessage.RCodeRefused, nil), probe.Unknown},
		{openDNSResult(nil, 0, netx.ErrProxyRaw), probe.Unknown},
		{googleChaosResult(nil, dnsmessage.RCodeNotImplemented, nil), probe.Yes},
		{googleChaosResult([]string{"dnsmasq-2.90"}, 0, nil), probe.No},
	}
	for i, c := range cases {
		if c.res.Status != c.want {
			t.Errorf("case %d: %+v, want %s", i, c.res, c.want)
		}
	}
}

func TestLocalResolverCheck(t *testing.T) {
	dir := t.TempDir()
	saved := resolvConf
	defer func() { resolvConf = saved }()
	resolvConf = filepath.Join(dir, "resolv.conf")
	os.WriteFile(resolvConf, []byte("# managed\nnameserver 198.18.0.2\nsearch lan\n"), 0o644)
	var got probe.Result
	for _, r := range localChecks(netx.New(netx.Options{Family: netx.IPv4}, netx.NewPolicy(), nil)) {
		if r.Service == "System resolver" {
			got = r
		}
	}
	if got.Status != probe.Partial || got.Detail != "198.18.0.2" {
		t.Errorf("fake-ip resolver = %+v", got)
	}
	os.WriteFile(resolvConf, []byte("nameserver 192.0.2.53\nnameserver fe80::1%eth0\n"), 0o644)
	if ns := netx.SystemNameservers(resolvConf); len(ns) != 2 || ns[1].String() != "fe80::1" {
		t.Errorf("nameservers = %v", ns)
	}
	for _, r := range localChecks(netx.New(netx.Options{Family: netx.IPv4}, netx.NewPolicy(), nil)) {
		if r.Service == "System resolver" && r.Status != probe.Yes {
			t.Errorf("plain resolver = %+v", r)
		}
	}
}

func TestLocalRouteBehindProxy(t *testing.T) {
	proxy, _ := url.Parse("http://127.0.0.1:1")
	n := netx.New(netx.Options{Family: netx.IPv4, Proxy: proxy}, netx.NewPolicy(), nil)
	if r := localChecks(n)[0]; r.Status != probe.Unknown || !strings.Contains(r.Reason, "proxy") {
		t.Errorf("route behind proxy = %+v", r)
	}
}

func TestLocalChecksAddTheOtherStack(t *testing.T) {
	noProxyEnv(t)
	n := netx.New(netx.Options{Family: netx.IPv4}, netx.NewPolicy(), nil)
	rows := localChecks(n, netx.IPv4, netx.IPv6)
	var names []string
	for _, r := range rows {
		names = append(names, r.Service)
	}
	if !slices.Contains(names, "Default route") || !slices.Contains(names, "Default route (IPv6)") || slices.Contains(names, "Default route (IPv4)") {
		t.Errorf("rows = %v", names)
	}
	for _, r := range rows {
		if r.Service == "Default route (IPv6)" && (r.Group != Local || r.Status == "" || r.Reason == "") {
			t.Errorf("IPv6 route row = %+v", r)
		}
	}
	if only := localChecks(n, netx.IPv4); slices.ContainsFunc(only, func(r probe.Result) bool { return strings.HasPrefix(r.Service, "Default route (") }) {
		t.Errorf("a second route row without a second stack: %+v", only)
	}
	bound := netx.New(netx.Options{Family: netx.IPv4, Source: netip.MustParseAddr("192.0.2.10")}, netx.NewPolicy(), nil)
	if rows := localChecks(bound, netx.IPv4, netx.IPv6); slices.ContainsFunc(rows, func(r probe.Result) bool { return r.Service == "Default route (IPv6)" }) {
		t.Error("a bound source address still got a route row for the other family")
	}
	if r := otherRoute(netx.IPv6); r.Service != "Default route (IPv6)" || (r.Status == probe.No) != strings.HasPrefix(r.Reason, "no default route") {
		t.Errorf("otherRoute = %+v", r)
	}
}
