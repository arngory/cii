package censor

import (
	"os"
	"path/filepath"
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

func TestParseTXT(t *testing.T) {
	got, rcode, err := parseTXT(txtReply(t, 7, dnsmessage.ClassINET, "I am ", "r3001.lon"), 7)
	if err != nil || rcode != dnsmessage.RCodeSuccess || len(got) != 1 || got[0] != "I am r3001.lon" {
		t.Fatalf("parseTXT = %q %v %v", got, rcode, err)
	}
	if _, _, err := parseTXT(txtReply(t, 7, dnsmessage.ClassINET), 8); err != errMismatch {
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
	for _, r := range localChecks(netx.IPv4) {
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
	for _, r := range localChecks(netx.IPv4) {
		if r.Service == "System resolver" && r.Status != probe.Yes {
			t.Errorf("plain resolver = %+v", r)
		}
	}
}
