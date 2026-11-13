package censor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

func TestEgressResult(t *testing.T) {
	locate := func(ip netip.Addr) (string, string) {
		if ip == netip.MustParseAddr("203.0.113.53") {
			return "DE", "AS64500 Example Net"
		}
		return "", ""
	}
	for name, c := range map[string]struct {
		raw    []string
		err    error
		status probe.Status
		cc     string
		reason string
		detail string
	}{
		"address": {raw: []string{"203.0.113.53"}, status: probe.Yes, cc: "DE",
			reason: "the resolver that asks on your behalf", detail: "203.0.113.53 AS64500 Example Net"},
		"two addresses": {raw: []string{"198.51.100.9", "203.0.113.53", "198.51.100.9", "::ffff:198.51.100.9"}, status: probe.Yes, cc: "DE",
			reason: "the resolver that asks on your behalf", detail: "198.51.100.9, 203.0.113.53 AS64500 Example Net"},
		"client subnet": {raw: []string{"2001:db8::53", "edns0-client-subnet 192.0.2.0/24"}, status: probe.Yes,
			reason: "the resolver that asks on your behalf; it passes the client subnet on (ECS)", detail: "2001:db8::53; client subnet 192.0.2.0/24"},
		"fake-ip":   {raw: []string{"198.18.0.7"}, status: probe.Unknown, reason: "answered locally by a fake-IP resolver", detail: "198.18.0.7"},
		"text only": {raw: []string{"hello"}, status: probe.Unknown, reason: "no address in the answer"},
		"empty":     {status: probe.Unknown, reason: "no address in the answer"},
		"not found": {err: &net.DNSError{Err: "no such host", Name: akamaiWhoami, IsNotFound: true}, status: probe.Unknown,
			reason: "no such name: the resolver does not pass the query on"},
		"timeout": {err: context.DeadlineExceeded, status: probe.Unknown, reason: "timeout"},
		"other":   {err: errors.New("server misbehaving"), status: probe.Unknown, reason: "server misbehaving"},
	} {
		got := egressResult("Resolver exit (test)", c.raw, c.err, locate)
		if got.Status != c.status || got.Country != c.cc || got.Reason != c.reason || got.Detail != c.detail || got.Group != DNS {
			t.Errorf("%s = %+v", name, got)
		}
	}
	if got := egressResult("x", []string{"203.0.113.53"}, nil, nil); got.Status != probe.Yes || got.Detail != "203.0.113.53" || got.Country != "" {
		t.Errorf("without a locator = %+v", got)
	}
}

func TestEgressNeedsDeclaredNames(t *testing.T) {
	rules := Rules(Options{Modes: []string{"dns"}})
	for _, name := range []string{akamaiWhoami, googleWhoami} {
		found := false
		for _, r := range rules {
			found = found || r.Pattern == name
		}
		if !found {
			t.Errorf("%s is not declared in the dns mode rules", name)
		}
	}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(k, "")
	}
	r := newRunner(netx.New(netx.Options{}, netx.NewPolicy(), ledger.New()), Options{})
	for _, res := range r.egress(context.Background()) {
		if res.Status != probe.Failed || res.Reason == "" {
			t.Errorf("undeclared lookup = %+v", res)
		}
	}
	proxy, _ := url.Parse("http://127.0.0.1:1")
	r = newRunner(netx.New(netx.Options{Proxy: proxy}, netx.NewPolicy(Rules(Options{Modes: []string{"dns"}})...), ledger.New()), Options{})
	for _, res := range r.egress(context.Background()) {
		if res.Status != probe.Unknown || !strings.Contains(res.Reason, "proxy") {
			t.Errorf("behind a proxy = %+v", res)
		}
	}
}
