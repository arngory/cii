package netx

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/arngory/cii/internal/ledger"
)

func TestDialPolicyLedgerAndProxy(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()

	led := ledger.New()
	n := New(Options{Family: IPv4}, NewPolicy(Rule{Module: "m", Pattern: "127.0.0.1", Purpose: "p"}), led)
	c, err := n.Dial(context.Background(), "m", "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("declared dial: %v", err)
	}
	c.Close()

	var be *BlockedError
	if _, err := n.Dial(context.Background(), "other", "tcp", ln.Addr().String()); !errors.As(err, &be) {
		t.Fatalf("undeclared module dial: %v", err)
	}
	if _, err := n.Dial(context.Background(), "m", "icmp", "127.0.0.1:1"); err == nil {
		t.Fatal("unsupported network accepted")
	}
	if _, err := n.LookupHost(context.Background(), "m", "undeclared.invalid"); !errors.As(err, &be) {
		t.Fatalf("undeclared lookup: %v", err)
	}

	proxied := New(Options{Proxy: mustURL(t, "socks5://127.0.0.1:1")}, NewPolicy(Rule{Module: "m", Pattern: "*.example"}), led)
	if _, err := proxied.Dial(context.Background(), "m", "udp", "a.example:53"); !errors.Is(err, ErrProxyRaw) {
		t.Fatalf("raw dial with proxy: %v", err)
	}
	if _, err := proxied.LookupHost(context.Background(), "m", "a.example"); !errors.Is(err, ErrProxyRaw) {
		t.Fatalf("lookup with proxy: %v", err)
	}

	byKey := map[string]ledger.Entry{}
	for _, e := range led.Entries() {
		byKey[e.Module+" "+e.Host+" "+e.Proto] = e
	}
	if byKey["m 127.0.0.1 tcp"].Requests != 1 || byKey["other 127.0.0.1 tcp"].Blocked != 1 ||
		byKey["m *.example udp"].Skipped != 1 || byKey["m *.example dns"].Skipped != 1 ||
		byKey["m *.example udp"].Blocked != 0 {
		t.Fatalf("ledger = %+v", led.Entries())
	}
}

func TestWildcardLookupKeepsQueryNameOutOfLedger(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "")
	}
	led := ledger.New()
	n := New(Options{}, NewPolicy(Rule{Module: "m", Pattern: "*.zone.invalid", Purpose: "p"}, Rule{Module: "m", Pattern: "exact.invalid", Purpose: "p"}), led)
	for _, name := range []string{"4.3.2.81.zone.invalid", "Exact.Invalid."} {
		if _, err := n.allow("m", name, "dns"); err != nil {
			t.Fatalf("allow(%s): %v", name, err)
		}
	}
	hosts := map[string]int{}
	for _, e := range led.Entries() {
		hosts[e.Host] += e.Requests
	}
	if len(hosts) != 2 || hosts["*.zone.invalid"] != 1 || hosts["exact.invalid"] != 1 {
		t.Fatalf("ledger = %+v", led.Entries())
	}
}

func TestEnvProxyDisablesRaw(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "")
	}
	clean := New(Options{}, NewPolicy(Rule{Module: "m", Pattern: "a.example"}), ledger.New())
	if clean.Proxied() {
		t.Fatal("no proxy configured, yet Proxied() is true")
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	n := New(Options{}, NewPolicy(Rule{Module: "m", Pattern: "a.example"}), ledger.New())
	if !n.Proxied() {
		t.Fatal("HTTPS_PROXY not detected")
	}
	if _, err := n.Dial(context.Background(), "m", "tcp", "a.example:25"); !errors.Is(err, ErrProxyRaw) {
		t.Fatalf("raw dial with env proxy: %v", err)
	}
	if _, err := n.LookupHost(context.Background(), "m", "a.example"); !errors.Is(err, ErrProxyRaw) {
		t.Fatalf("lookup with env proxy: %v", err)
	}
}

func TestAllProxyRoutesHTTP(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
	hits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte(r.Host))
	}))
	defer proxy.Close()
	t.Setenv("ALL_PROXY", proxy.URL)
	n := New(Options{}, NewPolicy(Rule{Module: "m", Pattern: "target.invalid"}), ledger.New())
	if !n.Proxied() {
		t.Fatal("ALL_PROXY not detected")
	}
	resp, err := n.HTTPClient("m").Get("http://target.invalid/")
	if err != nil {
		t.Fatalf("request via ALL_PROXY: %v", err)
	}
	resp.Body.Close()
	if hits != 1 {
		t.Fatalf("proxy hits = %d", hits)
	}
}

func TestDialAddrChecksHostDialsAddress(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	led := ledger.New()
	n := New(Options{}, NewPolicy(Rule{Module: "route", Pattern: "localhost", Purpose: "path"}, Rule{Module: "route", Pattern: "127.0.0.1", Purpose: "lit"}), led)
	if _, err := n.DialAddr(context.Background(), "route", "tcp", "localhost", netip.MustParseAddr("127.0.0.1"), port); !errors.Is(err, ErrAddrNotOfHost) {
		t.Fatalf("dial before the host was resolved: %v", err)
	}
	if _, err := n.LookupHost(context.Background(), "route", "localhost"); err != nil {
		t.Skipf("no localhost resolution here: %v", err)
	}
	c, err := n.DialAddr(context.Background(), "route", "tcp", "localhost", netip.MustParseAddr("127.0.0.1"), port)
	if err != nil {
		t.Fatalf("DialAddr: %v", err)
	}
	c.Close()
	if _, err := n.DialAddr(context.Background(), "route", "tcp", "localhost", netip.MustParseAddr("192.0.2.1"), port); !errors.Is(err, ErrAddrNotOfHost) {
		t.Errorf("address outside the resolved set dialled: %v", err)
	}
	if _, err := n.DialAddr(context.Background(), "route", "tcp", "127.0.0.1", netip.MustParseAddr("192.0.2.1"), port); !errors.Is(err, ErrAddrNotOfHost) {
		t.Errorf("literal host with another address dialled: %v", err)
	}
	if _, err := n.DialAddr(context.Background(), "route", "tcp", "other.example", netip.MustParseAddr("127.0.0.1"), port); AsBlocked(err) == nil {
		t.Errorf("undeclared host dialled: %v", err)
	}
	blocked := map[string]int{}
	for _, e := range led.Entries() {
		blocked[e.Host] += e.Blocked
		if e.Host == "localhost" && e.Proto == "tcp" && e.Blocked == 0 && e.Requests != 1 {
			t.Errorf("ledger = %+v", e)
		}
	}
	if blocked["localhost"] != 2 || blocked["127.0.0.1"] != 1 || blocked["other.example"] != 1 {
		t.Errorf("blocked attempts in the ledger = %v", blocked)
	}
}
