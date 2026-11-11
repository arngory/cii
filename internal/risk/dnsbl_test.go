package risk

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	errs    map[string]error
	asked   []string
}

func (f *fakeResolver) LookupHost(_ context.Context, module, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, name)
	if module != Module {
		return nil, errors.New("wrong module")
	}
	if err, ok := f.errs[name]; ok {
		return nil, err
	}
	if a, ok := f.answers[name]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeResolver) LookupAddr(ctx context.Context, module string, ip netip.Addr) ([]string, error) {
	return f.LookupHost(ctx, module, netx.ReverseName(ip)+"."+netx.ReverseZone(ip))
}

func TestReverse(t *testing.T) {
	if got := netx.ReverseName(netip.MustParseAddr("192.0.2.10")); got != "10.2.0.192" {
		t.Errorf("v4 = %s", got)
	}
	if got := netx.ReverseName(netip.MustParseAddr("::ffff:192.0.2.10")); got != "10.2.0.192" {
		t.Errorf("mapped = %s", got)
	}
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
	if got := netx.ReverseName(netip.MustParseAddr("2001:db8::1")); got != want {
		t.Errorf("v6 = %s", got)
	}
}

func writeResolvConf(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func byService(rs []probe.Result) map[string]probe.Result {
	m := map[string]probe.Result{}
	for _, r := range rs {
		m[r.Service] = r
	}
	return m
}

func TestDNSBL(t *testing.T) {
	noEnvProxy(t)
	f := &fakeResolver{
		answers: map[string][]string{
			"4.3.2.81.zen.spamhaus.org":       {"127.0.0.4", "127.0.0.11"},
			"4.3.2.81.bl.spamcop.net":         {"127.0.0.2"},
			"4.3.2.81.dnsbl.dronebl.org":      {"127.0.0.255"},
			"4.3.2.81.bl.mailspike.net":       {"127.0.0.18"},
			"4.3.2.81.psbl.surriel.com":       {"127.255.255.254"},
			"4.3.2.81.dnsbl-1.uceprotect.net": {"203.0.113.9"},
		},
		errs: map[string]error{"4.3.2.81.all.s5h.net": &net.DNSError{Err: "i/o timeout", IsTimeout: true}},
	}
	rc := writeResolvConf(t, "nameserver 192.168.1.1\n")
	rs := run(context.Background(), f, nil, time.Second, netip.MustParseAddr("81.2.3.4"), Options{NoMail: true, ResolvConf: rc})
	if len(rs) != len(Zones)+1 {
		t.Fatalf("got %d results", len(rs))
	}
	m := byService(rs)
	if ptr := m[PTRService]; ptr.Group != Network || ptr.Status != probe.Unknown || ptr.Reason != "no PTR record" {
		t.Errorf("ptr = %+v", ptr)
	}
	cases := map[string]struct {
		status probe.Status
		detail string
	}{
		"zen.spamhaus.org":       {probe.No, "127.0.0.4 XBL, 127.0.0.11 PBL end-user range"},
		"bl.spamcop.net":         {probe.No, "127.0.0.2"},
		"dnsbl.dronebl.org":      {probe.No, "127.0.0.255 uncategorized"},
		"bl.mailspike.net":       {probe.Yes, "127.0.0.18 reputation code"},
		"psbl.surriel.com":       {probe.Unknown, "127.255.255.254 refused: query via public/open resolver"},
		"dnsbl-1.uceprotect.net": {probe.Unknown, "203.0.113.9"},
		"all.s5h.net":            {probe.Failed, ""},
	}
	for zone, want := range cases {
		r := m[zone]
		if r.Group != DNSBL || r.Status != want.status || r.Detail != want.detail {
			t.Errorf("%s = %+v, want %v %q", zone, r, want.status, want.detail)
		}
	}
}

func TestDNSBLv6AndPublicResolver(t *testing.T) {
	noEnvProxy(t)
	f := &fakeResolver{}
	rc := writeResolvConf(t, "# x\nnameserver 8.8.8.8\nnameserver 2001:4860:4860::8888\n")
	rs := checkDNSBL(context.Background(), f, netip.MustParseAddr("2a00:1450::1"), rc)
	m := byService(rs)
	if len(rs) != 2 || m["zen.spamhaus.org"].Status != probe.Unknown || m["dnsbl.dronebl.org"].Status != probe.Yes {
		t.Fatalf("v6 results = %+v", rs)
	}
	if len(f.asked) != 1 || !strings.HasSuffix(f.asked[0], ".a.2.dnsbl.dronebl.org") {
		t.Errorf("asked = %v", f.asked)
	}
	if rs := checkDNSBL(context.Background(), f, netip.MustParseAddr("10.0.0.1"), rc); rs != nil {
		t.Errorf("private address queried: %+v", rs)
	}
}

func TestInterpretErrors(t *testing.T) {
	z := Zones[1]
	if s, _, reason := interpret(z, nil, netx.ErrProxyRaw); s != probe.Unknown || reason != proxyReason {
		t.Errorf("proxy = %v %q", s, reason)
	}
	name := "4.3.2.81." + z.Zone
	if s, _, reason := interpret(z, nil, &netx.BlockedError{Module: Module, Host: name}); s != probe.Failed || reason != "blocked by policy: *."+z.Zone {
		t.Errorf("blocked = %v %q", s, reason)
	}
	failure := &net.DNSError{Err: "server misbehaving", Name: name, Server: "127.0.0.53:53"}
	if s, _, reason := interpret(z, nil, failure); s != probe.Failed || reason != "resolve: server misbehaving" {
		t.Errorf("dns failure = %v %q", s, reason)
	}
}

func TestLedgerHasNoReversedAddress(t *testing.T) {
	proxy, _ := url.Parse("http://127.0.0.1:1")
	for _, addr := range []string{"81.2.3.4", "2a00:1450::1"} {
		ip := netip.MustParseAddr(addr)
		led := ledger.New()
		n := netx.New(netx.Options{Timeout: time.Second, Proxy: proxy}, netx.NewPolicy(Rules(Options{NoMail: true})...), led)
		results := run(context.Background(), n, n, time.Second, ip, Options{NoMail: true})
		entries := led.Entries()
		if len(entries) == 0 || len(results) != len(zonesFor(ip))+1 {
			t.Fatalf("%s: %d ledger entries, %d results", addr, len(entries), len(results))
		}
		for _, e := range entries {
			if strings.Contains(e.Host, netx.ReverseName(ip)) || !strings.HasPrefix(e.Host, "*.") || e.Skipped != 1 {
				t.Errorf("%s: ledger entry %+v", addr, e)
			}
		}
		for _, r := range results {
			if strings.Contains(r.Reason+r.Detail, netx.ReverseName(ip)) {
				t.Errorf("%s: result %+v", addr, r)
			}
		}
	}
}

func TestRules(t *testing.T) {
	rs := Rules(Options{Mail: MailOptions{Host: "mx.example.net"}})
	p := netx.NewPolicy(rs...)
	for _, h := range []string{"4.3.2.1.zen.spamhaus.org", "1.0.0.2.dnsbl.dronebl.org", "mx.example.net"} {
		if _, ok := p.Match(Module, h); !ok {
			t.Errorf("%s not allowed", h)
		}
	}
	if _, ok := p.Match(Module, "gmail-smtp-in.l.google.com"); ok {
		t.Error("default mail host allowed despite override")
	}
	if _, ok := p.Match(Module, "4.3.2.1.in-addr.arpa"); !ok {
		t.Error("reverse zone not allowed")
	}
	if n := len(Rules(Options{NoDNSBL: true})); n != 3 {
		t.Errorf("mail-only rules = %d", n)
	}
}

func smtpServer(t *testing.T, handle func(net.Conn)) (string, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handle(c)
			}()
		}
	}()
	addr := l.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func testNet(proxy *url.URL, rules ...netx.Rule) *netx.Net {
	return netx.New(netx.Options{Timeout: 2 * time.Second, Proxy: proxy}, netx.NewPolicy(rules...), ledger.New())
}

func noEnvProxy(t *testing.T) {
	t.Helper()
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "")
	}
}

func TestSMTP(t *testing.T) {
	noEnvProxy(t)
	quit := make(chan string, 1)
	host, port := smtpServer(t, func(c net.Conn) {
		c.Write([]byte("220-mx.example.net ESMTP\r\n220 ready\r\n"))
		buf := make([]byte, 64)
		k, _ := c.Read(buf)
		quit <- string(buf[:k])
		c.Write([]byte("221 bye\r\n"))
	})
	opts := Options{NoDNSBL: true, Mail: MailOptions{Host: host, Port: port}}
	n := testNet(nil, Rules(opts)...)
	rs := Run(context.Background(), n, netip.MustParseAddr("81.2.3.4"), opts)
	if len(rs) != 2 || rs[1].Status != probe.Yes || rs[1].Group != Mail || rs[1].Detail != "220-mx.example.net ESMTP" {
		t.Fatalf("smtp = %+v", rs)
	}
	if q := <-quit; q != "QUIT\r\n" {
		t.Errorf("sent %q", q)
	}
}

func TestSMTPFailures(t *testing.T) {
	noEnvProxy(t)
	silent, sport := smtpServer(t, func(c net.Conn) { time.Sleep(time.Second) })
	reject, rport := smtpServer(t, func(c net.Conn) { c.Write([]byte("554 no service\r\n")); c.Read(make([]byte, 16)) })
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().(*net.TCPAddr).Port
	l.Close()

	d := testNet(nil, netx.Rule{Module: Module, Pattern: "127.0.0.1"})
	cases := []struct {
		host   string
		port   int
		status probe.Status
		detail string
	}{
		{silent, sport, probe.No, "connected to 127.0.0.1, no SMTP banner (timeout)"},
		{reject, rport, probe.No, "554 no service"},
		{"127.0.0.1", closed, probe.No, "connection refused (127.0.0.1)"},
	}
	for _, c := range cases {
		r := checkSMTP(context.Background(), d, MailOptions{Host: c.host, Port: c.port}, 300*time.Millisecond)
		if r.Status != c.status || r.Detail != c.detail {
			t.Errorf("%d: %+v", c.port, r)
		}
	}
	r := checkSMTP(context.Background(), d, MailOptions{Host: "undeclared.invalid"}, time.Second)
	if r.Status != probe.Failed || !strings.HasPrefix(r.Reason, "blocked by policy") {
		t.Errorf("undeclared = %+v", r)
	}
}

func TestRunWithProxy(t *testing.T) {
	proxy, _ := url.Parse("http://127.0.0.1:1")
	n := testNet(proxy, Rules(Options{})...)
	rs := Run(context.Background(), n, netip.MustParseAddr("81.2.3.4"), Options{})
	if len(rs) != len(Zones)+2 {
		t.Fatalf("got %d results", len(rs))
	}
	for _, r := range rs {
		if r.Status != probe.Unknown || r.Reason != proxyReason {
			t.Errorf("proxied = %+v", r)
		}
	}
	d := testNet(proxy, netx.Rule{Module: Module, Pattern: "127.0.0.1"})
	if r := checkSMTP(context.Background(), d, MailOptions{Host: "127.0.0.1"}, time.Second); r.Status != probe.Unknown || r.Reason != proxyReason {
		t.Errorf("dial via proxy = %+v", r)
	}
}

func TestPTR(t *testing.T) {
	ip := netip.MustParseAddr("81.2.3.4")
	f := &fakeResolver{answers: map[string][]string{"4.3.2.81.in-addr.arpa": {"host-81-2-3-4.example.net."}}}
	if r := checkPTR(context.Background(), f, ip); r.Status != probe.Yes || r.Detail != "host-81-2-3-4.example.net" {
		t.Errorf("ptr = %+v", r)
	}
	f = &fakeResolver{errs: map[string]error{"4.3.2.81.in-addr.arpa": &net.DNSError{Err: "server misbehaving"}}}
	if r := checkPTR(context.Background(), f, ip); r.Status != probe.Failed || r.Reason != "resolve: server misbehaving" {
		t.Errorf("ptr error = %+v", r)
	}
	f = &fakeResolver{errs: map[string]error{"4.3.2.81.in-addr.arpa": netx.ErrProxyRaw}}
	if r := checkPTR(context.Background(), f, ip); r.Status != probe.Unknown || r.Reason != proxyReason {
		t.Errorf("ptr via proxy = %+v", r)
	}
	f = &fakeResolver{errs: map[string]error{"4.3.2.81.in-addr.arpa": context.DeadlineExceeded}}
	if r := checkPTR(context.Background(), f, ip); r.Status != probe.Failed || r.Reason != "timeout" {
		t.Errorf("ptr timeout = %+v", r)
	}
	if got := Placeholders(ip, Options{NoDNSBL: true, NoMail: true}); len(got) != 1 || got[0].Service != PTRService || got[0].Status != probe.Pending {
		t.Errorf("placeholders = %+v", got)
	}
}
