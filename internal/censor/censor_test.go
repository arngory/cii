package censor

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

func noEnvProxy(t *testing.T) {
	t.Helper()
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "")
	}
}

func testRunner(t *testing.T, rules ...netx.Rule) *runner {
	t.Helper()
	noEnvProxy(t)
	n := netx.New(netx.Options{Timeout: 2 * time.Second, Family: netx.IPv4}, netx.NewPolicy(rules...), ledger.New())
	return &runner{n: n, sem: make(chan struct{}, 8)}
}

type seq struct{ b []byte }

func (s *seq) Read(p []byte) (int, error) {
	n := copy(p, s.b)
	s.b = s.b[n:]
	return n, nil
}

func TestMTProtoHelloMatchesReference(t *testing.T) {
	var random []byte
	for i := 1; i <= 64; i++ {
		random = append(random, byte(i))
	}
	random = append(random, bytes.Repeat([]byte{0xaa}, 16)...)
	h, err := newHello(&seq{random}, 2, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	wantHeader := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738eeeeeeee02003f40"
	sealed, _ := hex.DecodeString("2473534879e956cb65c192d1e3b16bf807f8215b409a5ec52a03ace7031cfdf20f2a1e8112137821da5089a240c396c35932d8b06f06272333bd9484f1fb4e3af5004d2a9d4aeedc3c99effa6b5679fa236f1b5a419015143bf3295800dae4fcfdae84f00e9274fac62b7580")
	want := wantHeader[:112] + hex.EncodeToString(sealed[56:])
	if got := hex.EncodeToString(h.Wire); got != want {
		t.Fatalf("wire\n got %s\nwant %s", got, want)
	}
	if hex.EncodeToString(h.decKey) != "3837363534333231302f2e2d2c2b2a292827262524232221201f1e1d1c1b1a19" || hex.EncodeToString(h.decIV) != "1817161514131211100f0e0d0c0b0a09" {
		t.Fatalf("decrypt key/iv = %x / %x", h.decKey, h.decIV)
	}
	plain := make([]byte, 44)
	copy(plain[24:28], resPQ)
	copy(plain[28:44], h.Nonce)
	enc, _ := ctrStream(h.decKey, h.decIV)
	reply := make([]byte, 44)
	enc.XORKeyStream(reply, plain)
	if err := h.check(reply); err != nil {
		t.Fatalf("valid reply rejected: %v", err)
	}
	reply[30] ^= 1
	if err := h.check(reply); !errors.Is(err, errBadReply) {
		t.Fatalf("tampered nonce accepted: %v", err)
	}
	if err := h.check(reply[:10]); !errors.Is(err, errBadReply) {
		t.Fatal("short reply accepted")
	}
}

func TestRandomHeaderAvoidsForbiddenPrefixes(t *testing.T) {
	var r []byte
	r = append(r, 0xef, 1, 2, 3, 4, 5, 6, 7)
	r = append(r, bytes.Repeat([]byte{9}, 56)...)
	r = append(r, 'P', 'O', 'S', 'T', 1, 2, 3, 4)
	r = append(r, bytes.Repeat([]byte{9}, 56)...)
	r = append(r, 1, 2, 3, 4, 0, 0, 0, 0)
	r = append(r, bytes.Repeat([]byte{9}, 56)...)
	r = append(r, 1, 2, 3, 4, 5, 6, 7, 8)
	r = append(r, bytes.Repeat([]byte{9}, 56)...)
	h, err := randomHeader(&seq{r})
	if err != nil || h[0] != 1 || h[7] != 8 {
		t.Fatalf("header = %x, %v", h[:8], err)
	}
}

func TestTelegramAgainstLocalServers(t *testing.T) {
	ok := localTCP(t, func(c net.Conn) {
		hdr := make([]byte, 64)
		if _, err := c.Read(hdr); err != nil {
			return
		}
		c.Write(make([]byte, 44))
	})
	drop := localTCP(t, func(c net.Conn) {
		buf := make([]byte, 64)
		c.Read(buf)
	})
	r := testRunner(t, netx.Rule{Module: Module, Pattern: "127.0.0.1"})
	r.n = netx.New(netx.Options{Timeout: 300 * time.Millisecond, Family: netx.IPv4}, netx.NewPolicy(netx.Rule{Module: Module, Pattern: "127.0.0.1"}), ledger.New())
	if res := telegramResult("x", r.mtprotoExchange(context.Background(), ok, 2)); res.Status != probe.No || !strings.Contains(res.Reason, "unexpected") {
		t.Errorf("garbage reply = %+v", res)
	}
	if res := telegramResult("x", r.mtprotoExchange(context.Background(), drop, 2)); res.Status != probe.No || !strings.Contains(res.Detail, "handshake dropped") {
		t.Errorf("dropped = %+v", res)
	}
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	if res := telegramResult("x", r.mtprotoExchange(context.Background(), closed, 2)); res.Status != probe.No || res.Detail != "TCP connect failed" {
		t.Errorf("refused = %+v", res)
	}
}

func localTCP(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handle(c)
			}()
		}
	}()
	return ln.Addr().String()
}

func answerFor(t *testing.T, q []byte, ips []string, rcode dnsmessage.RCode) []byte {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		t.Fatal(err)
	}
	qs, _ := p.AllQuestions()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RCode: rcode})
	b.StartQuestions()
	for _, qq := range qs {
		b.Question(qq)
	}
	b.StartAnswers()
	for _, ip := range ips {
		a := net.ParseIP(ip).To4()
		b.AResource(dnsmessage.ResourceHeader{Name: qs[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte(a)})
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestUDPQueryAndParse(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(answerFor(t, buf[:n], []string{"203.0.113.7"}, dnsmessage.RCodeSuccess), addr)
		}
	}()
	r := testRunner(t, netx.Rule{Module: Module, Pattern: "127.0.0.1"})
	a, err := r.queryUDP(context.Background(), pc.LocalAddr().String(), "example.test", dnsmessage.TypeA)
	if err != nil || len(a.IPs) != 1 || a.IPs[0] != "203.0.113.7" {
		t.Fatalf("udp answer = %+v, %v", a, err)
	}
	q, _ := buildQuery(7, "example.test", dnsmessage.TypeA)
	if _, err := parseAnswer(answerFor(t, q, nil, dnsmessage.RCodeSuccess), 8, dnsmessage.TypeA); !errors.Is(err, errMismatch) {
		t.Fatalf("mismatched id accepted: %v", err)
	}
	nx, _ := parseAnswer(answerFor(t, q, nil, dnsmessage.RCodeNameError), 7, dnsmessage.TypeA)
	if nx.RCode != dnsmessage.RCodeNameError || len(nx.IPs) != 0 {
		t.Fatalf("nxdomain = %+v", nx)
	}
}

func TestDoHQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Content-Type") != "application/dns-message" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		buf := make([]byte, 1024)
		n, _ := req.Body.Read(buf)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(answerFor(t, buf[:n], []string{"198.51.100.9"}, dnsmessage.RCodeSuccess))
	}))
	defer srv.Close()
	r := testRunner(t, netx.Rule{Module: Module, Pattern: "127.0.0.1"})
	a, err := r.queryDoH(context.Background(), srv.URL+"/dns-query", "example.test", dnsmessage.TypeA)
	if err != nil || len(a.IPs) != 1 || a.IPs[0] != "198.51.100.9" {
		t.Fatalf("doh answer = %+v, %v", a, err)
	}
}

func TestClassifyPlain(t *testing.T) {
	ref := []string{"203.0.113.7", "203.0.113.8"}
	cases := []struct {
		a    plainAnswer
		want probe.Status
		sub  string
	}{
		{plainAnswer{Responded: true, IPs: []string{"203.0.113.8"}}, probe.Yes, "clean"},
		{plainAnswer{Responded: true, NXDomain: true}, probe.No, "NXDOMAIN"},
		{plainAnswer{Responded: true, IPs: []string{"10.0.0.1"}}, probe.No, "bogus"},
		{plainAnswer{Responded: true, IPs: []string{"192.0.2.1"}}, probe.No, "spoofed (192.0.2.1)"},
		{plainAnswer{}, probe.Unknown, "unreachable"},
	}
	for _, c := range cases {
		st, reason := classifyPlain(c.a, ref)
		if st != c.want || !strings.Contains(reason, c.sub) {
			t.Errorf("classifyPlain(%+v) = %s %q, want %s %q", c.a, st, reason, c.want, c.sub)
		}
	}
}

func TestClassifyHTTP(t *testing.T) {
	cases := []struct {
		o      outcome
		want   probe.Status
		reason string
	}{
		{outcome{Status: 200}, probe.Yes, "available"},
		{outcome{Status: 301, Location: "https://www.example.com/"}, probe.Yes, "redirected"},
		{outcome{Status: 302, Location: "http://warning.rt.ru/"}, probe.No, "block page"},
		{outcome{Status: 302, Location: "http://10.1.1.1/blocked"}, probe.No, "block page"},
		{outcome{Status: 302, Location: "http://93.184.216.34/zapret"}, probe.No, "block page"},
		{outcome{Status: 302, Location: "http://93.184.216.34/"}, probe.Unknown, "redirected"},
		{outcome{Status: 302, Location: "https://other.test/"}, probe.Unknown, "redirected"},
		{outcome{Status: 403}, probe.No, "denied"},
		{outcome{Status: 451}, probe.No, "legal"},
		{outcome{Status: 503}, probe.Unknown, "status code 503"},
		{outcome{Err: errors.New("reset"), Phase: phaseTLS}, probe.No, "TLS handshake"},
		{outcome{Err: errors.New("x"), Phase: phaseConnect}, probe.No, "blocked by port"},
		{outcome{Err: errors.New("x"), Phase: phaseDNS}, probe.Unknown, "DNS lookup failed"},
		{outcome{Err: netx.ErrProxyRaw}, probe.Unknown, "proxy"},
	}
	for _, c := range cases {
		res := classifyHTTP("example.com", c.o)
		if res.Status != c.want || !strings.Contains(res.Reason, c.reason) {
			t.Errorf("classifyHTTP(%+v) = %s %q, want %s %q", c.o, res.Status, res.Reason, c.want, c.reason)
		}
	}
}

func TestParseTargetAndRules(t *testing.T) {
	cases := map[string]string{
		"youtube.com":                               "youtube.com",
		"https://Example.COM:8443/path?x=1":         "example.com",
		"redirector.googlevideo.com/report_mapping": "redirector.googlevideo.com",
		"  # comment  ":                             "",
		"":                                          "",
	}
	for in, host := range cases {
		tg, ok := parseTarget(in)
		if (host == "") == ok || tg.Host != host {
			t.Errorf("parseTarget(%q) = %+v %v", in, tg, ok)
		}
	}
	rules := Rules(Options{Modes: []string{"dpi"}})
	hosts := map[string]bool{}
	for _, r := range rules {
		hosts[r.Pattern] = true
	}
	if !hosts["youtube.com"] || !hosts["*.youtube.com"] || hosts["1.1.1.1"] || hosts["149.154.175.50"] {
		t.Errorf("dpi rules = %v", hosts)
	}
	if got := resolvers[0].forFamily(netx.IPv6).DoH; got != "https://[2606:4700:4700::1111]/dns-query" {
		t.Errorf("IPv6 DoH endpoint = %q", got)
	}
	if got := resolvers[0].forFamily(netx.IPv4).DoH; got != "https://1.1.1.1/dns-query" {
		t.Errorf("IPv4 DoH endpoint = %q", got)
	}
	for _, fam := range []netx.Family{netx.IPv4, netx.IPv6} {
		for _, rs := range resolversFor(fam) {
			req, err := http.NewRequest(http.MethodPost, rs.DoH, nil)
			if err != nil || req.URL.Hostname() == "" || req.URL.Port() != "" || req.URL.Path != "/dns-query" {
				t.Errorf("%s %s DoH endpoint %q: %v", rs.Name, fam, rs.DoH, err)
			}
		}
	}
	all := Rules(Options{})
	if len(all) <= len(rules) {
		t.Error("all-mode rules not larger than dpi rules")
	}
	if _, bad := selectedModes(Options{Modes: []string{"tg", "bogus"}}); len(bad) != 1 || bad[0] != "bogus" {
		t.Errorf("bad modes = %v", bad)
	}
	for p, ok := range map[string]bool{"": true, "both": true, "HTTP": true, "https": true, "htps": false, "http,https": false, " https": false} {
		if ValidProtocol(p) != ok {
			t.Errorf("ValidProtocol(%q) = %v", p, !ok)
		}
	}
}

func TestRunWithProxyDisablesRaw(t *testing.T) {
	noEnvProxy(t)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	n := netx.New(netx.Options{Timeout: 300 * time.Millisecond}, netx.NewPolicy(Rules(Options{Modes: []string{"telegram"}})...), ledger.New())
	for _, r := range Run(context.Background(), n, Options{Modes: []string{"telegram"}}) {
		if r.Status != probe.Unknown || !strings.Contains(r.Reason, "proxy") {
			t.Errorf("telegram via proxy = %+v", r)
		}
	}
}
