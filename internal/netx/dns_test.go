package netx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/arngory/cii/internal/ledger"
)

func TestParseDNS(t *testing.T) {
	for spec, want := range map[string]string{
		"": "", "system": "", "System": "",
		"quad9": "Quad9 over TLS|9.9.9.9|853|dns.quad9.net", "CZNIC": "CZ.NIC ODVR over TLS|193.17.47.1|853|odvr.nic.cz",
		"192.0.2.53": "192.0.2.53|192.0.2.53|53|", "192.0.2.53:5353": "192.0.2.53|192.0.2.53|5353|",
		"[2001:db8::53]:53": "2001:db8::53|2001:db8::53|53|", "2001:db8::53": "2001:db8::53|2001:db8::53|53|",
		"tls://192.0.2.53#dns.example":          "192.0.2.53 over TLS|192.0.2.53|853|dns.example",
		"tls://[2001:db8::53]:8853#dns.example": "2001:db8::53 over TLS|2001:db8::53|8853|dns.example",
	} {
		s, err := ParseDNS(spec)
		if err != nil {
			t.Errorf("%q: %v", spec, err)
			continue
		}
		got := ""
		if s != nil {
			got = strings.Join([]string{s.Label(), s.Addrs[0].String(), s.Port, s.TLSName}, "|")
		}
		if got != want {
			t.Errorf("%q = %q, want %q", spec, got, want)
		}
	}
	for _, bad := range []string{"dns.example", "tls://192.0.2.53", "tls://dns.example#dns.example", "quad8", "192.0.2.53:x", "fe80::1%eth0"} {
		if s, err := ParseDNS(bad); err == nil {
			t.Errorf("%q accepted as %+v", bad, s)
		}
	}
	for name, p := range DNSPresets {
		v4, v6 := 0, 0
		for _, a := range p.Addrs {
			if a.Is4() {
				v4++
			} else {
				v6++
			}
		}
		if v4 == 0 || v6 == 0 || p.TLSName == "" || p.Port != "853" || !p.Public() {
			t.Errorf("preset %s = %+v", name, p)
		}
	}
	quad9 := DNSPresets["quad9"]
	if rules := quad9.Rules(); len(rules) != 4 || rules[0].Module != DNSModule || rules[0].Pattern != "9.9.9.9" || !strings.Contains(rules[0].Purpose, "Quad9 over TLS") {
		t.Errorf("rules = %+v", rules)
	}
	if order := quad9.ordered(); !order[0].Is4() || !order[1].Is4() || order[2].Is4() {
		t.Errorf("IPv4 servers should come first: %v", order)
	}
}

func dnsAnswer(t *testing.T, query []byte, a netip.Addr) []byte {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		t.Errorf("bad query: %v", err)
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	if q.Type == dnsmessage.TypeA {
		b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: a.As4()})
	}
	msg, _ := b.Finish()
	return msg
}

func serveDNSStream(t *testing.T, ln net.Listener, a netip.Addr, seen chan<- string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(2 * time.Second))
			for {
				var size [2]byte
				if _, err := io.ReadFull(c, size[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				seen <- "stream"
				reply := dnsAnswer(t, q, a)
				c.Write(binary.BigEndian.AppendUint16(nil, uint16(len(reply))))
				c.Write(reply)
			}
		}()
	}
}

func TestChosenResolver(t *testing.T) {
	noProxy(t)
	answer := netip.MustParseAddr("127.0.0.1")
	seen := make(chan string, 64)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			seen <- "udp"
			pc.WriteTo(dnsAnswer(t, buf[:n], answer), from)
		}
	}()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("TCP port of the UDP server is taken: %v", err)
	}
	defer ln.Close()
	go serveDNSStream(t, ln, answer, seen)

	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hello " + r.Host)) }))
	defer web.Close()
	webPort := web.Listener.Addr().(*net.TCPAddr).Port

	server, err := ParseDNS(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	policy := NewPolicy(append(server.Rules(), Rule{Module: "m", Pattern: "web.cii-test.example", Purpose: "test"})...)
	n := New(Options{Family: IPv4, Timeout: 2 * time.Second, DNS: server}, policy, led)
	addrs, err := n.LookupHost(context.Background(), "m", "web.cii-test.example")
	if err != nil || len(addrs) != 1 || addrs[0] != "127.0.0.1" {
		t.Fatalf("lookup = %v, %v", addrs, err)
	}
	if got := <-seen; got != "udp" {
		t.Errorf("first query went over %s", got)
	}
	resp, err := n.HTTPClient("m").Get("http://web.cii-test.example:" + strconv.Itoa(webPort) + "/")
	if err != nil {
		t.Fatalf("HTTP through the chosen resolver: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(body), "hello web.cii-test.example") {
		t.Errorf("body = %q", body)
	}
	dnsRequests := 0
	for _, e := range led.Entries() {
		if e.Module == DNSModule && e.Host == "127.0.0.1" {
			dnsRequests += e.Requests
		}
		if e.Blocked > 0 {
			t.Errorf("blocked: %+v", e)
		}
	}
	if dnsRequests < 2 {
		t.Errorf("resolver connections in the ledger = %d: %+v", dnsRequests, led.Entries())
	}

	closed := New(Options{Family: IPv4, Timeout: time.Second, DNS: server}, NewPolicy(Rule{Module: "m", Pattern: "web.cii-test.example"}), ledger.New())
	if _, err := closed.LookupHost(context.Background(), "m", "web.cii-test.example"); err == nil || !strings.Contains(err.Error(), "network policy") {
		t.Errorf("an undeclared resolver was used: %v", err)
	}

	proxy, _ := url.Parse("http://127.0.0.1:1")
	if p := New(Options{Proxy: proxy, DNS: server}, policy, ledger.New()); p.resolver != net.DefaultResolver {
		t.Error("behind a proxy names are resolved at the proxy, so the chosen resolver must stay unused")
	}
	if sys := New(Options{}, policy, ledger.New()); sys.resolver != net.DefaultResolver {
		t.Error("without --dns the system resolver must be used")
	}
}

func TestChosenResolverOverTLS(t *testing.T) {
	noProxy(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dns.cii-test.example"}, DNSNames: []string{"dns.cii-test.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	seen := make(chan string, 16)
	go serveDNSStream(t, ln, netip.MustParseAddr("192.0.2.77"), seen)
	server, err := ParseDNS("tls://" + ln.Addr().String() + "#dns.cii-test.example")
	if err != nil {
		t.Fatal(err)
	}
	policy := NewPolicy(append(server.Rules(), Rule{Module: "m", Pattern: "name.cii-test.example"})...)
	saved := dnsRoots
	defer func() { dnsRoots = saved }()
	dnsRoots = pool
	n := New(Options{Family: IPv4, Timeout: 2 * time.Second, DNS: server}, policy, ledger.New())
	if addrs, err := n.LookupHost(context.Background(), "m", "name.cii-test.example"); err != nil || len(addrs) != 1 || addrs[0] != "192.0.2.77" {
		t.Fatalf("lookup over TLS = %v, %v", addrs, err)
	}
	dnsRoots = x509.NewCertPool()
	led := ledger.New()
	n = New(Options{Family: IPv4, Timeout: time.Second, DNS: server}, policy, led)
	if _, err := n.LookupHost(context.Background(), "m", "name.cii-test.example"); err == nil {
		t.Error("an untrusted resolver certificate was accepted")
	}
	failed := false
	for _, e := range led.Entries() {
		failed = failed || e.Module == DNSModule && e.Errors > 0
	}
	if !failed {
		t.Errorf("the failed TLS handshake is not in the ledger: %+v", led.Entries())
	}
}

func noProxy(t *testing.T) {
	t.Helper()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(k, "")
	}
}
