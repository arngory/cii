package censor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/quic"

	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

func noProxyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(k, "")
	}
}

func stunReply(req []byte, mapped netip.AddrPort, xor bool) []byte {
	val := []byte{0, 1, 0, 0}
	ip := mapped.Addr().AsSlice()
	if mapped.Addr().Is6() {
		val[1] = 2
	}
	binary.BigEndian.PutUint16(val[2:], mapped.Port())
	val = append(val, ip...)
	typ := uint16(stunMapped)
	if xor {
		typ = stunXORMapped
		val[2] ^= 0x21
		val[3] ^= 0x12
		for i := range ip {
			val[4+i] ^= req[4+i]
		}
	}
	out := make([]byte, 20, 64)
	binary.BigEndian.PutUint16(out[0:], stunSuccess)
	copy(out[4:], req[4:20])
	out = append(out, 0x80, 0x22, 0, 3, 'c', 'i', 'i', 0)
	out = binary.BigEndian.AppendUint16(out, typ)
	out = binary.BigEndian.AppendUint16(out, uint16(len(val)))
	out = append(out, val...)
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)-20))
	return out
}

func TestParseSTUN(t *testing.T) {
	req, id := stunBinding()
	if len(req) != 20 || binary.BigEndian.Uint16(req) != stunRequest || binary.BigEndian.Uint32(req[4:]) != stunMagic {
		t.Fatalf("request = %x", req)
	}
	for _, want := range []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:51000"), netip.MustParseAddrPort("[2001:db8::7]:443")} {
		for _, xor := range []bool{true, false} {
			if got, ok := parseSTUN(stunReply(req, want, xor), id); !ok || got != want {
				t.Errorf("xor=%v: parsed %v, %v; want %v", xor, got, ok, want)
			}
		}
	}
	reply := stunReply(req, netip.MustParseAddrPort("203.0.113.7:51000"), true)
	other, _ := stunBinding()
	for name, msg := range map[string][]byte{
		"short": reply[:12], "another transaction": stunReply(other, netip.MustParseAddrPort("203.0.113.7:1"), true),
		"a request": req, "truncated attribute": reply[:len(reply)-3], "no address": reply[:28], "empty": nil,
	} {
		if got, ok := parseSTUN(msg, id); ok {
			t.Errorf("%s was accepted as %v", name, got)
		}
	}
}

func TestNATResult(t *testing.T) {
	ap := netip.MustParseAddrPort
	for name, c := range map[string]struct {
		local  string
		mapped []netip.AddrPort
		status probe.Status
		reason string
		detail string
	}{
		"blocked":   {"192.168.1.5:40000", nil, probe.No, "no answer from STUN servers", ""},
		"public":    {"203.0.113.7:40000", []netip.AddrPort{ap("203.0.113.7:40000"), ap("203.0.113.7:40000")}, probe.Yes, "no NAT", "203.0.113.7:40000 → 203.0.113.7:40000"},
		"cone":      {"192.168.1.5:40000", []netip.AddrPort{ap("203.0.113.7:51000"), ap("203.0.113.7:51000")}, probe.Yes, "one mapping for every destination", "192.168.1.5:40000 → 203.0.113.7:51000"},
		"symmetric": {"192.168.1.5:40000", []netip.AddrPort{ap("203.0.113.7:51000"), ap("203.0.113.7:51001")}, probe.Partial, "symmetric NAT", "192.168.1.5:40000 → 203.0.113.7:51000, 203.0.113.7:51001"},
		"one":       {"192.168.1.5:40000", []netip.AddrPort{ap("203.0.113.7:51000")}, probe.Yes, "mapping type is unknown", "192.168.1.5:40000 → 203.0.113.7:51000"},
		"cgnat":     {"100.64.3.9:40000", []netip.AddrPort{ap("203.0.113.7:51000"), ap("203.0.113.7:51000")}, probe.Yes, "carrier-grade NAT", "100.64.3.9:40000 → 203.0.113.7:51000"},
	} {
		got := natResult(ap(c.local), c.mapped)
		if got.Status != c.status || !strings.Contains(got.Reason, c.reason) || got.Detail != c.detail || got.Group != Transport {
			t.Errorf("%s = %+v", name, got)
		}
	}
	if got := natResult(netip.AddrPort{}, []netip.AddrPort{ap("203.0.113.7:51000")}); got.Detail != "203.0.113.7:51000" || got.Status != probe.Yes {
		t.Errorf("without a local address = %+v", got)
	}
}

func stunTestServer(t *testing.T, answer func(req []byte, from netip.AddrPort) []byte) stunServer {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if reply := answer(append([]byte(nil), buf[:n]...), from); reply != nil {
				pc.WriteToUDPAddrPort(reply, from)
			}
		}
	}()
	return stunServer{"127.0.0.1", netip.MustParseAddrPort(pc.LocalAddr().String()).String()[len("127.0.0.1:"):]}
}

func TestNATOverLoopback(t *testing.T) {
	noProxyEnv(t)
	echo := func(req []byte, from netip.AddrPort) []byte { return stunReply(req, from, true) }
	shifted := func(req []byte, from netip.AddrPort) []byte {
		return stunReply(req, netip.AddrPortFrom(from.Addr(), from.Port()+1), true)
	}
	silent := func([]byte, netip.AddrPort) []byte { return nil }
	saved := stunServers
	defer func() { stunServers = saved }()
	run := func(servers ...stunServer) (probe.Result, []ledger.Entry) {
		stunServers = servers
		led := ledger.New()
		n := netx.New(netx.Options{Family: netx.IPv4, Timeout: 300 * time.Millisecond}, netx.NewPolicy(Rules(Options{Modes: []string{"transport"}})...), led)
		return newRunner(n, Options{}).nat(context.Background()), led.Entries()
	}
	res, entries := run(stunTestServer(t, echo), stunTestServer(t, echo))
	if res.Status != probe.Yes || !strings.Contains(res.Reason, "one mapping for every destination") && !strings.Contains(res.Reason, "no NAT") {
		t.Errorf("two echoing servers = %+v", res)
	}
	udp := false
	for _, e := range entries {
		udp = udp || e.Proto == "udp" && e.Requests == 2
		if e.Blocked > 0 {
			t.Errorf("blocked entry in the ledger: %+v", e)
		}
	}
	if !udp {
		t.Errorf("no UDP contact in the ledger: %+v", entries)
	}
	if res, _ := run(stunTestServer(t, echo), stunTestServer(t, shifted)); res.Status != probe.Partial || !strings.Contains(res.Reason, "symmetric") {
		t.Errorf("different mappings = %+v", res)
	}
	if res, _ := run(stunTestServer(t, silent), stunTestServer(t, echo)); res.Status != probe.Yes || !strings.Contains(res.Reason, "one STUN server answered") {
		t.Errorf("one silent server = %+v", res)
	}
	if res, _ := run(stunTestServer(t, silent)); res.Status != probe.No {
		t.Errorf("silent server = %+v", res)
	}
	stunServers = []stunServer{{"127.0.0.1", "9"}}
	n := netx.New(netx.Options{Family: netx.IPv4, Timeout: 200 * time.Millisecond}, netx.NewPolicy(), ledger.New())
	if res := newRunner(n, Options{}).nat(context.Background()); res.Status != probe.Failed || !strings.Contains(res.Reason, "blocked by policy") {
		t.Errorf("undeclared STUN server = %+v", res)
	}
}

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cii test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func TestQUICOverLoopback(t *testing.T) {
	noProxyEnv(t)
	cert, pool := testCertificate(t)
	server, err := quic.Listen("udp4", "127.0.0.1:0", &quic.Config{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(context.Background())
	go func() {
		for {
			c, err := server.Accept(context.Background())
			if err != nil {
				return
			}
			go c.Wait(context.Background())
		}
	}()
	savedPort, savedRoots, savedTargets := quicPort, quicRoots, quicTargets
	defer func() { quicPort, quicRoots, quicTargets = savedPort, savedRoots, savedTargets }()
	quicTargets = []string{"127.0.0.1"}
	run := func(port string, roots *x509.CertPool) probe.Result {
		quicPort, quicRoots = port, roots
		n := netx.New(netx.Options{Family: netx.IPv4, Timeout: 700 * time.Millisecond}, netx.NewPolicy(Rules(Options{Modes: []string{"transport"}})...), ledger.New())
		return newRunner(n, Options{}).quic(context.Background(), "127.0.0.1")
	}
	port := server.LocalAddr().String()[len("127.0.0.1:"):]
	if res := run(port, pool); res.Status != probe.Yes || !strings.Contains(res.Reason, "handshake completed") || res.Detail != "127.0.0.1" || res.Service != "QUIC 127.0.0.1" {
		t.Errorf("local QUIC server = %+v", res)
	}
	if res := run(port, x509.NewCertPool()); res.Status != probe.No || !strings.Contains(res.Reason, "certificate") {
		t.Errorf("untrusted certificate = %+v", res)
	}
	quiet, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer quiet.Close()
	if res := run(quiet.LocalAddr().String()[len("127.0.0.1:"):], pool); res.Status != probe.No || !strings.Contains(res.Reason, "no QUIC answer") {
		t.Errorf("silent port = %+v", res)
	}
	n := netx.New(netx.Options{Family: netx.IPv4, Timeout: 300 * time.Millisecond}, netx.NewPolicy(), ledger.New())
	if res := newRunner(n, Options{}).quic(context.Background(), "127.0.0.1"); res.Status != probe.Failed || !strings.Contains(res.Reason, "blocked by policy") {
		t.Errorf("undeclared QUIC target = %+v", res)
	}
}

func TestTransportRules(t *testing.T) {
	rules := Rules(Options{Modes: []string{"transport"}})
	want := map[string]bool{"stun.cloudflare.com": true, "stun.l.google.com": true, "www.google.com": true, "www.cloudflare.com": true}
	for _, r := range rules {
		if !want[r.Pattern] || r.Module != Module || r.Purpose == "" {
			t.Errorf("unexpected rule %+v", r)
		}
		delete(want, r.Pattern)
	}
	if len(want) != 0 {
		t.Errorf("hosts without a rule: %v", want)
	}
	if !ValidMode("transport") || len(Placeholders(Options{Modes: []string{"transport"}})) != 1 {
		t.Error("transport is not a known mode")
	}
}

func TestBlockKeyControls(t *testing.T) {
	noProxyEnv(t)
	cert, _ := testCertificate(t)
	listen := func(handle func(net.Conn)) string {
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
					c.SetDeadline(time.Now().Add(2 * time.Second))
					handle(c)
				}()
			}
		}()
		return ln.Addr().String()[len("127.0.0.1:"):]
	}
	var sawName, sawHost string
	tlsOK := listen(func(c net.Conn) {
		s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			sawName = "name:" + h.ServerName
			return nil, nil
		}})
		s.Handshake()
	})
	tlsAlert := listen(func(c net.Conn) {
		tls.Server(c, &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return nil, context.Canceled
		}}).Handshake()
	})
	dropped := listen(func(net.Conn) {})
	httpOK := listen(func(c net.Conn) {
		buf := make([]byte, 512)
		n, _ := c.Read(buf)
		for _, line := range strings.Split(string(buf[:n]), "\r\n") {
			if strings.HasPrefix(line, "Host: ") {
				sawHost = line
			}
		}
		c.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
	})
	savedTLS, savedHTTP := tlsControlPort, httpControlPort
	defer func() { tlsControlPort, httpControlPort = savedTLS, savedHTTP }()
	n := netx.New(netx.Options{Family: netx.IPv4, Timeout: 700 * time.Millisecond}, netx.NewPolicy(netx.Rule{Module: Module, Pattern: "127.0.0.1", Purpose: "test"}), ledger.New())
	r := newRunner(n, Options{})
	ip := netip.MustParseAddr("127.0.0.1")
	for port, want := range map[string]bool{tlsOK: true, tlsAlert: true, dropped: false} {
		tlsControlPort = port
		if got := r.tlsWithoutName(context.Background(), "127.0.0.1", ip); got != want {
			t.Errorf("handshake without the name on port %s = %v, want %v", port, got, want)
		}
	}
	if sawName != "name:" {
		t.Errorf("the control handshake carried a server name: %q", sawName)
	}
	for port, want := range map[string]bool{httpOK: true, dropped: false} {
		httpControlPort = port
		if got := r.httpByAddress(context.Background(), "127.0.0.1", ip); got != want {
			t.Errorf("request by address on port %s = %v, want %v", port, got, want)
		}
	}
	if sawHost != "Host: 127.0.0.1" {
		t.Errorf("the control request carried %q", sawHost)
	}
	if r.tlsWithoutName(context.Background(), "other.example", ip) || r.httpByAddress(context.Background(), "other.example", ip) {
		t.Error("a control probe went to a host the policy does not declare")
	}
	for _, c := range []struct {
		proto    string
		answered bool
		want     string
	}{
		{"HTTPS", true, "blocked by SNI: TLS handshake connection reset, while the same address answers a handshake without the name"},
		{"HTTPS", false, "TLS handshake connection reset (likely DPI); the address does not answer a handshake without the name either"},
		{"HTTP", true, "blocked by Host header: connection reset after request, while the same address answers a request without the name"},
		{"HTTP", false, "blocked / connection reset after request (likely DPI); the address does not answer a request without the name either"},
	} {
		reason := "TLS handshake connection reset (likely DPI)"
		if c.proto == "HTTP" {
			reason = "blocked / connection reset after request (likely DPI)"
		}
		if got := keyedBlock(c.proto, "connection reset", reason, c.answered); got != c.want {
			t.Errorf("%s answered=%v: %q", c.proto, c.answered, got)
		}
	}
}
