package netx

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/arngory/cii/internal/ledger"
)

func TestUDPConnSendsOnlyToAllowedAddresses(t *testing.T) {
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(k, "")
	}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	led := ledger.New()
	n := New(Options{Family: IPv4}, NewPolicy(Rule{Module: "m", Pattern: "127.0.0.1", Purpose: "test"}, Rule{Module: "m", Pattern: "named.example", Purpose: "test"}), led)
	c, err := n.ListenUDP("m")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	to := peer.LocalAddr().(*net.UDPAddr)
	if _, err := c.WriteTo([]byte("x"), to); !errors.Is(err, ErrAddrNotOfHost) {
		t.Errorf("write before Allow = %v", err)
	}
	loopback := netip.MustParseAddr("127.0.0.1")
	if err := c.Allow("other.example", loopback); AsBlocked(err) == nil {
		t.Errorf("undeclared host = %v", err)
	}
	if err := c.Allow("named.example", loopback); !errors.Is(err, ErrAddrNotOfHost) {
		t.Errorf("address never resolved for the host = %v", err)
	}
	if err := c.Allow("127.0.0.1", netip.MustParseAddr("127.0.0.2")); !errors.Is(err, ErrAddrNotOfHost) {
		t.Errorf("another address for a literal host = %v", err)
	}
	if err := c.Allow("127.0.0.1", loopback); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteTo([]byte("ping"), to); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: to.Port}); !errors.Is(err, ErrAddrNotOfHost) {
		t.Errorf("write to an address that was not allowed = %v", err)
	}
	if _, err := c.WriteTo([]byte("x"), &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}); !errors.Is(err, ErrAddrNotOfHost) {
		t.Errorf("write to a non-UDP address = %v", err)
	}
	buf := make([]byte, 16)
	peer.SetReadDeadline(time.Now().Add(time.Second))
	got, from, err := peer.ReadFromUDP(buf)
	if err != nil || string(buf[:got]) != "ping" {
		t.Fatalf("peer read %q, %v", buf[:got], err)
	}
	peer.WriteToUDP([]byte("pong"), from)
	c.SetReadDeadline(time.Now().Add(time.Second))
	if got, _, err := c.ReadFrom(buf); err != nil || string(buf[:got]) != "pong" {
		t.Errorf("read %q, %v", buf[:got], err)
	}
	blocked, requests := 0, 0
	for _, e := range led.Entries() {
		blocked += e.Blocked
		requests += e.Requests
	}
	if blocked != 3 || requests != 1 {
		t.Errorf("ledger: %d blocked, %d requests: %+v", blocked, requests, led.Entries())
	}
	proxy, _ := url.Parse("http://127.0.0.1:1")
	if _, err := New(Options{Proxy: proxy}, NewPolicy(), ledger.New()).ListenUDP("m"); !errors.Is(err, ErrProxyRaw) {
		t.Errorf("behind a proxy = %v", err)
	}
}
