package netx

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/arngory/cii/internal/ledger"
)

func TestDialPolicyLedgerAndProxy(t *testing.T) {
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
		byKey["m a.example udp"].Blocked != 1 || byKey["m a.example dns"].Blocked != 1 {
		t.Fatalf("ledger = %+v", led.Entries())
	}
}
