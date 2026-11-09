package netx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/arngory/cii/internal/ledger"
)

func TestPolicyMatch(t *testing.T) {
	p := NewPolicy(
		Rule{Module: "a", Pattern: "Example.com", Purpose: "x"},
		Rule{Module: "a", Pattern: "*.cdn.example"},
		Rule{Module: "a", Pattern: "example.com", Purpose: "y"},
		Rule{Module: "a", Pattern: "example.com", Purpose: "x"},
	)
	cases := []struct {
		module, host string
		want         bool
	}{
		{"a", "example.com", true},
		{"a", "EXAMPLE.com.", true},
		{"a", "example.com:443", true},
		{"a", "x.example.com", false},
		{"a", "img.cdn.example", true},
		{"a", "a.b.cdn.example", true},
		{"a", "cdn.example", false},
		{"a", "evilcdn.example", false},
		{"b", "example.com", false},
	}
	for _, c := range cases {
		if _, got := p.Match(c.module, c.host); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.module, c.host, got, c.want)
		}
	}
	if n := len(p.Rules()); n != 2 {
		t.Errorf("duplicate rule kept: %d rules", n)
	}
	if r, _ := p.Match("a", "example.com"); r.Purpose != "x; y" {
		t.Errorf("merged purpose = %q", r.Purpose)
	}
	for _, c := range [][3]string{{"", "y", "y"}, {"x", "", "x"}, {"x; y", "y", "x; y"}, {"xy", "x", "xy; x"}} {
		if got := mergePurpose(c[0], c[1]); got != c[2] {
			t.Errorf("mergePurpose(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

func TestGuardBlocksUndeclaredAndRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://undeclared.invalid/", http.StatusFound)
			return
		}
		w.Write([]byte(r.UserAgent()))
	}))
	defer srv.Close()

	led := ledger.New()
	n := New(Options{}, NewPolicy(Rule{Module: "m", Pattern: "127.0.0.1", Purpose: "test"}), led)
	c := n.HTTPClient("m")

	resp, err := c.Get(srv.URL + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	_, err = c.Get(srv.URL + "/redirect")
	var be *BlockedError
	if !errors.As(err, &be) || be.Host != "undeclared.invalid" {
		t.Fatalf("redirect to undeclared host not blocked: %v", err)
	}

	_, err = n.HTTPClient("other").Get(srv.URL + "/ok")
	if !errors.As(err, &be) {
		t.Fatalf("module scoping not enforced: %v", err)
	}

	got := map[string]ledger.Entry{}
	for _, e := range led.Entries() {
		got[e.Module+" "+e.Host] = e
	}
	if e := got["m 127.0.0.1"]; e.Requests != 2 {
		t.Errorf("requests to 127.0.0.1 = %d, want 2", e.Requests)
	}
	if e := got["m undeclared.invalid"]; e.Blocked != 1 {
		t.Errorf("blocked redirect not recorded: %+v", e)
	}
	if e := got["other 127.0.0.1"]; e.Blocked != 1 {
		t.Errorf("blocked module not recorded: %+v", e)
	}
}

func TestIsPublic(t *testing.T) {
	for s, want := range map[string]bool{
		"1.1.1.1": true, "10.0.0.1": false, "100.64.1.1": false, "192.0.2.1": false,
		"127.0.0.1": false, "2a00:1450::1": true, "fd00::1": false, "fe80::1": false,
		"2001:db8::1": false, "::ffff:8.8.8.8": true,
	} {
		if got := IsPublic(netip.MustParseAddr(s)); got != want {
			t.Errorf("IsPublic(%s) = %v, want %v", s, got, want)
		}
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestForcedFamilyNotAppliedToProxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.URL.Host))
	}))
	defer srv.Close()
	proxy := mustURL(t, srv.URL)
	n := New(Options{Family: IPv6, Proxy: proxy}, NewPolicy(Rule{Module: "m", Pattern: "target.invalid"}), ledger.New())
	resp, err := n.HTTPClient("m").Get("http://target.invalid/")
	if err != nil {
		t.Fatalf("IPv6-forced request through IPv4 proxy failed: %v", err)
	}
	resp.Body.Close()
}
