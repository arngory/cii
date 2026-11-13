package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

func TestCustomChecks(t *testing.T) {
	checks, err := CustomChecks([]config.ServiceCheck{
		{URL: "https://wiki.example.org/health"},
		{Name: "Shop", URL: "https://shop.example.org/", Expect: config.Codes{200, 204}, Contains: "cart", Blocked: "not available in your country", Group: "Work"},
		{Name: "Radio", URL: "http://radio.example.org/live", Group: "streaming"},
	})
	if err != nil || len(checks) != 3 {
		t.Fatalf("checks = %d, err = %v", len(checks), err)
	}
	for i, want := range []struct {
		name  string
		group probe.Group
		title string
	}{{"wiki.example.org", Custom, "Custom"}, {"Shop", "custom:Work", "Work"}, {"Radio", Streaming, ""}} {
		c := checks[i]
		if c.Service != want.name || c.Group != want.group || !c.Custom || c.Module != Module || !c.Requests[0].NoRedirect || Title(c.Group) != want.title {
			t.Errorf("check %d = %+v, title %q", i, c, Title(c.Group))
		}
	}
	if q, _ := CustomChecks([]config.ServiceCheck{{URL: "https://example.org/?a={ip}"}}); strings.Contains(q[0].Requests[0].URL, "{ip}") {
		t.Errorf("the address placeholder of built-in checks is live in an own check: %s", q[0].Requests[0].URL)
	}
	if q, _ := CustomChecks([]config.ServiceCheck{{URL: "https://wiki.example.org./"}}); q[0].Host != "wiki.example.org" || q[0].Service != "wiki.example.org" {
		t.Errorf("trailing dot kept: %+v", q[0])
	}
	if q, _ := CustomChecks([]config.ServiceCheck{{URL: "https://Wiki.Example.ORG/Path"}}); q[0].Service != "wiki.example.org" || q[0].Requests[0].URL != "https://wiki.example.org/Path" {
		t.Errorf("host case kept: %+v", q[0])
	}
	idn, err := CustomChecks([]config.ServiceCheck{{URL: "https://Вики.example:8443/x"}, {URL: "https://[2001:DB8::1]:8443/"}, {URL: "http://192.0.2.10/"}})
	if err != nil || idn[0].Host != "xn--b1amah.example" || idn[0].Service != idn[0].Host || idn[0].Requests[0].URL != "https://xn--b1amah.example:8443/x" ||
		idn[1].Host != "2001:db8::1" || idn[1].Requests[0].URL != "https://[2001:DB8::1]:8443/" || idn[2].Host != "192.0.2.10" {
		t.Errorf("hosts = %+v, err = %v", idn, err)
	}
	if checks[1].Host != "shop.example.org" || probe.Placeholders(checks)[1].Host != "shop.example.org" {
		t.Errorf("host of the check = %q", checks[1].Host)
	}
	rules := probe.Rules(checks)
	if len(rules) != 3 || rules[1].Pattern != "shop.example.org" || rules[1].Purpose != "services: Shop" {
		t.Errorf("rules = %+v", rules)
	}

	eval := func(i, status int, body string) probe.Result {
		return checks[i].Eval([]*probe.Response{{Status: status, Body: []byte(body)}})[0]
	}
	for _, c := range []struct {
		check, status int
		body          string
		want          probe.Status
		reason        string
	}{
		{0, http.StatusOK, "", probe.Yes, ""},
		{0, http.StatusFound, "", probe.Yes, ""},
		{0, http.StatusForbidden, "", probe.No, "HTTP 403"},
		{0, http.StatusBadGateway, "", probe.Failed, "HTTP 502"},
		{0, http.StatusTooManyRequests, "", probe.Failed, "rate limited"},
		{1, http.StatusOK, "your cart", probe.Yes, ""},
		{1, http.StatusNoContent, "cart", probe.Yes, ""},
		{1, http.StatusOK, "welcome", probe.No, "marker not found"},
		{1, http.StatusFound, "cart", probe.No, "HTTP 302"},
		{1, http.StatusOK, "cart: not available in your country", probe.No, "blocked marker found"},
		{1, http.StatusForbidden, "not available in your country", probe.No, "blocked marker found"},
		{1, http.StatusServiceUnavailable, "", probe.Failed, "HTTP 503"},
	} {
		if got := eval(c.check, c.status, c.body); got.Status != c.want || got.Reason != c.reason {
			t.Errorf("check %d, HTTP %d, %q = %s %q, want %s %q", c.check, c.status, c.body, got.Status, got.Reason, c.want, c.reason)
		}
	}
}

func TestCustomChecksRejectBadDefinitions(t *testing.T) {
	many := make([]config.ServiceCheck, MaxCustom+1)
	for i := range many {
		many[i].URL = "https://example.org/"
	}
	for name, defs := range map[string][]config.ServiceCheck{
		"no url":      {{Name: "x"}},
		"scheme":      {{URL: "ftp://example.org/"}},
		"no host":     {{URL: "https:///path"}},
		"credentials": {{URL: "https://user:secret@example.org/"}},
		"bad port":    {{URL: "https://user:secret@example.org:9x/"}},
		"bad escape":  {{URL: "https://example.org/%zz?token=secret"}},
		"semicolon":   {{Name: "Shop; EU", URL: "https://example.org/"}},
		"status":      {{URL: "https://example.org/", Expect: config.Codes{700}}},
		"twice":       {{Name: "a", URL: "https://example.org/"}, {Name: "a", URL: "https://example.net/"}},
		"same host":   {{URL: "https://example.org/a"}, {URL: "https://example.org/b"}},
		"built-in":    {{Name: "Netflix", URL: "https://example.org/", Group: "Streaming"}},
		"built-in 2":  {{Name: "netflix", URL: "https://example.org/"}},
		"catalog":     {{Name: Catalogs[0].checks[0].Service, URL: "https://example.org/", Group: "Work"}},
		"bad idn":     {{URL: "https://exa_mple..org/"}},
		"long name":   {{Name: strings.Repeat("n", maxLabel+1), URL: "https://example.org/"}},
		"control":     {{Name: "a\x1b[31m", URL: "https://example.org/"}},
		"long group":  {{URL: "https://example.org/", Group: strings.Repeat("g", maxLabel+1)}},
		"too many":    many,
	} {
		if checks, err := CustomChecks(defs); err == nil {
			t.Errorf("%s: accepted as %+v", name, checks)
		} else if strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: error repeats the credentials: %v", name, err)
		}
	}
	if checks, err := CustomChecks(nil); err != nil || checks != nil {
		t.Errorf("empty config = %v, %v", checks, err)
	}
}

func TestCustomChecksRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte("status: ok"))
		case "/away":
			http.Redirect(w, r, "http://elsewhere.invalid/", http.StatusFound)
		default:
			w.WriteHeader(http.StatusUnavailableForLegalReasons)
		}
	}))
	defer srv.Close()
	checks, err := CustomChecks([]config.ServiceCheck{
		{Name: "ok", URL: srv.URL + "/ok", Expect: config.Codes{200}, Contains: "status: ok"},
		{Name: "away", URL: srv.URL + "/away"},
		{Name: "legal", URL: srv.URL + "/legal"},
		{Name: "down", URL: "http://127.0.0.1:1/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range probe.Placeholders(checks) {
		if !p.Custom || p.Status != probe.Pending {
			t.Errorf("placeholder = %+v", p)
		}
	}
	led := ledger.New()
	n := netx.New(netx.Options{}, netx.NewPolicy(probe.Rules(checks)...), led)
	env := probe.Env{Nets: map[netx.Family]*netx.Net{netx.IPv4: n}}
	res := probe.Run(context.Background(), env, netx.IPv4, netip.MustParseAddr("203.0.113.9"), checks)
	if len(res) != 4 {
		t.Fatalf("results = %+v", res)
	}
	for i, want := range []probe.Status{probe.Yes, probe.Yes, probe.No, probe.Failed} {
		if res[i].Status != want || !res[i].Custom || res[i].Group != Custom || res[i].Host != "127.0.0.1" {
			t.Errorf("%s = %+v, want %s", checks[i].Service, res[i], want)
		}
	}
	if res[2].Reason != "HTTP 451" {
		t.Errorf("legal = %+v", res[2])
	}
	for _, e := range led.Entries() {
		if e.Blocked > 0 || strings.Contains(e.Host, "elsewhere") {
			t.Errorf("a redirect was followed: %+v", e)
		}
	}
}
