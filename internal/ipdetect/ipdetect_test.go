package ipdetect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
)

func TestParse(t *testing.T) {
	cases := []struct {
		body   string
		format Format
		want   string
	}{
		{"203.0.113.9\n", "plain", "203.0.113.9"},
		{"fl=1\nh=x\nip=2001:db8::5\nloc=DE\n", "trace", "2001:db8::5"},
		{`{"ip":"198.51.100.4"}`, "json:ip", "198.51.100.4"},
		{"::ffff:1.2.3.4", "", "1.2.3.4"},
	}
	for _, c := range cases {
		a, err := Parse([]byte(c.body), c.format)
		if err != nil || a.String() != c.want {
			t.Errorf("Parse(%q, %q) = %v, %v; want %s", c.body, c.format, a, err, c.want)
		}
	}
	for _, bad := range []struct {
		body   string
		format Format
	}{{"<html>", "plain"}, {"h=x", "trace"}, {"{}", "json:ip"}, {"1.2.3.4", "xml"}} {
		if _, err := Parse([]byte(bad.body), bad.format); err == nil {
			t.Errorf("Parse(%q, %q) succeeded", bad.body, bad.format)
		}
	}
}

func TestDetectFallsBackAndChecksFamily(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v6":
			w.Write([]byte("2a00:1450::1"))
		case "/v4":
			w.Write([]byte("8.8.8.8"))
		default:
			http.Error(w, "nope", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	providers := []Provider{
		{Name: "broken", URL4: srv.URL + "/err"},
		{Name: "wrongfamily", URL4: srv.URL + "/v6"},
		{Name: "good", URL4: srv.URL + "/v4"},
	}
	n := netx.New(netx.Options{}, netx.NewPolicy(Rules(providers)...), ledger.New())
	got := Detect(context.Background(), n, netx.IPv4, Options{Providers: providers})
	if got.Address.String() != "8.8.8.8" || got.Source != "echo:good" {
		t.Fatalf("Detect = %+v", got)
	}
}

func TestDetectBehindProxyNeverFallsBackToInterface(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "")
	}
	providers := []Provider{{Name: "echo", URL4: "http://echo.invalid/"}}
	source := netip.MustParseAddr("8.8.8.8")
	direct := netx.New(netx.Options{}, netx.NewPolicy(Rules(providers)...), ledger.New())
	if got := Detect(context.Background(), direct, netx.IPv4, Options{Providers: providers, Source: source, Offline: true}); got.Address != source {
		t.Fatalf("direct offline = %+v", got)
	}
	proxy, _ := url.Parse("http://127.0.0.1:1")
	proxied := netx.New(netx.Options{Timeout: time.Second, Proxy: proxy}, netx.NewPolicy(Rules(providers)...), ledger.New())
	got := Detect(context.Background(), proxied, netx.IPv4, Options{Providers: providers, Source: source})
	if got.Address.IsValid() || len(got.Interface) != 0 || got.Error == "" {
		t.Errorf("proxied = %+v", got)
	}
	if got := Detect(context.Background(), proxied, netx.IPv4, Options{Providers: providers, Source: source, Offline: true}); got.Address != source {
		t.Errorf("proxied offline = %+v", got)
	}
}

func TestDetectMajorityVote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/odd":
			w.Write([]byte("192.0.2.9"))
		case "/slow":
			time.Sleep(80 * time.Millisecond)
			w.Write([]byte("203.0.113.7"))
		default:
			time.Sleep(40 * time.Millisecond)
			w.Write([]byte("203.0.113.7"))
		}
	}))
	defer srv.Close()
	providers := []Provider{
		{Name: "b", URL4: srv.URL + "/slow"},
		{Name: "odd", URL4: srv.URL + "/odd"},
		{Name: "a", URL4: srv.URL + "/a"},
	}
	n := netx.New(netx.Options{}, netx.NewPolicy(Rules(providers)...), ledger.New())
	got := Detect(context.Background(), n, netx.IPv4, Options{Providers: providers})
	if got.Address.String() != "203.0.113.7" || got.Source != "echo:a+b" || len(got.Disagree) != 1 || got.Disagree[0] != "odd: 192.0.2.9" {
		t.Fatalf("Detect = %+v", got)
	}
}

func TestDetectTieFollowsConfigOrder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			time.Sleep(60 * time.Millisecond)
			w.Write([]byte("203.0.113.7"))
			return
		}
		w.Write([]byte("198.51.100.9"))
	}))
	defer srv.Close()
	providers := []Provider{{Name: "first", URL4: srv.URL + "/slow"}, {Name: "second", URL4: srv.URL + "/fast"}}
	n := netx.New(netx.Options{}, netx.NewPolicy(Rules(providers)...), ledger.New())
	got := Detect(context.Background(), n, netx.IPv4, Options{Providers: providers})
	if got.Address.String() != "203.0.113.7" || got.Source != "echo:first" || len(got.Disagree) != 1 || got.Disagree[0] != "second: 198.51.100.9" {
		t.Fatalf("tie = %+v", got)
	}
}

func TestDetectExplainsMissingRecords(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "")
	}
	providers := []Provider{{Name: "a", URL6: "https://a.cii-test.invalid/"}, {Name: "b", URL6: "https://b.cii-test.invalid/"}}
	n := netx.New(netx.Options{Timeout: 5 * time.Second}, netx.NewPolicy(Rules(providers)...), ledger.New())
	got := Detect(context.Background(), n, netx.IPv6, Options{Providers: providers, Source: netip.MustParseAddr("2001:db8::1")})
	if !strings.Contains(got.Error, "no AAAA records") || !strings.Contains(got.Error, "IPv6 is off or filtered") {
		t.Skipf("resolver did not answer NXDOMAIN for .invalid here: %s", got.Error)
	}
}
