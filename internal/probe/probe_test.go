package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
)

func TestJSONPath(t *testing.T) {
	r := &Response{Body: []byte(`)]}'
[["x",null,[[["en","DE"]]]]]`)}
	if got := JSONPathAfter(")]}'", "[0][2][0][0][1]")(r); got != "DE" {
		t.Errorf("prefixed path = %q", got)
	}
	r = &Response{Body: []byte(`{"data":{"location":{"country":{"alpha2":"NL"}}},"list":[{"c":"FR"}]}`)}
	for path, want := range map[string]string{"data.location.country.alpha2": "NL", "list[0].c": "FR", "list[1].c": "", "data.x.y": "", "list[": ""} {
		if got := JSONPath(path)(r); got != want {
			t.Errorf("JSONPath(%q) = %q, want %q", path, got, want)
		}
	}
	if got := JSONPath("[0].country")(&Response{Body: []byte(`[{"country":"US"}]`)}); got != "US" {
		t.Errorf("leading index = %q", got)
	}
}

func TestCountryResult(t *testing.T) {
	cases := []struct {
		raw    string
		status int
		want   Status
	}{
		{"us\n", 200, OK}, {"ZZ", 200, Unknown}, {"", 429, Failed}, {"", 500, Failed}, {"DE", 404, OK}, {"<html>", 200, Unknown},
	}
	for _, c := range cases {
		if got := CountryResult(c.raw, c.status); got.Status != c.want {
			t.Errorf("CountryResult(%q, %d) = %+v, want %s", c.raw, c.status, got, c.want)
		}
	}
}

func TestTruncateKeepsUTF8(t *testing.T) {
	if got := Truncate("абвгд", 5); !utf8.ValidString(got) || got != "аб…" {
		t.Fatalf("Truncate = %q", got)
	}
}

func TestRun(t *testing.T) {
	var gotAuth, gotBody, gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/geo/203.0.113.9":
			gotAuth = r.Header.Get("Authorization")
			w.Write([]byte(`{"country":"SE"}`))
		case "/post":
			b := make([]byte, 64)
			n, _ := r.Body.Read(b)
			gotBody, gotHeader = string(b[:n]), r.Header.Get("X-Client")
			w.Write([]byte(`{"country":"NO"}`))
		case "/blocked":
			w.WriteHeader(http.StatusForbidden)
		default:
			http.Redirect(w, r, "http://elsewhere.invalid/", http.StatusFound)
		}
	}))
	defer srv.Close()
	checks := []Check{
		{Service: "geo", Group: "g", Requests: Get(srv.URL + "/geo/{ip}"), Eval: CountryFrom(JSONPath("country"), 0),
			Authorize: func(req *http.Request, k config.Keys) { req.Header.Set("Authorization", "Bearer "+k.IPinfoToken) }},
		{Service: "post", Group: "g", Tier: TierB, Requests: []Request{{Method: http.MethodPost, URL: srv.URL + "/post", Body: `{"q":1}`, Header: map[string]string{"X-Client": "id"}}},
			Eval: CountryFrom(JSONPath("country"), 0)},
		{Service: "blk", Group: "g", Requests: Get(srv.URL + "/blocked"), Eval: CountryFrom(WholeBody, http.StatusForbidden)},
		{Service: "redir", Group: "g", Requests: Get(srv.URL + "/redir"), Eval: CountryFrom(WholeBody, 0)},
		{Service: "v6only", Group: "g", Transport: netx.IPv6, Requests: Get(srv.URL + "/x"), Eval: CountryFrom(WholeBody, 0)},
	}
	keys := config.Keys{IPinfoToken: "T"}
	checks = Select("m", checks, keys, true)
	led := ledger.New()
	n := netx.New(netx.Options{}, netx.NewPolicy(Rules(checks)...), led)
	env := Env{Nets: map[netx.Family]*netx.Net{netx.IPv4: n}, Keys: keys}
	res := Run(context.Background(), env, netx.IPv4, netip.MustParseAddr("203.0.113.9"), checks)
	if len(res) != 5 {
		t.Fatalf("results = %+v", res)
	}
	if res[0].Country != "SE" || gotAuth != "Bearer T" || res[0].Service != "geo" || res[0].Group != "g" || res[0].Extended {
		t.Errorf("geo = %+v auth=%q", res[0], gotAuth)
	}
	if res[1].Country != "NO" || gotBody != `{"q":1}` || gotHeader != "id" || !res[1].Extended {
		t.Errorf("post = %+v body=%q header=%q", res[1], gotBody, gotHeader)
	}
	if res[2].Status != IPBlock {
		t.Errorf("blocked = %+v", res[2])
	}
	if res[3].Status != Failed || !strings.Contains(res[3].Reason, "blocked by policy") {
		t.Errorf("redirect = %+v", res[3])
	}
	if res[4].Status != Failed || !strings.Contains(res[4].Reason, "ipv6") {
		t.Errorf("transport = %+v", res[4])
	}
}

func TestSelect(t *testing.T) {
	checks := []Check{
		{Service: "a"},
		{Service: "b", Tier: TierB},
		{Service: "k", KeyOK: func(k config.Keys) bool { return k.GeoapifyKey != "" }},
	}
	names := func(cs []Check) string {
		var s []string
		for _, c := range cs {
			s = append(s, c.Service)
		}
		return strings.Join(s, ",")
	}
	if got := names(Select("m", checks, config.Keys{}, false)); got != "a" {
		t.Errorf("default = %s", got)
	}
	sel := Select("m", checks, config.Keys{GeoapifyKey: "x"}, true)
	if got := names(sel); got != "a,b,k" || sel[0].Module != "m" {
		t.Errorf("extended+key = %s", got)
	}
}

func TestRunBodyFrom(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/page":
			w.Write([]byte("token=abc"))
		case "/gone":
			w.WriteHeader(http.StatusTooManyRequests)
		case "/query":
			b := make([]byte, 64)
			n, _ := r.Body.Read(b)
			gotBody = string(b[:n])
			w.Write([]byte(`{"country":"FI"}`))
		}
	}))
	defer srv.Close()
	chain := func(fail bool) Check {
		eval := CountryFrom(JSONPath("country"), 0)
		return Check{Service: "chain", Group: "g", Eval: func(rs []*Response) []Result { return eval(rs[1:]) }, Requests: []Request{
			{URL: srv.URL + "/page"},
			{Method: http.MethodPost, URL: srv.URL + "/query", BodyFrom: func(ip netip.Addr, prev []*Response) (string, error) {
				if fail {
					return "", errors.New("no token on the page")
				}
				return "ip=" + ip.String() + "&" + string(prev[0].Body), nil
			}},
		}}
	}
	gone := chain(false)
	gone.Requests = []Request{{URL: srv.URL + "/gone"}, gone.Requests[1]}
	checks := Select("m", []Check{chain(false), chain(true), gone}, config.Keys{}, false)
	n := netx.New(netx.Options{}, netx.NewPolicy(Rules(checks)...), ledger.New())
	res := Run(context.Background(), Env{Nets: map[netx.Family]*netx.Net{netx.IPv4: n}}, netx.IPv4, netip.MustParseAddr("203.0.113.9"), checks)
	if len(res) != 3 || res[0].Country != "FI" || gotBody != "ip=203.0.113.9&token=abc" {
		t.Errorf("chain = %+v body=%q", res, gotBody)
	}
	if res[1].Status != Unknown || res[1].Reason != "no token on the page" {
		t.Errorf("failed chain = %+v", res[1])
	}
	if res[2].Status != Failed || res[2].Reason != "rate limited" {
		t.Errorf("failed prerequisite = %+v", res[2])
	}
}

func TestChallenged(t *testing.T) {
	page := `<!DOCTYPE html><html><head><title>Just a moment...</title><script>window._cf_chl_opt={}</script>`
	for _, c := range []struct {
		r    Response
		want bool
	}{
		{Response{Status: 403, Body: []byte(page)}, true},
		{Response{Status: 503, Header: http.Header{"Cf-Mitigated": {"challenge"}}}, true},
		{Response{Status: 200, Body: []byte(`<script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>`)}, false},
		{Response{Status: 403, Body: []byte(`<title>Attention Required! | Cloudflare</title>Sorry, you have been blocked`)}, false},
	} {
		if got := Challenged(&c.r); got != c.want {
			t.Errorf("Challenged(%d %q) = %v", c.r.Status, c.r.Body, got)
		}
	}
}
