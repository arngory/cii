package region

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
)

func TestJSONPath(t *testing.T) {
	r := &response{Body: []byte(`)]}'
[["x",null,[[["en","DE"]]]]]`)}
	if got := jsonPathAfter(")]}'", "[0][2][0][0][1]")(r); got != "DE" {
		t.Errorf("prefixed path = %q", got)
	}
	r = &response{Body: []byte(`{"data":{"location":{"country":{"alpha2":"NL"}}},"list":[{"c":"FR"}]}`)}
	for path, want := range map[string]string{"data.location.country.alpha2": "NL", "list[0].c": "FR", "list[1].c": "", "data.x.y": "", "list[": ""} {
		if got := jsonPath(path)(r); got != want {
			t.Errorf("jsonPath(%q) = %q, want %q", path, got, want)
		}
	}
	if got := jsonPath("[0].country")(&response{Body: []byte(`[{"country":"US"}]`)}); got != "US" {
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
		if got := countryResult(GeoIP, "x", c.raw, c.status); got.Status != c.want {
			t.Errorf("countryResult(%q, %d) = %+v, want %s", c.raw, c.status, got, c.want)
		}
	}
}

func TestRDAP(t *testing.T) {
	top := rdap(&response{Status: 200, Body: []byte(`{"country":"ru"}`)})
	arin := rdap(&response{Status: 200, Body: []byte(`{"country":null,"entities":[
		{"roles":["abuse"],"vcardArray":["vcard",[["adr",{"label":"x\nCanada"},"text",[]]]]},
		{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Google"],["adr",{"label":"1600 Amphitheatre\nCA\nUnited States"},"text",[]]]]}]}`)})
	if top[0].Country != "RU" || arin[0].Country != "US" {
		t.Fatalf("rdap = %+v / %+v", top, arin)
	}
}

func TestCloudflareTraceAndYouTubeCDN(t *testing.T) {
	res := cloudflareTrace(&response{Status: 200, Body: []byte("fl=1\nip=1.2.3.4\ncolo=FRA\nloc=NL\n")})
	if len(res) != 2 || res[0].Group != Platform || res[0].Country != "NL" || res[1].Group != CDN || res[1].Country != "DE" || res[1].IATA != "FRA" {
		t.Fatalf("cloudflareTrace = %+v", res)
	}
	for body, want := range map[string]string{
		"1.2.3.4 => yyz10s25 (::/0) [D]":     "CA",
		"1.2.3.4 => rostelecom-led1 (x) [D]": "RU",
		"1.2.3.4 => nothing here":            "",
		"1.2.3.4 => 12345 (x) [D]":           "",
		"1.2.3.4 => xxamsa-rt1 (::/0) [ggc]": "NL",
	} {
		r := youtubeCDN(&response{Status: 200, Body: []byte(body)})[0]
		if r.Country != want {
			t.Errorf("youtubeCDN(%q) = %+v, want %q", body, r, want)
		}
	}
}

func TestSummarizeWeightsGroupsEqually(t *testing.T) {
	var results []Result
	for i := 0; i < 6; i++ {
		results = append(results, Result{Group: GeoIP, Service: "g", Status: OK, Country: "US"})
	}
	results = append(results,
		Result{Group: GeoIP, Service: "g7", Status: OK, Country: "DE"},
		Result{Group: Platform, Service: "p1", Status: OK, Country: "DE"},
		Result{Group: CDN, Service: "c", Status: OK, Country: "FR"},
		Result{Group: Platform, Service: "p2", Status: Failed},
	)
	s := Summarize(results)
	if len(s.Verdict) != 1 || s.Verdict[0] != "DE" {
		t.Fatalf("verdict = %v", s.Verdict)
	}
	if len(s.Attention) != 6 {
		t.Fatalf("attention = %+v", s.Attention)
	}
	tie := Summarize([]Result{{Group: GeoIP, Status: OK, Country: "US"}, {Group: GeoIP, Status: OK, Country: "DE"}})
	if strings.Join(tie.Verdict, ",") != "DE,US" {
		t.Fatalf("tie = %v", tie.Verdict)
	}
	if v := Summarize(nil).Verdict; v == nil || len(v) != 0 {
		t.Fatalf("empty verdict = %#v", v)
	}
}

func TestRunUsesPolicyKeysAndTransport(t *testing.T) {
	var gotAuth, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/geo/203.0.113.9":
			gotAuth, gotQuery = r.Header.Get("Authorization"), r.URL.Query().Get("key")
			w.Write([]byte(`{"country":"SE"}`))
		case "/blocked":
			w.WriteHeader(http.StatusForbidden)
		default:
			http.Redirect(w, r, "http://elsewhere.invalid/", http.StatusFound)
		}
	}))
	defer srv.Close()
	checks := []Check{
		{Service: "geo", Group: GeoIP, ByIP: true, URL: srv.URL + "/geo/{ip}", Extract: jsonPath("country"),
			Authorize: func(req *http.Request, k config.Keys) {
				req.Header.Set("Authorization", "Bearer "+k.IPinfoToken)
				setQuery(req, "key", k.IP2LocationKey)
			}},
		{Service: "blk", Group: Platform, URL: srv.URL + "/blocked", BlockStatus: http.StatusForbidden, Extract: wholeBody},
		{Service: "redir", Group: Platform, URL: srv.URL + "/redir", Extract: wholeBody},
		{Service: "v6only", Group: GeoIP, Transport: netx.IPv6, URL: srv.URL + "/x", Extract: wholeBody},
	}
	led := ledger.New()
	n := netx.New(netx.Options{}, netx.NewPolicy(Rules(checks)...), led)
	env := Env{Nets: map[netx.Family]*netx.Net{netx.IPv4: n}, Keys: config.Keys{IPinfoToken: "T", IP2LocationKey: "K"}}
	res := Run(context.Background(), env, netx.IPv4, netip.MustParseAddr("203.0.113.9"), checks)
	if len(res) != 4 {
		t.Fatalf("results = %+v", res)
	}
	if res[0].Country != "SE" || gotAuth != "Bearer T" || gotQuery != "K" {
		t.Errorf("geo = %+v auth=%q key=%q", res[0], gotAuth, gotQuery)
	}
	if res[1].Status != IPBlock {
		t.Errorf("blocked = %+v", res[1])
	}
	if res[2].Status != Failed || !strings.Contains(res[2].Reason, "blocked by policy") {
		t.Errorf("redirect = %+v", res[2])
	}
	if res[3].Status != Failed || !strings.Contains(res[3].Reason, "ipv6") {
		t.Errorf("transport = %+v", res[3])
	}
}

func TestSelectRespectsKeys(t *testing.T) {
	has := func(cs []Check, name string) bool {
		for _, c := range cs {
			if c.Service == name {
				return true
			}
		}
		return false
	}
	if has(Select(config.Keys{}), "ipregistry.co") || !has(Select(config.Keys{IPRegistryKey: "k"}), "ipregistry.co") {
		t.Error("ipregistry selection ignores key")
	}
	if !has(Select(config.Keys{}), "ipinfo.io") {
		t.Error("keyless ipinfo.io missing")
	}
}
