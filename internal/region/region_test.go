package region

import (
	"strings"
	"testing"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/probe"
)

func resp(body string) []*probe.Response {
	return []*probe.Response{{Status: 200, Body: []byte(body)}}
}

func TestRDAP(t *testing.T) {
	top := rdap(resp(`{"country":"ru"}`))
	arin := rdap(resp(`{"country":null,"entities":[
		{"roles":["abuse"],"vcardArray":["vcard",[["adr",{"label":"x\nCanada"},"text",[]]]]},
		{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Google"],["adr",{"label":"1600 Amphitheatre\nCA\nUnited States"},"text",[]]]]}]}`))
	if top[0].Country != "RU" || arin[0].Country != "US" {
		t.Fatalf("rdap = %+v / %+v", top, arin)
	}
}

func TestCloudflareTraceAndYouTubeCDN(t *testing.T) {
	res := cloudflareTrace(resp("fl=1\nip=1.2.3.4\ncolo=FRA\nloc=NL\n"))
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
		if r := youtubeCDN(resp(body))[0]; r.Country != want {
			t.Errorf("youtubeCDN(%q) = %+v, want %q", body, r, want)
		}
	}
}

func TestNetflixFast(t *testing.T) {
	res := netflixFast(resp(`{"client":{"location":{"country":"DE"}},"targets":[{"url":"https://ipv4-c001-fra001-ix.1.oca.nflxvideo.net/speedtest?x","location":{"country":"DE"}}]}`))
	if len(res) != 2 || res[0].Country != "DE" || res[1].Group != CDN || res[1].IATA != "FRA" || res[1].Node != "c001-fra001-ix" || res[1].Country != "DE" {
		t.Fatalf("netflixFast = %+v", res)
	}
}

func TestSummarizeWeightsGroupsEqually(t *testing.T) {
	var results []probe.Result
	for i := 0; i < 6; i++ {
		results = append(results, probe.Result{Group: GeoIP, Service: "g", Status: probe.OK, Country: "US"})
	}
	results = append(results,
		probe.Result{Group: GeoIP, Service: "g7", Status: probe.OK, Country: "DE"},
		probe.Result{Group: Platform, Service: "p1", Status: probe.OK, Country: "DE"},
		probe.Result{Group: CDN, Service: "c", Status: probe.OK, Country: "FR"},
		probe.Result{Group: Platform, Service: "p2", Status: probe.Failed},
	)
	s := Summarize(results)
	if len(s.Verdict) != 1 || s.Verdict[0] != "DE" || len(s.Attention) != 6 {
		t.Fatalf("summary = %+v", s)
	}
	tie := Summarize([]probe.Result{{Group: GeoIP, Status: probe.OK, Country: "US"}, {Group: GeoIP, Status: probe.OK, Country: "DE"}})
	if strings.Join(tie.Verdict, ",") != "DE,US" {
		t.Fatalf("tie = %v", tie.Verdict)
	}
	if v := Summarize(nil).Verdict; v == nil || len(v) != 0 {
		t.Fatalf("empty verdict = %#v", v)
	}
}

func TestYouTubeFallbackCountry(t *testing.T) {
	unlisted := []probe.Result{
		{Group: GeoIP, Service: "a", Status: probe.OK, Country: "XX"},
		{Group: Platform, Service: "Reddit", Status: probe.OK, Country: "XX"},
		{Group: Platform, Service: "YouTube", Status: probe.OK, Country: "US"},
	}
	s := Summarize(unlisted)
	if strings.Join(s.Verdict, ",") != "XX" || len(s.Attention) != 0 || s.Results[2].Status != probe.Unknown {
		t.Fatalf("unlisted country summary = %+v", s)
	}
	us := Summarize([]probe.Result{
		{Group: GeoIP, Service: "a", Status: probe.OK, Country: "US"},
		{Group: Platform, Service: "YouTube", Status: probe.OK, Country: "US"},
	})
	if strings.Join(us.Verdict, ",") != "US" || us.Results[1].Status != probe.OK {
		t.Fatalf("US summary = %+v", us)
	}
}

func TestSelect(t *testing.T) {
	has := func(cs []probe.Check, name string) bool {
		for _, c := range cs {
			if c.Service == name {
				return true
			}
		}
		return false
	}
	if has(Select(config.Keys{}, false), "ipregistry.co") || !has(Select(config.Keys{IPRegistryKey: "k"}, false), "ipregistry.co") {
		t.Error("ipregistry selection ignores key")
	}
	if has(Select(config.Keys{}, false), "Twitch") || !has(Select(config.Keys{}, true), "Twitch") {
		t.Error("tier B selection ignores --extended")
	}
}

func TestFactsFromGeoIPAnswers(t *testing.T) {
	q := ipqueryFacts([]byte(`{"risk":{"is_mobile":true,"is_vpn":false,"is_tor":false,"is_proxy":true,"is_datacenter":false,"risk_score":42}}`))
	if q.Usage != "mobile" || !q.Flags[probe.Proxy] || q.Flags[probe.VPN] || len(q.Flags) != 4 || *q.Score != 42 {
		t.Errorf("ipquery = %+v", q)
	}
	if f := ip2locationFacts([]byte(`{"country_code":"DE","is_proxy":false}`)); len(f.Flags) != 1 || f.Flags[probe.Proxy] {
		t.Errorf("ip2location = %+v", f)
	}
	if f := ip2locationFacts([]byte(`{"country_code":"DE"}`)).OrNil(); f != nil {
		t.Errorf("ip2location without flag = %+v", f)
	}
	a := ipAPIFacts([]byte(`{"status":"success","countryCode":"DE","proxy":false,"hosting":true,"mobile":false}`))
	if a.Usage != "" || !a.Flags[probe.Hosting] || a.Flags[probe.Proxy] || len(a.Flags) != 2 {
		t.Errorf("ip-api = %+v", a)
	}
	r := ipregistryFacts([]byte(`{"connection":{"type":"isp"},"company":{"type":"business"},"security":{"is_abuser":false,"is_attacker":true,"is_cloud_provider":false,"is_proxy":false,"is_tor":false,"is_tor_exit":false,"is_vpn":false}}`))
	if r.Usage != "isp" || r.Company != "business" || !r.Flags[probe.Abuser] || r.Flags[probe.Tor] || len(r.Flags) != 5 {
		t.Errorf("ipregistry = %+v", r)
	}

	c := withFacts(geoip("x", "https://x.example/{ip}", probe.JSONPath("cc")), ipqueryFacts)
	ok := c.Eval(resp(`{"cc":"DE","risk":{"is_vpn":true}}`))
	bad := c.Eval([]*probe.Response{{Status: 500, Body: []byte(`{"risk":{"is_vpn":true}}`)}})
	if ok[0].Country != "DE" || !ok[0].Facts.Flags[probe.VPN] || bad[0].Facts != nil {
		t.Errorf("withFacts = %+v / %+v", ok, bad)
	}
}

func TestRegistryDoesNotVote(t *testing.T) {
	s := Summarize([]probe.Result{
		{Group: GeoIP, Service: "a", Status: probe.OK, Country: "DE"},
		{Group: Registry, Service: "RDAP (RIR)", Status: probe.OK, Country: "US"},
	})
	if strings.Join(s.Verdict, ",") != "DE" || len(s.Attention) != 0 {
		t.Fatalf("summary = %+v", s)
	}
}
