package risk

import (
	"net/http"
	"strings"
	"testing"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

func resp(status int, body string) []*probe.Response {
	return []*probe.Response{{Status: status, Header: http.Header{}, Body: []byte(body)}}
}

func one(t *testing.T, rs []probe.Result) probe.Result {
	t.Helper()
	if len(rs) != 1 {
		t.Fatalf("got %d results", len(rs))
	}
	return rs[0]
}

func TestChecksSelection(t *testing.T) {
	cs := Checks(config.Keys{}, false)
	if len(cs) != 1 || cs[0].Service != "proxycheck.io" || cs[0].Module != Module {
		t.Fatalf("keyless checks = %+v", cs)
	}
	cs = Checks(config.Keys{IPAPIisKey: "a", AbuseIPDBKey: "b", IPQSKey: "c", IPDataKey: "d"}, false)
	if len(cs) != 5 {
		t.Fatalf("keyed checks = %d", len(cs))
	}
	for _, r := range probe.Rules(cs) {
		if r.Module != Module || strings.ContainsAny(r.Pattern, "{}") {
			t.Errorf("bad rule %+v", r)
		}
	}
	for _, c := range cs {
		for _, r := range c.Requests {
			for _, k := range []string{"=a", "=b", "/c/", "=d"} {
				if strings.Contains(r.URL, k) {
					t.Errorf("%s: key in request template %s", c.Service, r.URL)
				}
			}
		}
	}
}

func authorized(t *testing.T, c probe.Check, ip string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, strings.ReplaceAll(c.Requests[0].URL, "{ip}", ip), nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Authorize(req, config.Keys{})
	return req
}

func TestAuthorize(t *testing.T) {
	req := authorized(t, ipqs("se/cret"), "2001:db8::1")
	if req.URL.Path != "/api/json/ip/se/cret/2001:db8::1" || !strings.Contains(req.URL.String(), "/se%2Fcret/") {
		t.Errorf("ipqs url = %s", req.URL)
	}
	req = authorized(t, ipdata("k1"), "1.2.3.4")
	if req.URL.Query().Get("api-key") != "k1" || strings.Contains(netx.StripSecrets(req.URL.String()), "k1") {
		t.Errorf("ipdata url = %s", req.URL)
	}
	req = authorized(t, ipapiIs("k2"), "1.2.3.4")
	if req.URL.Query().Get("key") != "k2" || req.URL.Query().Get("q") != "1.2.3.4" {
		t.Errorf("ipapi.is url = %s", req.URL)
	}
	req = authorized(t, abuseIPDB("k3"), "1.2.3.4")
	if req.Header.Get("Key") != "k3" {
		t.Errorf("abuseipdb header missing")
	}
	req = authorized(t, proxyCheck(""), "1.2.3.4")
	if req.URL.Query().Has("key") || req.URL.Query().Get("vpn") != "1" {
		t.Errorf("keyless proxycheck url = %s", req.URL)
	}
}

func TestProxyCheck(t *testing.T) {
	clean := `{"status":"ok","1.1.1.1":{"asn":"AS13335","isocode":"AU","proxy":"no","type":"Business","risk":0}}`
	r := one(t, evalProxyCheck(resp(200, clean)))
	if r.Status != probe.Yes || r.Country != "AU" || r.Detail != "Business; risk 0" {
		t.Errorf("clean = %+v", r)
	}
	vpn := `{"status":"ok","2001:db8::1":{"isocode":"NL","proxy":"yes","type":"VPN","risk":66}}`
	r = one(t, evalProxyCheck(resp(200, vpn)))
	if r.Status != probe.No || r.Detail != "VPN; risk 66" {
		t.Errorf("vpn = %+v", r)
	}
	r = one(t, evalProxyCheck(resp(200, `{"status":"denied","message":"1000 free queries exhausted"}`)))
	if r.Status != probe.Failed || !strings.Contains(r.Reason, "exhausted") {
		t.Errorf("denied = %+v", r)
	}
}

func TestIPAPIis(t *testing.T) {
	full := `{"ip":"107.174.138.172","is_datacenter":true,"is_tor":true,"is_proxy":false,"is_vpn":true,"is_abuser":true,
		"vpn":{"service":"NordVPN"},"datacenter":{"datacenter":"HostPapa"},
		"company":{"type":"business","abuser_score":"0.1016 (High)"},"location":{"country_code":"US"}}`
	r := one(t, evalIPAPIis(resp(200, full)))
	if r.Status != probe.No || r.Country != "US" || !strings.HasPrefix(r.Detail, "VPN (NordVPN), Tor, abuser; datacenter HostPapa") {
		t.Errorf("full = %+v", r)
	}
	anon := `{"ip":"1.1.1.1","is_bogon":false,"company":"APNIC","asn":"AS13335 Cloudflare, Inc.","country":"Australia","docs":"https://ipapi.is/free-tier.html?ref=api"}`
	if r := one(t, evalIPAPIis(resp(200, anon))); r.Status != probe.Unknown {
		t.Errorf("anonymous = %+v", r)
	}
	bad := `{"error":"Invalid API key","error_code":"ERR_FORBIDDEN_INVALID_API_KEY"}`
	if r := one(t, evalIPAPIis(resp(403, bad))); r.Status != probe.Failed || !strings.HasPrefix(r.Reason, "key rejected") {
		t.Errorf("bad key = %+v", r)
	}
}

func TestAbuseIPDB(t *testing.T) {
	ok := `{"data":{"ipAddress":"1.2.3.4","abuseConfidenceScore":0,"countryCode":"DE","usageType":"Data Center/Web Hosting/Transit","isTor":false,"totalReports":2}}`
	r := one(t, evalAbuseIPDB(resp(200, ok)))
	if r.Status != probe.Yes || r.Country != "DE" || r.Detail != "confidence 0%; 2 reports in 90 days; Data Center/Web Hosting/Transit" {
		t.Errorf("clean = %+v", r)
	}
	bad := `{"data":{"abuseConfidenceScore":100,"countryCode":"CN","isTor":true,"totalReports":900}}`
	if r := one(t, evalAbuseIPDB(resp(200, bad))); r.Status != probe.No || !strings.HasPrefix(r.Detail, "Tor, abuse reports") {
		t.Errorf("flagged = %+v", r)
	}
	unauth := `{"errors":[{"detail":"Authentication failed.","status":401}]}`
	if r := one(t, evalAbuseIPDB(resp(401, unauth))); r.Status != probe.Failed || r.Reason != "key rejected (HTTP 401): Authentication failed." {
		t.Errorf("unauth = %+v", r)
	}
}

func TestIPQS(t *testing.T) {
	ok := `{"success":true,"fraud_score":88,"country_code":"US","proxy":true,"vpn":true,"tor":false,"recent_abuse":false,"connection_type":"Data Center"}`
	r := one(t, evalIPQS(resp(200, ok)))
	if r.Status != probe.No || r.Detail != "VPN, high fraud score; fraud score 88; Data Center" {
		t.Errorf("flagged = %+v", r)
	}
	bad := `{"success":false,"message":"Invalid or unauthorized key. Please check the API key and try again."}`
	if r := one(t, evalIPQS(resp(200, bad))); r.Status != probe.Failed || !strings.Contains(r.Reason, "Invalid or unauthorized key") {
		t.Errorf("bad key = %+v", r)
	}
}

func TestIPData(t *testing.T) {
	ok := `{"ip":"1.2.3.4","country_code":"FR","asn":{"type":"isp"},"threat":{"is_tor":false,"is_proxy":false,"is_datacenter":false,"is_anonymous":false,"is_known_attacker":false,"is_known_abuser":false,"is_threat":false,"blocklists":[]}}`
	r := one(t, evalIPData(resp(200, ok)))
	if r.Status != probe.Yes || r.Country != "FR" || r.Detail != "ASN type isp" {
		t.Errorf("clean = %+v", r)
	}
	bad := `{"country_code":"RU","threat":{"is_known_abuser":true,"is_threat":true,"is_datacenter":true,"blocklists":[{"name":"FireHOL"}]}}`
	if r := one(t, evalIPData(resp(200, bad))); r.Status != probe.No || r.Detail != "known abuser; datacenter; blocklists: FireHOL" {
		t.Errorf("flagged = %+v", r)
	}
	if r := one(t, evalIPData(resp(401, `{"message":"You have not provided a valid API Key."}`))); r.Status != probe.Failed {
		t.Errorf("unauth = %+v", r)
	}
}
