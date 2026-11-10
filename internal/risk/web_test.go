package risk

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/probe"
)

func TestWebChecksAreExtendedOnly(t *testing.T) {
	names := func(cs []probe.Check) string {
		var s []string
		for _, c := range cs {
			s = append(s, c.Service)
		}
		return strings.Join(s, ",")
	}
	if got := names(Checks(config.Keys{}, false)); got != "proxycheck.io" {
		t.Errorf("default checks = %s", got)
	}
	if got := names(Checks(config.Keys{}, true)); got != "proxycheck.io,ipinfo.io,Scamalytics,ip2location.com" {
		t.Errorf("extended checks = %s", got)
	}
	hosts := map[string]bool{}
	for _, r := range probe.Rules(Checks(config.Keys{}, true)) {
		hosts[r.Pattern] = true
	}
	for _, h := range []string{"ipinfo.io", "scamalytics.com", "www.ip2location.com", "api.ip2location.io"} {
		if !hosts[h] {
			t.Errorf("%s not declared", h)
		}
	}
}

func TestIPinfoDemo(t *testing.T) {
	res := one(t, evalIPinfoDemo(resp(200, `{"input":"203.0.113.7","data":{"ip":"203.0.113.7","country":"DE",
		"asn":{"asn":"AS64500","type":"isp"},"company":{"type":"business"},
		"privacy":{"vpn":true,"proxy":false,"tor":false,"relay":false,"hosting":false,"service":"ExampleVPN"},"is_mobile":false}}`)))
	f := res.Facts
	if res.Status != probe.No || res.Country != "DE" || !strings.Contains(res.Detail, "VPN (ExampleVPN)") ||
		f.Usage != "isp" || f.Company != "business" || !f.Flags[probe.VPN] || f.Flags[probe.Hosting] || len(f.Flags) != 4 {
		t.Errorf("ipinfo demo = %+v facts %+v", res, f)
	}
	if res := one(t, evalIPinfoDemo(resp(200, `{"data":{"country":"DE"}}`))); res.Status != probe.Unknown {
		t.Errorf("without privacy = %+v", res)
	}
	if res := one(t, evalIPinfoDemo(resp(429, `{"error":"rate limit"}`))); res.Status != probe.Failed || res.Reason != "rate limited" {
		t.Errorf("rate limited = %+v", res)
	}
	if res := one(t, evalIPinfoDemo(resp(403, `forbidden`))); res.Status != probe.Failed || res.Reason != "HTTP 403" {
		t.Errorf("forbidden = %+v", res)
	}
}

const scamPage = `<title>203.0.113.7 Fraud Risk</title>
<div class="score">Fraud Score: 37</div>
<pre>
      "ip":"203.0.113.7",
      "score":"37",
      "risk":"medium",
</pre>
<table>
<tr><th>Connection type</th>
    <td>Fixed Line ISP</td></tr>
<tr><th>Country Code</th>
    <td>DE</td></tr>
<tr><th>Datacenter</th>
    <td><div class="risk stretch no">No</div></td></tr>
<tr><th>VPN</th>
    <td><div class="risk stretch "></div></td></tr>
<tr><th>Spamhaus</th>
    <td><div class="risk yes">Yes</div></td></tr>
<tr><th>Firehol</th>
    <td><div class="risk no">No</div></td></tr>
<tr><th>Anonymizing VPN</th>
    <td><div class="risk no">No</div></td></tr>
<tr><th>Tor Exit Node</th>
    <td><div class="risk no">No</div></td></tr>
<tr><th>Server</th>
    <td><div class="risk yes">Yes</div></td></tr>
<tr><th>Public Proxy</th>
    <td><div class="risk no">No</div></td></tr>
<tr><th>Search Engine Robot</th>
    <td><div class="risk no">No</div></td></tr>
</table>`

func TestScamalytics(t *testing.T) {
	res := one(t, evalScamalytics(resp(200, scamPage)))
	f := res.Facts
	if res.Status != probe.No || res.Country != "DE" || !strings.Contains(res.Detail, "blacklisted") || !strings.Contains(res.Detail, "lists: Spamhaus") ||
		*f.Score != 37 || f.Usage != "isp" || !f.Flags[probe.Abuser] || !f.Flags[probe.Hosting] || f.Flags[probe.VPN] || len(f.Flags) != 6 {
		t.Errorf("scamalytics = %+v facts %+v", res, f)
	}
	clean := strings.NewReplacer(`"risk yes">Yes`, `"risk no">No`, `"risk":"medium"`, `"risk":"low"`).Replace(scamPage)
	if res := one(t, evalScamalytics(resp(200, clean))); res.Status != probe.Yes || res.Facts.Flags[probe.Abuser] {
		t.Errorf("clean scamalytics = %+v", res)
	}
	high := strings.Replace(clean, `"risk":"low"`, `"risk":"very high"`, 1)
	if res := one(t, evalScamalytics(resp(200, high))); res.Status != probe.No || !strings.Contains(res.Detail, "high risk") {
		t.Errorf("high risk = %+v", res)
	}
	if res := one(t, evalScamalytics(resp(403, `<title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/x"></script>`))); res.Status != probe.Failed || res.Reason != "Cloudflare challenge" {
		t.Errorf("challenge = %+v", res)
	}
	if res := one(t, evalScamalytics(resp(200, `<html>redesigned</html>`))); res.Status != probe.Unknown {
		t.Errorf("unknown layout = %+v", res)
	}
}

func TestIP2LocationWeb(t *testing.T) {
	page := []*probe.Response{{Status: 200, Body: []byte(`$.post('https://api.ip2location.io/query/', {
							ip: '203.0.113.7',
							t: 1700000000,
							token: '0123456789abcdef',
						}, function(json) {`)}}
	body, err := ip2locationQuery(netip.MustParseAddr("203.0.113.7"), page)
	if err != nil || body != "ip=203.0.113.7&t=1700000000&token=0123456789abcdef" {
		t.Errorf("query body = %q, %v", body, err)
	}
	if _, err := ip2locationQuery(netip.MustParseAddr("198.51.100.1"), page); err == nil || strings.Contains(err.Error(), "203.0") {
		t.Errorf("other address error = %v", err)
	}
	if _, err := ip2locationQuery(netip.MustParseAddr("203.0.113.7"), []*probe.Response{{Status: 200, Body: []byte("<html></html>")}}); err == nil {
		t.Error("page without token accepted")
	}

	answer := func(body string) []*probe.Response { return append(page, resp(200, body)...) }
	res := one(t, evalIP2LocationWeb(answer(`{"countryCode":"DE","usageType":"Fixed Line ISP","fraudScore":"40","isProxy":"Yes","proxyType":"VPN","threat":"-","asUsageType":"Fixed Line ISP"}`)))
	f := res.Facts
	if res.Status != probe.No || res.Country != "DE" || !f.Flags[probe.VPN] || f.Flags[probe.Proxy] || f.Flags[probe.Abuser] || *f.Score != 40 || f.Usage != "isp" || len(f.Flags) != 6 {
		t.Errorf("ip2location vpn = %+v facts %+v", res, f)
	}
	res = one(t, evalIP2LocationWeb(answer(`{"countryCode":"DE","usageType":"Data Center/Web Hosting/Transit","fraudScore":"3","isProxy":"Yes","proxyType":"DCH","threat":"-"}`)))
	if res.Status != probe.Yes || !res.Facts.Flags[probe.Hosting] || res.Facts.Flags[probe.Proxy] || res.Facts.Usage != "hosting" {
		t.Errorf("ip2location data center = %+v facts %+v", res, res.Facts)
	}
	res = one(t, evalIP2LocationWeb(answer(`{"countryCode":"DE","usageType":"Data Center/Web Hosting/Transit","fraudScore":"1","isProxy":"No","proxyType":"-","threat":"-"}`)))
	if res.Status != probe.Yes || !res.Facts.Flags[probe.Hosting] || res.Facts.Flags[probe.Proxy] {
		t.Errorf("ip2location hosting without proxy = %+v facts %+v", res, res.Facts)
	}
	res = one(t, evalIP2LocationWeb(answer(`{"countryCode":"DE","fraudScore":"0","isProxy":"No","proxyType":"-","threat":"SPAM"}`)))
	if res.Status != probe.No || !res.Facts.Flags[probe.Abuser] || !strings.Contains(res.Detail, "threat SPAM") {
		t.Errorf("ip2location threat = %+v", res)
	}
	if res := one(t, evalIP2LocationWeb(answer(`{"countryCode":"-","usageType":"-","fraudScore":"-","isProxy":"-","proxyType":"-","threat":"-"}`))); res.Status != probe.Unknown {
		t.Errorf("empty answer = %+v", res)
	}
}
