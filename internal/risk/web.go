package risk

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/arngory/cii/internal/probe"
)

var webChecks = []probe.Check{
	{Service: "ipinfo.io", Group: Reputation, Tier: probe.TierB,
		Requests: probe.Get("https://ipinfo.io/widget/demo/{ip}"), Eval: evalIPinfoDemo},
	{Service: "Scamalytics", Group: Reputation, Tier: probe.TierB,
		Requests: probe.Get("https://scamalytics.com/ip/{ip}"), Eval: evalScamalytics},
	{Service: "ip2location.com", Group: Reputation, Tier: probe.TierB,
		Requests: []probe.Request{
			{URL: ip2locationPage},
			{Method: http.MethodPost, URL: "https://api.ip2location.io/query/", BodyFrom: ip2locationQuery,
				Header: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}},
		},
		Eval: evalIP2LocationWeb},
}

const ip2locationPage = "https://www.ip2location.com/"

func pageFailure(r *probe.Response) []probe.Result {
	if res, failed := probe.HTTPFailure(r.Status); failed {
		return []probe.Result{res}
	}
	return []probe.Result{{Status: probe.Failed, Reason: "unexpected response"}}
}

func evalIPinfoDemo(rs []*probe.Response) []probe.Result {
	r := rs[0]
	var d struct {
		Data *struct {
			Country string `json:"country"`
			ASN     *struct {
				Type string `json:"type"`
			} `json:"asn"`
			Company *struct {
				Type string `json:"type"`
			} `json:"company"`
			Privacy *struct {
				VPN     bool   `json:"vpn"`
				Proxy   bool   `json:"proxy"`
				Tor     bool   `json:"tor"`
				Relay   bool   `json:"relay"`
				Hosting bool   `json:"hosting"`
				Service string `json:"service"`
			} `json:"privacy"`
			IsMobile bool `json:"is_mobile"`
		} `json:"data"`
	}
	err := json.Unmarshal(r.Body, &d)
	if r.Status >= 400 || err != nil || d.Data == nil {
		return pageFailure(r)
	}
	p := d.Data.Privacy
	if p == nil {
		return []probe.Result{{Status: probe.Unknown, Reason: "answer without privacy flags"}}
	}
	v := verdict{country: d.Data.Country}
	vpn := "VPN"
	if p.Service != "" {
		vpn += " (" + p.Service + ")"
	}
	v.mark(probe.VPN, p.VPN, vpn)
	v.mark(probe.Proxy, p.Proxy, "proxy")
	v.mark(probe.Tor, p.Tor, "Tor")
	v.facts.Set(probe.Hosting, p.Hosting)
	v.note(p.Hosting, "hosting")
	v.note(p.Relay, "privacy relay")
	if d.Data.ASN != nil {
		v.facts.SetUsage(d.Data.ASN.Type)
		v.note(d.Data.ASN.Type != "", "ASN type "+d.Data.ASN.Type)
	}
	if d.Data.Company != nil {
		v.facts.SetCompany(d.Data.Company.Type)
	}
	if d.Data.IsMobile {
		v.facts.Usage = "mobile"
		v.note(true, "mobile")
	}
	return v.result()
}

var (
	scamScore   = regexp.MustCompile(`Fraud Score:\s*(\d+)`)
	scamRisk    = regexp.MustCompile(`"risk"\s*:\s*"([a-z ]+)"`)
	scamCountry = regexp.MustCompile(`<th>Country Code</th>\s*<td>([A-Za-z]{2})</td>`)
	scamConn    = regexp.MustCompile(`<th>Connection type</th>\s*<td>([^<]*)</td>`)
	scamRow     = regexp.MustCompile(`<th>([^<]+)</th>\s*<td>\s*<div class="risk[^"]*">\s*(Yes|No)\s*</div>`)

	scamFlags = map[string]probe.Flag{
		"anonymizing vpn": probe.VPN, "vpn": probe.VPN,
		"tor exit node": probe.Tor,
		"server":        probe.Hosting, "datacenter": probe.Hosting,
		"public proxy": probe.Proxy, "web proxy": probe.Proxy, "residential proxy": probe.Proxy,
		"search engine robot": probe.Bot,
	}
	scamLists = map[string]bool{"firehol": true, "ip2proxylite": true, "ipsum": true, "spamhaus": true, "x4bnet spambot": true}
)

func evalScamalytics(rs []*probe.Response) []probe.Result {
	r := rs[0]
	m := scamScore.FindSubmatch(r.Body)
	if m == nil {
		if r.Status >= 400 && strings.Contains(string(r.Body), "challenge-platform") {
			return []probe.Result{{Status: probe.Failed, Reason: "Cloudflare challenge"}}
		}
		if res, failed := probe.HTTPFailure(r.Status); failed {
			return []probe.Result{res}
		}
		return []probe.Result{{Status: probe.Unknown, Reason: "page layout not recognised"}}
	}
	score, _ := strconv.Atoi(string(m[1]))
	risk := ""
	if rm := scamRisk.FindSubmatch(r.Body); rm != nil {
		risk = string(rm[1])
	}
	v := verdict{}
	if cm := scamCountry.FindSubmatch(r.Body); cm != nil {
		v.country = string(cm[1])
	}
	flags := map[probe.Flag]bool{}
	var lists []string
	for _, row := range scamRow.FindAllSubmatch(r.Body, -1) {
		name, yes := strings.ToLower(strings.TrimSpace(string(row[1]))), string(row[2]) == "Yes"
		if f, ok := scamFlags[name]; ok {
			flags[f] = flags[f] || yes
		}
		if scamLists[name] {
			flags[probe.Abuser] = flags[probe.Abuser] || yes
			if yes {
				lists = append(lists, strings.TrimSpace(string(row[1])))
			}
		}
	}
	names := map[probe.Flag]string{probe.VPN: "VPN", probe.Tor: "Tor", probe.Proxy: "proxy", probe.Bot: "search engine robot", probe.Abuser: "blacklisted"}
	for _, f := range probe.Flags {
		on, ok := flags[f]
		switch {
		case !ok:
		case f == probe.Hosting:
			v.facts.Set(f, on)
			v.note(on, "server")
		default:
			v.mark(f, on, names[f])
		}
	}
	v.flag(risk == "high" || risk == "very high", "high risk")
	v.note(true, "fraud score "+strconv.Itoa(score))
	v.note(risk != "", "risk "+risk)
	v.note(len(lists) > 0, "lists: "+strings.Join(lists, ", "))
	v.facts.SetScore(float64(score))
	if cm := scamConn.FindSubmatch(r.Body); cm != nil {
		v.facts.SetUsage(string(cm[1]))
	}
	return v.result()
}

var ip2locationToken = regexp.MustCompile(`ip:\s*'([^']+)',\s*t:\s*(\d+),\s*token:\s*'([0-9A-Fa-f]+)'`)

func ip2locationQuery(ip netip.Addr, prev []*probe.Response) (string, error) {
	m := ip2locationToken.FindSubmatch(prev[0].Body)
	if m == nil {
		return "", errors.New("lookup token not found on the page")
	}
	shown, err := netip.ParseAddr(string(m[1]))
	if err != nil || shown.Unmap() != ip.Unmap() {
		return "", errors.New("the page shows another address")
	}
	return url.Values{"ip": {string(m[1])}, "t": {string(m[2])}, "token": {string(m[3])}}.Encode(), nil
}

var ip2locationProxyTypes = map[string]probe.Flag{"VPN": probe.VPN, "TOR": probe.Tor, "DCH": probe.Hosting, "SES": probe.Bot}

func evalIP2LocationWeb(rs []*probe.Response) []probe.Result {
	r := rs[len(rs)-1]
	var d struct {
		CountryCode string `json:"countryCode"`
		UsageType   string `json:"usageType"`
		ASUsageType string `json:"asUsageType"`
		FraudScore  string `json:"fraudScore"`
		IsProxy     string `json:"isProxy"`
		ProxyType   string `json:"proxyType"`
		Threat      string `json:"threat"`
	}
	err := json.Unmarshal(r.Body, &d)
	if r.Status >= 400 || err != nil {
		return pageFailure(r)
	}
	known := func(s string) bool { return s != "" && s != "-" }
	if !known(d.IsProxy) && !known(d.FraudScore) && !known(d.UsageType) {
		return []probe.Result{{Status: probe.Unknown, Reason: "empty answer (lookup token not accepted)"}}
	}
	v := verdict{}
	if known(d.CountryCode) {
		v.country = d.CountryCode
	}
	usage := d.UsageType
	if !known(usage) {
		usage = d.ASUsageType
	}
	if known(usage) {
		v.facts.SetUsage(usage)
		v.note(true, usage)
	}
	dc := probe.NormalizeUsage(usage) == "hosting"
	if known(d.IsProxy) {
		isProxy := strings.EqualFold(d.IsProxy, "yes")
		typ := strings.ToUpper(strings.TrimSpace(d.ProxyType))
		typed, isTyped := ip2locationProxyTypes[typ]
		v.mark(probe.VPN, isProxy && typed == probe.VPN, "VPN")
		v.mark(probe.Tor, isProxy && typed == probe.Tor, "Tor")
		v.mark(probe.Bot, isProxy && typed == probe.Bot, "search engine spider")
		v.mark(probe.Proxy, isProxy && !isTyped, "proxy")
		dc = dc || isProxy && typed == probe.Hosting
		v.note(isProxy && typed == probe.Hosting, "data center range")
		v.note(isProxy && known(d.ProxyType), "proxy type "+d.ProxyType)
	}
	if known(d.IsProxy) || known(usage) {
		v.facts.Set(probe.Hosting, dc)
	}
	if known(d.Threat) || known(d.IsProxy) {
		v.mark(probe.Abuser, known(d.Threat), "threat "+d.Threat)
	}
	if score, err := strconv.Atoi(strings.TrimSpace(d.FraudScore)); err == nil {
		v.flag(score >= 75, "high fraud score")
		v.note(true, "fraud score "+strconv.Itoa(score))
		v.facts.SetScore(float64(score))
	}
	return v.result()
}
