package risk

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/refdata"
)

const Module = "risk"

const (
	Reputation probe.Group = "risk"
	DNSBL      probe.Group = "dnsbl"
	Mail       probe.Group = "mail"
)

func Checks(k config.Keys, extended bool) []probe.Check {
	cs := []probe.Check{proxyCheck(k.ProxyCheckKey)}
	if k.IPAPIisKey != "" {
		cs = append(cs, ipapiIs(k.IPAPIisKey))
	}
	if k.AbuseIPDBKey != "" {
		cs = append(cs, abuseIPDB(k.AbuseIPDBKey))
	}
	if k.IPQSKey != "" {
		cs = append(cs, ipqs(k.IPQSKey))
	}
	if k.IPDataKey != "" {
		cs = append(cs, ipdata(k.IPDataKey))
	}
	return probe.Select(Module, append(cs, webChecks...), k, extended)
}

func queryKey(name, value string) func(*http.Request, config.Keys) {
	return func(req *http.Request, _ config.Keys) {
		if value == "" {
			return
		}
		q := req.URL.Query()
		q.Set(name, value)
		req.URL.RawQuery = q.Encode()
	}
}

func proxyCheck(key string) probe.Check {
	return probe.Check{
		Service:   "proxycheck.io",
		Group:     Reputation,
		Requests:  probe.Get("https://proxycheck.io/v2/{ip}?vpn=1&risk=1"),
		Authorize: queryKey("key", key),
		Eval:      evalProxyCheck,
	}
}

func ipapiIs(key string) probe.Check {
	return probe.Check{
		Service:   "ipapi.is",
		Group:     Reputation,
		Requests:  probe.Get("https://api.ipapi.is/?q={ip}"),
		Authorize: queryKey("key", key),
		Eval:      evalIPAPIis,
	}
}

func abuseIPDB(key string) probe.Check {
	return probe.Check{
		Service: "AbuseIPDB",
		Group:   Reputation,
		Requests: []probe.Request{{
			URL:    "https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
			Header: map[string]string{"Accept": "application/json"},
		}},
		Authorize: func(req *http.Request, _ config.Keys) { req.Header.Set("Key", key) },
		Eval:      evalAbuseIPDB,
	}
}

const ipqsPath = "/api/json/ip/"

func ipqs(key string) probe.Check {
	return probe.Check{
		Service:  "IPQualityScore",
		Group:    Reputation,
		Requests: probe.Get("https://ipqualityscore.com" + ipqsPath + "{ip}?strictness=0&allow_public_access_points=true"),
		Authorize: func(req *http.Request, _ config.Keys) {
			ip := strings.TrimPrefix(req.URL.Path, ipqsPath)
			req.URL.Path = ipqsPath + key + "/" + ip
			req.URL.RawPath = ipqsPath + escapePath(key) + "/" + ip
		},
		Eval: evalIPQS,
	}
}

func escapePath(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func ipdata(key string) probe.Check {
	return probe.Check{
		Service:   "ipdata",
		Group:     Reputation,
		Requests:  probe.Get("https://api.ipdata.co/{ip}?fields=ip,country_code,asn,threat"),
		Authorize: queryKey("api-key", key),
		Eval:      evalIPData,
	}
}

type verdict struct {
	flags   []string
	notes   []string
	country string
	facts   probe.Facts
}

func (v *verdict) flag(on bool, name string) {
	if on {
		v.flags = append(v.flags, name)
	}
}

func (v *verdict) mark(f probe.Flag, on bool, name string) {
	v.flag(on, name)
	v.facts.Set(f, on)
}

func (v *verdict) note(on bool, s string) {
	if on && s != "" {
		v.notes = append(v.notes, s)
	}
}

func (v *verdict) result() []probe.Result {
	r := probe.Result{Status: probe.Yes}
	if len(v.flags) > 0 {
		r.Status = probe.No
	}
	if cc := strings.ToUpper(strings.TrimSpace(v.country)); refdata.IsCountry(cc) {
		r.Country = cc
	}
	parts := v.notes
	if len(v.flags) > 0 {
		parts = append([]string{strings.Join(v.flags, ", ")}, parts...)
	}
	r.Detail = probe.Truncate(strings.Join(parts, "; "), 160)
	r.Facts = v.facts.OrNil()
	return []probe.Result{r}
}

func failure(r *probe.Response, msg string) []probe.Result {
	res := pageFailure(r)[0]
	if r.Status == http.StatusUnauthorized || r.Status == http.StatusForbidden {
		res.Reason = fmt.Sprintf("key rejected (HTTP %d)", r.Status)
	}
	if msg = strings.TrimSpace(msg); msg != "" {
		res.Reason += ": " + probe.Truncate(msg, 100)
	}
	return []probe.Result{res}
}

type number float64

func (n *number) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	*n = number(f)
	return nil
}

func (n number) String() string { return strconv.FormatFloat(float64(n), 'f', -1, 64) }

func evalProxyCheck(rs []*probe.Response) []probe.Result {
	r := rs[0]
	var top map[string]json.RawMessage
	if json.Unmarshal(r.Body, &top) != nil {
		return failure(r, "")
	}
	var status, message string
	json.Unmarshal(top["status"], &status)
	json.Unmarshal(top["message"], &message)
	var e struct {
		Proxy   string  `json:"proxy"`
		VPN     string  `json:"vpn"`
		Type    string  `json:"type"`
		Risk    *number `json:"risk"`
		ISOCode string  `json:"isocode"`
	}
	found := false
	for k, raw := range top {
		if k == "status" || k == "message" || k == "query time" {
			continue
		}
		if json.Unmarshal(raw, &e) == nil && e.Proxy != "" {
			found = true
			break
		}
	}
	if !found || r.Status >= 400 || status == "denied" || status == "error" {
		return failure(r, message)
	}
	typ := strings.ToLower(e.Type)
	v := verdict{country: e.ISOCode}
	v.mark(probe.VPN, typ == "vpn" || strings.EqualFold(e.VPN, "yes"), "VPN")
	v.mark(probe.Tor, typ == "tor", "Tor")
	v.mark(probe.Proxy, strings.EqualFold(e.Proxy, "yes") && typ != "vpn" && typ != "tor", "proxy")
	v.flag(e.Risk != nil && *e.Risk >= 67, "high risk")
	v.note(typ != "vpn" && typ != "tor", e.Type)
	if e.Risk != nil {
		v.note(true, "risk "+e.Risk.String())
		v.facts.SetScore(float64(*e.Risk))
		v.facts.SetLevel(probe.LevelByThresholds(float64(*e.Risk), 1, 34, 67))
	}
	if u := probe.NormalizeUsage(e.Type); u != "" {
		v.facts.Usage = u
		v.facts.Set(probe.Hosting, u == "hosting")
	}
	return v.result()
}

func evalIPAPIis(rs []*probe.Response) []probe.Result {
	r := rs[0]
	var d struct {
		Error        string `json:"error"`
		IsBogon      bool   `json:"is_bogon"`
		IsDatacenter *bool  `json:"is_datacenter"`
		IsVPN        bool   `json:"is_vpn"`
		IsProxy      bool   `json:"is_proxy"`
		IsTor        bool   `json:"is_tor"`
		IsAbuser     bool   `json:"is_abuser"`
		IsCrawler    bool   `json:"is_crawler"`
		IsMobile     bool   `json:"is_mobile"`
		VPN          *struct {
			Service string `json:"service"`
		} `json:"vpn"`
		Datacenter *struct {
			Datacenter string `json:"datacenter"`
		} `json:"datacenter"`
		Company  json.RawMessage `json:"company"`
		ASN      json.RawMessage `json:"asn"`
		Location *struct {
			CountryCode string `json:"country_code"`
		} `json:"location"`
	}
	err := json.Unmarshal(r.Body, &d)
	if r.Status >= 400 || err != nil || d.Error != "" {
		return failure(r, d.Error)
	}
	if d.IsDatacenter == nil {
		return []probe.Result{{Status: probe.Unknown, Reason: "anonymous answer without detection flags (key not accepted)"}}
	}
	v := verdict{}
	if d.Location != nil {
		v.country = d.Location.CountryCode
	}
	vpn := "VPN"
	if d.VPN != nil && d.VPN.Service != "" {
		vpn += " (" + d.VPN.Service + ")"
	}
	v.mark(probe.VPN, d.IsVPN, vpn)
	v.mark(probe.Proxy, d.IsProxy, "proxy")
	v.mark(probe.Tor, d.IsTor, "Tor")
	v.mark(probe.Abuser, d.IsAbuser, "abuser")
	dc := "datacenter"
	if d.Datacenter != nil && d.Datacenter.Datacenter != "" {
		dc += " " + d.Datacenter.Datacenter
	}
	v.note(*d.IsDatacenter, dc)
	v.note(d.IsCrawler, "crawler")
	v.note(d.IsMobile, "mobile")
	v.note(d.IsBogon, "bogon")
	var company struct {
		Type        string `json:"type"`
		AbuserScore string `json:"abuser_score"`
	}
	json.Unmarshal(d.Company, &company)
	v.note(company.Type != "", "company type "+company.Type)
	v.note(company.AbuserScore != "", "abuser score "+company.AbuserScore)
	v.facts.Set(probe.Hosting, *d.IsDatacenter)
	v.facts.Set(probe.Bot, d.IsCrawler)
	v.facts.SetCompany(company.Type)
	var asn struct {
		Type string `json:"type"`
	}
	json.Unmarshal(d.ASN, &asn)
	v.facts.SetUsage(asn.Type)
	if d.IsMobile {
		v.facts.Usage = "mobile"
	}
	if score, err := strconv.ParseFloat(strings.Fields(company.AbuserScore + " x")[0], 64); err == nil {
		v.facts.SetScore(score * 100)
	}
	if _, label, ok := strings.Cut(company.AbuserScore, "("); ok {
		v.facts.SetLevelName(strings.TrimSuffix(label, ")"))
	}
	return v.result()
}

func evalAbuseIPDB(rs []*probe.Response) []probe.Result {
	r := rs[0]
	var d struct {
		Data *struct {
			Score         *number `json:"abuseConfidenceScore"`
			CountryCode   string  `json:"countryCode"`
			UsageType     string  `json:"usageType"`
			IsTor         bool    `json:"isTor"`
			IsWhitelisted *bool   `json:"isWhitelisted"`
			TotalReports  number  `json:"totalReports"`
		} `json:"data"`
		Errors []struct {
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	json.Unmarshal(r.Body, &d)
	if r.Status >= 400 || d.Data == nil || d.Data.Score == nil {
		msg := ""
		if len(d.Errors) > 0 {
			msg = d.Errors[0].Detail
		}
		return failure(r, msg)
	}
	x := d.Data
	v := verdict{country: x.CountryCode}
	v.mark(probe.Tor, x.IsTor, "Tor")
	v.mark(probe.Abuser, *x.Score >= 25, "abuse reports")
	v.note(true, "confidence "+x.Score.String()+"%")
	v.note(true, x.TotalReports.String()+" reports in 90 days")
	v.note(x.UsageType != "", x.UsageType)
	v.note(x.IsWhitelisted != nil && *x.IsWhitelisted, "whitelisted")
	v.facts.SetScore(float64(*x.Score))
	v.facts.SetLevel(probe.LevelByThresholds(float64(*x.Score), 1, 25, 75, 100))
	v.facts.SetUsage(x.UsageType)
	return v.result()
}

func evalIPQS(rs []*probe.Response) []probe.Result {
	r := rs[0]
	var d struct {
		Success        bool    `json:"success"`
		Message        string  `json:"message"`
		FraudScore     *number `json:"fraud_score"`
		CountryCode    string  `json:"country_code"`
		Proxy          bool    `json:"proxy"`
		VPN            bool    `json:"vpn"`
		Tor            bool    `json:"tor"`
		ActiveVPN      bool    `json:"active_vpn"`
		ActiveTor      bool    `json:"active_tor"`
		RecentAbuse    bool    `json:"recent_abuse"`
		BotStatus      bool    `json:"bot_status"`
		ConnectionType string  `json:"connection_type"`
		Mobile         bool    `json:"mobile"`
	}
	if json.Unmarshal(r.Body, &d) != nil || !d.Success || d.FraudScore == nil {
		return failure(r, d.Message)
	}
	v := verdict{country: d.CountryCode}
	v.mark(probe.VPN, d.VPN || d.ActiveVPN, "VPN")
	v.mark(probe.Tor, d.Tor || d.ActiveTor, "Tor")
	v.mark(probe.Proxy, d.Proxy && !d.VPN && !d.ActiveVPN && !d.Tor && !d.ActiveTor, "proxy")
	v.mark(probe.Abuser, d.RecentAbuse, "recent abuse")
	v.mark(probe.Bot, d.BotStatus, "bot")
	v.flag(*d.FraudScore >= 75, "high fraud score")
	v.note(true, "fraud score "+d.FraudScore.String())
	v.note(d.ConnectionType != "", d.ConnectionType)
	v.facts.SetScore(float64(*d.FraudScore))
	v.facts.SetLevel(probe.LevelByThresholds(float64(*d.FraudScore), 25, 75, 85, 90))
	v.facts.SetUsage(d.ConnectionType)
	if d.Mobile {
		v.facts.Usage = "mobile"
	}
	return v.result()
}

func evalIPData(rs []*probe.Response) []probe.Result {
	r := rs[0]
	var d struct {
		Message     string `json:"message"`
		CountryCode string `json:"country_code"`
		ASN         *struct {
			Type string `json:"type"`
		} `json:"asn"`
		Threat *struct {
			IsTor         bool  `json:"is_tor"`
			IsICloudRelay bool  `json:"is_icloud_relay"`
			IsProxy       bool  `json:"is_proxy"`
			IsDatacenter  bool  `json:"is_datacenter"`
			IsAnonymous   bool  `json:"is_anonymous"`
			IsKnownAttack bool  `json:"is_known_attacker"`
			IsKnownAbuser bool  `json:"is_known_abuser"`
			IsThreat      bool  `json:"is_threat"`
			IsBogon       bool  `json:"is_bogon"`
			IsVPN         *bool `json:"is_vpn"`
			Scores        *struct {
				Threat *number `json:"threat_score"`
			} `json:"scores"`
			Blocklists []struct {
				Name string `json:"name"`
			} `json:"blocklists"`
		} `json:"threat"`
	}
	json.Unmarshal(r.Body, &d)
	if r.Status >= 400 || d.Threat == nil {
		return failure(r, d.Message)
	}
	t := d.Threat
	v := verdict{country: d.CountryCode}
	v.mark(probe.Tor, t.IsTor, "Tor")
	v.mark(probe.Proxy, t.IsProxy, "proxy")
	v.flag(t.IsAnonymous && !t.IsTor && !t.IsProxy && !t.IsICloudRelay, "anonymous")
	v.mark(probe.Abuser, t.IsKnownAttack, "known attacker")
	v.mark(probe.Abuser, t.IsKnownAbuser, "known abuser")
	v.flag(t.IsThreat && !t.IsKnownAttack && !t.IsKnownAbuser, "threat")
	v.note(t.IsICloudRelay, "iCloud Private Relay")
	v.note(t.IsDatacenter, "datacenter")
	v.note(t.IsBogon, "bogon")
	if d.ASN != nil {
		v.note(d.ASN.Type != "", "ASN type "+d.ASN.Type)
	}
	if len(t.Blocklists) > 0 {
		names := make([]string, 0, len(t.Blocklists))
		for _, b := range t.Blocklists {
			names = append(names, b.Name)
		}
		v.note(true, "blocklists: "+strings.Join(names, ", "))
	}
	v.facts.SetIf(probe.VPN, t.IsVPN)
	v.facts.Set(probe.Hosting, t.IsDatacenter)
	if d.ASN != nil {
		v.facts.SetUsage(d.ASN.Type)
	}
	if t.Scores != nil && t.Scores.Threat != nil {
		v.facts.SetScore(float64(*t.Scores.Threat))
	}
	return v.result()
}
