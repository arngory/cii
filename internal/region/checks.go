package region

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/refdata"
)

var rdapHosts = []string{"rdap.arin.net", "rdap.apnic.net", "rdap.lacnic.net", "rdap.registro.br", "rdap.afrinic.net"}

var Checks = []Check{
	{Service: "RDAP (RIR)", Group: GeoIP, ByIP: true, URL: "https://rdap.db.ripe.net/ip/{ip}", ExtraHosts: rdapHosts, Custom: rdap},
	{Service: "ipinfo.io", Group: GeoIP, ByIP: true, URL: "https://ipinfo.io/{ip}/json", Extract: jsonPath("country"),
		Authorize: func(req *http.Request, k config.Keys) {
			if k.IPinfoToken != "" {
				req.Header.Set("Authorization", "Bearer "+k.IPinfoToken)
			}
		}},
	{Service: "ipapi.co", Group: GeoIP, ByIP: true, URL: "https://ipapi.co/{ip}/json/", Extract: jsonPath("country_code")},
	{Service: "ifconfig.co", Group: GeoIP, ByIP: true, URL: "https://ifconfig.co/country-iso?ip={ip}", Extract: wholeBody},
	{Service: "ip2location.io", Group: GeoIP, ByIP: true, URL: "https://api.ip2location.io/?ip={ip}", Extract: jsonPath("country_code"),
		Authorize: func(req *http.Request, k config.Keys) { setQuery(req, "key", k.IP2LocationKey) }},
	{Service: "country.is", Group: GeoIP, ByIP: true, URL: "https://api.country.is/{ip}", Extract: jsonPath("country")},
	{Service: "geojs.io", Group: GeoIP, ByIP: true, URL: "https://get.geojs.io/v1/ip/country.json?ip={ip}", Extract: jsonPath("[0].country")},
	{Service: "ipbase.com", Group: GeoIP, ByIP: true, URL: "https://api.ipbase.com/v2/info?ip={ip}", Extract: jsonPath("data.location.country.alpha2")},
	{Service: "ipquery.io", Group: GeoIP, ByIP: true, URL: "https://api.ipquery.io/{ip}", Extract: jsonPath("location.country_code")},
	{Service: "ipwho.is", Group: GeoIP, ByIP: true, URL: "https://ipwho.is/{ip}", Extract: jsonPath("country_code")},
	{Service: "ip-api.com", Group: GeoIP, ByIP: true, Transport: netx.IPv4, URL: "http://ip-api.com/json/{ip}?fields=status,countryCode", Extract: jsonPath("countryCode")},
	{Service: "ipregistry.co", Group: GeoIP, ByIP: true, URL: "https://api.ipregistry.co/{ip}", Extract: jsonPath("location.country.code"),
		KeyOK:     func(k config.Keys) bool { return k.IPRegistryKey != "" },
		Authorize: func(req *http.Request, k config.Keys) { setQuery(req, "key", k.IPRegistryKey) }},
	{Service: "geoapify.com", Group: GeoIP, ByIP: true, URL: "https://api.geoapify.com/v1/ipinfo?ip={ip}", Extract: jsonPath("country.iso_code"),
		KeyOK:     func(k config.Keys) bool { return k.GeoapifyKey != "" },
		Authorize: func(req *http.Request, k config.Keys) { setQuery(req, "apiKey", k.GeoapifyKey) }},
	{Service: "MaxMind GeoLite", Group: GeoIP, ByIP: true, URL: "https://geolite.info/geoip/v2.1/country/{ip}", Extract: jsonPath("country.iso_code"),
		KeyOK: func(k config.Keys) bool { return k.MaxMindAccountID != "" && k.MaxMindLicenseKey != "" },
		Authorize: func(req *http.Request, k config.Keys) {
			req.SetBasicAuth(k.MaxMindAccountID, k.MaxMindLicenseKey)
		}},

	{Service: "Cloudflare", Group: Platform, URL: "https://www.cloudflare.com/cdn-cgi/trace", Custom: cloudflareTrace},
	{Service: "Google", Group: Platform, URL: "https://accounts.google.com/v3/signin/identifier?flowName=GlifSetupAndroid", Extract: bodyRegex(`name="region" value="([^"]*)"`)},
	{Service: "YouTube", Group: Platform, URL: "https://www.youtube.com/sw.js_data", Extract: jsonPathAfter(")]}'", "[0][2][0][0][1]")},
	{Service: "Reddit", Group: Platform, URL: "https://www.reddit.com/api/v1/not-found", BlockStatus: http.StatusForbidden, Extract: bodyRegex(`country code: ([A-Z]{2})`)},
	{Service: "TikTok", Group: Platform, URL: "https://www.tiktok.com/api/v1/web-cookie-privacy/config?appId=1988", Extract: jsonPath("body.appProps.region")},
	{Service: "Apple", Group: Platform, URL: "https://gspe1-ssl.ls.apple.com/pep/gcc", Extract: wholeBody},
	{Service: "Steam", Group: Platform, Method: http.MethodHead, NoRedirect: true, URL: "https://store.steampowered.com/", Extract: headerRegex("Set-Cookie", `steamCountry=([A-Z]{2})`)},
	{Service: "Microsoft", Group: Platform, URL: "https://login.live.com/", Extract: bodyRegex(`"sRequestCountry":"([^"]*)"`)},
	{Service: "Ookla", Group: Platform, URL: "https://www.speedtest.net/api/js/config-sdk", Extract: jsonPath("location.countryCode")},
	{Service: "JetBrains", Group: Platform, URL: "https://data.services.jetbrains.com/geo", Extract: jsonPath("code")},
	{Service: "PlayStation", Group: Platform, Method: http.MethodHead, NoRedirect: true, URL: "https://www.playstation.com/", Extract: headerRegex("Set-Cookie", `(?i)^country=([A-Z]{2})`)},

	{Service: "YouTube", Group: CDN, URL: "https://redirector.googlevideo.com/report_mapping?di=no", Custom: youtubeCDN},
}

func setQuery(req *http.Request, name, value string) {
	if value == "" {
		return
	}
	q := req.URL.Query()
	q.Set(name, value)
	req.URL.RawQuery = q.Encode()
}

func rdap(r *response) []Result {
	var doc struct {
		Country  string `json:"country"`
		Entities []struct {
			Roles      []string          `json:"roles"`
			VCardArray []json.RawMessage `json:"vcardArray"`
		} `json:"entities"`
	}
	cc := ""
	if json.Unmarshal(r.Body, &doc) == nil {
		cc = doc.Country
		for _, e := range doc.Entities {
			if cc != "" {
				break
			}
			if len(e.VCardArray) == 2 && contains(e.Roles, "registrant") {
				cc = vcardCountry(e.VCardArray[1])
			}
		}
	}
	return []Result{countryResult(GeoIP, "RDAP (RIR)", cc, r.Status)}
}

func vcardCountry(raw json.RawMessage) string {
	var props [][]json.RawMessage
	if json.Unmarshal(raw, &props) != nil {
		return ""
	}
	for _, p := range props {
		var name string
		if len(p) < 2 || json.Unmarshal(p[0], &name) != nil || name != "adr" {
			continue
		}
		var params struct {
			Label string `json:"label"`
			CC    string `json:"cc"`
		}
		if json.Unmarshal(p[1], &params) != nil {
			continue
		}
		if params.CC != "" {
			return params.CC
		}
		lines := strings.Split(strings.TrimSpace(params.Label), "\n")
		if cc := refdata.CountryByName(lines[len(lines)-1]); cc != "" {
			return cc
		}
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

var traceLine = regexp.MustCompile(`(?m)^(loc|colo)=([A-Za-z]+)\s*$`)

func cloudflareTrace(r *response) []Result {
	fields := map[string]string{}
	for _, m := range traceLine.FindAllStringSubmatch(string(r.Body), -1) {
		fields[m[1]] = m[2]
	}
	edge := Result{Group: CDN, Service: "Cloudflare", IATA: strings.ToUpper(fields["colo"])}
	if cc := refdata.IATACountry(edge.IATA); cc != "" {
		edge.Status, edge.Country = OK, cc
	} else {
		edge.Status = Unknown
	}
	return []Result{countryResult(Platform, "Cloudflare", fields["loc"], r.Status), edge}
}

var (
	youtubeNode = regexp.MustCompile(`=> ([a-z0-9-]+)`)
	nodeIATA    = []*regexp.Regexp{
		regexp.MustCompile(`^([a-z]{3})[0-9]`),
		regexp.MustCompile(`^[a-z]+-([a-z]{3})[0-9]`),
		regexp.MustCompile(`^[a-z]{2}([a-z]{3})[a-z]-[a-z0-9]+$`),
	}
)

func youtubeCDN(r *response) []Result {
	res := Result{Group: CDN, Service: "YouTube", Status: Unknown}
	m := youtubeNode.FindSubmatch(r.Body)
	if m == nil {
		if r.Status >= 400 {
			res.Status, res.Reason = Failed, fmt.Sprintf("HTTP %d", r.Status)
		}
		return []Result{res}
	}
	res.Node = string(m[1])
	for _, re := range nodeIATA {
		if mm := re.FindStringSubmatch(res.Node); mm != nil {
			res.IATA = strings.ToUpper(mm[1])
			break
		}
	}
	if cc := refdata.IATACountry(res.IATA); cc != "" {
		res.Status, res.Country = OK, cc
	}
	return []Result{res}
}
