package region

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/refdata"
)

var rdapHosts = []string{"rdap.arin.net", "rdap.apnic.net", "rdap.lacnic.net", "rdap.registro.br", "rdap.afrinic.net"}

func country(rawURL string, extract func(*probe.Response) string) ([]probe.Request, func([]*probe.Response) []probe.Result) {
	return probe.Get(rawURL), probe.CountryFrom(extract, 0)
}

func geoip(service, rawURL string, extract func(*probe.Response) string) probe.Check {
	req, eval := country(rawURL, extract)
	return probe.Check{Service: service, Group: GeoIP, Requests: req, Eval: eval}
}

func platform(service, rawURL string, extract func(*probe.Response) string) probe.Check {
	req, eval := country(rawURL, extract)
	return probe.Check{Service: service, Group: Platform, Requests: req, Eval: eval}
}

func head(rawURL string) []probe.Request {
	return []probe.Request{{Method: http.MethodHead, URL: rawURL, NoRedirect: true}}
}

var Checks = []probe.Check{
	{Service: "RIPEstat", Group: Registry, Requests: []probe.Request{
		{URL: "https://stat.ripe.net/data/rir-stats-country/data.json?resource={ip}&sourceapp=cii"},
		{URL: "https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}&sourceapp=cii"},
	}, Eval: ripestat},
	{Service: "Fastly", Group: CDN, Requests: head("https://www.fastly.com/robots.txt"), Eval: fastlyEdge},
	geoip("DB-IP", "https://api.db-ip.com/v2/free/{ip}", probe.JSONPath("countryCode")),
	{Service: "RDAP (RIR)", Group: Registry, Requests: probe.Get("https://rdap.db.ripe.net/ip/{ip}"), ExtraHosts: rdapHosts, Eval: rdap},
	withAuth(geoip("ipinfo.io", "https://ipinfo.io/{ip}/json", probe.JSONPath("country")), nil, func(req *http.Request, k config.Keys) {
		if k.IPinfoToken != "" {
			req.Header.Set("Authorization", "Bearer "+k.IPinfoToken)
		}
	}),
	geoip("ipapi.co", "https://ipapi.co/{ip}/json/", probe.JSONPath("country_code")),
	geoip("ifconfig.co", "https://ifconfig.co/country-iso?ip={ip}", probe.WholeBody),
	withFacts(withAuth(geoip("ip2location.io", "https://api.ip2location.io/?ip={ip}", probe.JSONPath("country_code")), nil,
		func(req *http.Request, k config.Keys) { setQuery(req, "key", k.IP2LocationKey) }), ip2locationFacts),
	geoip("country.is", "https://api.country.is/{ip}", probe.JSONPath("country")),
	geoip("geojs.io", "https://get.geojs.io/v1/ip/country.json?ip={ip}", probe.JSONPath("[0].country")),
	geoip("ipbase.com", "https://api.ipbase.com/v2/info?ip={ip}", probe.JSONPath("data.location.country.alpha2")),
	withFacts(geoip("ipquery.io", "https://api.ipquery.io/{ip}", probe.JSONPath("location.country_code")), ipqueryFacts),
	geoip("ipwho.is", "https://ipwho.is/{ip}", probe.JSONPath("country_code")),
	withFacts(ipv4Only(geoip("ip-api.com", "http://ip-api.com/json/{ip}?fields=status,countryCode,proxy,hosting,mobile", probe.JSONPath("countryCode"))), ipAPIFacts),
	withFacts(withAuth(geoip("ipregistry.co", "https://api.ipregistry.co/{ip}", probe.JSONPath("location.country.code")),
		func(k config.Keys) bool { return k.IPRegistryKey != "" },
		func(req *http.Request, k config.Keys) { setQuery(req, "key", k.IPRegistryKey) }), ipregistryFacts),
	withAuth(geoip("geoapify.com", "https://api.geoapify.com/v1/ipinfo?ip={ip}", probe.JSONPath("country.iso_code")),
		func(k config.Keys) bool { return k.GeoapifyKey != "" },
		func(req *http.Request, k config.Keys) { setQuery(req, "apiKey", k.GeoapifyKey) }),
	withAuth(geoip("MaxMind GeoLite", "https://geolite.info/geoip/v2.1/country/{ip}", probe.JSONPath("country.iso_code")),
		func(k config.Keys) bool { return k.MaxMindAccountID != "" && k.MaxMindLicenseKey != "" },
		func(req *http.Request, k config.Keys) { req.SetBasicAuth(k.MaxMindAccountID, k.MaxMindLicenseKey) }),

	{Service: "Cloudflare", Group: Platform, Requests: probe.Get("https://www.cloudflare.com/cdn-cgi/trace"), Eval: cloudflareTrace},
	platform("Google", "https://accounts.google.com/v3/signin/identifier?flowName=GlifSetupAndroid", probe.BodyRegex(`name="region" value="([^"]*)"`)),
	platform("YouTube", "https://www.youtube.com/sw.js_data", probe.JSONPathAfter(")]}'", "[0][2][0][0][1]")),
	{Service: "Reddit", Group: Platform, Requests: probe.Get("https://www.reddit.com/api/v1/not-found"),
		Eval: probe.CountryFrom(probe.BodyRegex(`country code: ([A-Z]{2})`), http.StatusForbidden)},
	platform("TikTok", "https://www.tiktok.com/api/v1/web-cookie-privacy/config?appId=1988", probe.JSONPath("body.appProps.region")),
	platform("Apple", "https://gspe1-ssl.ls.apple.com/pep/gcc", probe.WholeBody),
	{Service: "Steam", Group: Platform, Requests: head("https://store.steampowered.com/"),
		Eval: probe.CountryFrom(probe.HeaderRegex("Set-Cookie", `steamCountry=([A-Z]{2})`), 0)},
	platform("Microsoft", "https://login.live.com/", probe.BodyRegex(`"sRequestCountry":"([^"]*)"`)),
	platform("Ookla", "https://www.speedtest.net/api/js/config-sdk", probe.JSONPath("location.countryCode")),
	platform("JetBrains", "https://data.services.jetbrains.com/geo", probe.JSONPath("code")),
	{Service: "PlayStation", Group: Platform, Requests: head("https://www.playstation.com/"),
		Eval: probe.CountryFrom(probe.HeaderRegex("Set-Cookie", `(?i)^country=([A-Z]{2})`), 0)},

	{Service: "YouTube", Group: CDN, Requests: probe.Get("https://redirector.googlevideo.com/report_mapping?di=no"), Eval: youtubeCDN},
}

func withAuth(c probe.Check, keyOK func(config.Keys) bool, authorize func(*http.Request, config.Keys)) probe.Check {
	c.KeyOK, c.Authorize = keyOK, authorize
	return c
}

func ipv4Only(c probe.Check) probe.Check {
	c.Transport = netx.IPv4
	return c
}

func setQuery(req *http.Request, name, value string) {
	if value == "" {
		return
	}
	q := req.URL.Query()
	q.Set(name, value)
	req.URL.RawQuery = q.Encode()
}

func rdap(rs []*probe.Response) []probe.Result {
	r := rs[0]
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
			if len(e.VCardArray) == 2 && slices.Contains(e.Roles, "registrant") {
				cc = vcardCountry(e.VCardArray[1])
			}
		}
	}
	return []probe.Result{probe.CountryResult(cc, r.Status)}
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

var traceLine = regexp.MustCompile(`(?m)^(loc|colo)=([A-Za-z]+)\s*$`)

func cloudflareTrace(rs []*probe.Response) []probe.Result {
	fields := map[string]string{}
	for _, m := range traceLine.FindAllStringSubmatch(string(rs[0].Body), -1) {
		fields[m[1]] = m[2]
	}
	loc := probe.CountryResult(fields["loc"], rs[0].Status)
	loc.Group = Platform
	return []probe.Result{loc, edge("Cloudflare", strings.ToUpper(fields["colo"]), "")}
}

func edge(service, iata, node string) probe.Result {
	r := probe.Result{Group: CDN, Service: service, IATA: iata, Node: node, Status: probe.Unknown}
	if cc := refdata.IATACountry(iata); cc != "" {
		r.Status, r.Country = probe.OK, cc
	}
	return r
}

var (
	youtubeNode = regexp.MustCompile(`=> ([a-z0-9-]+)`)
	nodeIATA    = []*regexp.Regexp{
		regexp.MustCompile(`^([a-z]{3})[0-9]`),
		regexp.MustCompile(`^[a-z]+-([a-z]{3})[0-9]`),
		regexp.MustCompile(`^[a-z]{2}([a-z]{3})[a-z]-[a-z0-9]+$`),
	}
)

func ripestat(rs []*probe.Response) []probe.Result {
	var reg struct {
		Data struct {
			Located []struct {
				Location string `json:"location"`
			} `json:"located_resources"`
		} `json:"data"`
	}
	cc := ""
	if json.Unmarshal(rs[0].Body, &reg) == nil && len(reg.Data.Located) > 0 {
		cc = reg.Data.Located[0].Location
	}
	res := probe.CountryResult(cc, rs[0].Status)
	var pfx struct {
		Data struct {
			Resource  string `json:"resource"`
			Announced bool   `json:"announced"`
			ASNs      []struct {
				ASN    int    `json:"asn"`
				Holder string `json:"holder"`
			} `json:"asns"`
		} `json:"data"`
	}
	if rs[1].Status == http.StatusOK && json.Unmarshal(rs[1].Body, &pfx) == nil {
		d := pfx.Data
		switch {
		case !d.Announced:
			res.Detail = "not announced"
		case len(d.ASNs) > 0:
			res.Detail = strings.TrimSpace(fmt.Sprintf("AS%d %s", d.ASNs[0].ASN, d.ASNs[0].Holder))
			if len(d.ASNs) > 1 {
				res.Detail += fmt.Sprintf(" (+%d origins)", len(d.ASNs)-1)
			}
			if d.Resource != "" {
				res.Detail += " · " + d.Resource
			}
		}
	}
	return []probe.Result{res}
}

func fastlyEdge(rs []*probe.Response) []probe.Result {
	r := rs[0]
	nodes := strings.Split(r.Header.Get("X-Served-By"), ",")
	node := strings.TrimPrefix(strings.TrimSpace(nodes[len(nodes)-1]), "cache-")
	if node == "" {
		if f, failed := probe.HTTPFailure(r.Status); failed {
			return []probe.Result{f}
		}
		return []probe.Result{{Status: probe.Unknown}}
	}
	iata := ""
	if i := strings.LastIndexByte(node, '-'); i >= 0 && len(node)-i == 4 {
		iata = strings.ToUpper(node[i+1:])
	}
	return []probe.Result{edge("Fastly", iata, node)}
}

func youtubeCDN(rs []*probe.Response) []probe.Result {
	r := rs[0]
	m := youtubeNode.FindSubmatch(r.Body)
	if m == nil {
		if f, failed := probe.HTTPFailure(r.Status); failed {
			return []probe.Result{f}
		}
		return []probe.Result{{Status: probe.Unknown}}
	}
	node := string(m[1])
	iata := ""
	for _, re := range nodeIATA {
		if mm := re.FindStringSubmatch(node); mm != nil {
			iata = strings.ToUpper(mm[1])
			break
		}
	}
	return []probe.Result{edge("YouTube", iata, node)}
}
