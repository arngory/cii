package services

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/arngory/cii/internal/clientids"
	"github.com/arngory/cii/internal/probe"
)

func noRedirect(rawURL string) []probe.Request {
	return []probe.Request{{URL: rawURL, NoRedirect: true}}
}

func toCC(raw string) string {
	if c := probe.CountryResult(raw, http.StatusOK); c.Status == probe.OK {
		return c.Country
	}
	return ""
}

func has(body []byte, markers ...string) bool {
	lower := bytes.ToLower(body)
	for _, m := range markers {
		if bytes.Contains(lower, []byte(strings.ToLower(m))) {
			return true
		}
	}
	return false
}

func unknownWith(r *probe.Response, reason string) []probe.Result {
	if f, failed := probe.HTTPFailure(r.Status); failed {
		return []probe.Result{f}
	}
	return []probe.Result{{Status: probe.Unknown, Reason: probe.Truncate(reason, 60)}}
}

func unknownRedirect(r *probe.Response) []probe.Result {
	return unknownWith(r, "redirected to "+r.Header.Get("Location"))
}

func redirected(r *probe.Response) bool {
	return r.Status >= 300 && r.Status < 400
}

func byStatus(yesCode int, noCodes ...int) func([]*probe.Response) []probe.Result {
	return func(rs []*probe.Response) []probe.Result {
		r := rs[0]
		switch {
		case r.Status == yesCode:
			return yes("")
		case slices.Contains(noCodes, r.Status):
			return no("HTTP " + strconv.Itoa(r.Status))
		}
		return unknownWith(r, "HTTP "+strconv.Itoa(r.Status))
	}
}

func byStatusMarker(okMarker string, blocked ...int) func([]*probe.Response) []probe.Result {
	return func(rs []*probe.Response) []probe.Result {
		r := rs[0]
		if slices.Contains(blocked, r.Status) {
			return no("HTTP " + strconv.Itoa(r.Status))
		}
		if r.Status == http.StatusOK && has(r.Body, okMarker) {
			return yes("")
		}
		return unknown(r)
	}
}

func byMarkers(blocked, ok []string) func([]*probe.Response) []probe.Result {
	return func(rs []*probe.Response) []probe.Result {
		r := rs[0]
		switch {
		case has(r.Body, blocked...):
			return no("")
		case r.Status == http.StatusOK && has(r.Body, ok...):
			return yes("")
		}
		return unknown(r)
	}
}

func byRedirect(blocked *regexp.Regexp, forbiddenIsNo bool) func([]*probe.Response) []probe.Result {
	return func(rs []*probe.Response) []probe.Result {
		r := rs[0]
		loc := r.Header.Get("Location")
		switch {
		case loc != "" && blocked.MatchString(loc):
			return no("redirected to " + probe.Truncate(loc, 60))
		case forbiddenIsNo && r.Status == http.StatusForbidden:
			return no("HTTP 403")
		case r.Status == http.StatusOK:
			return yes("")
		case loc != "":
			return unknownRedirect(r)
		}
		return unknown(r)
	}
}

func byRedirectMarker(blocked *regexp.Regexp, okMarker string, country func(*probe.Response) string) func([]*probe.Response) []probe.Result {
	return func(rs []*probe.Response) []probe.Result {
		r := rs[0]
		loc := r.Header.Get("Location")
		if loc != "" && blocked.MatchString(loc) {
			return no("redirected to " + probe.Truncate(loc, 60))
		}
		switch {
		case redirected(r):
			return unknownRedirect(r)
		case r.Status == http.StatusOK && has(r.Body, okMarker):
			found := ""
			if country != nil {
				found = toCC(country(r))
			}
			return yes(found)
		}
		return unknown(r)
	}
}

func byBool(field string, yesValue bool) func([]*probe.Response) []probe.Result {
	re := regexp.MustCompile(regexp.QuoteMeta(field) + `\s*:\s*(true|false)`)
	return func(rs []*probe.Response) []probe.Result {
		r := rs[0]
		m := re.FindSubmatch(r.Body)
		if m == nil {
			return unknown(r)
		}
		if (string(m[1]) == "true") == yesValue {
			return yes("")
		}
		return no("")
	}
}

var brightcoveSubcode = probe.BodyRegex(`"error_subcode"\s*:\s*"([^"]+)"`)

func brightcove(rs []*probe.Response) []probe.Result {
	r := rs[0]
	switch sub := brightcoveSubcode(r); {
	case sub == "CLIENT_GEO":
		return no("CLIENT_GEO")
	case sub != "":
		return unknownWith(r, sub)
	case r.Status == http.StatusOK && bytes.Contains(r.Body, []byte(`"sources"`)):
		return yes("")
	}
	return unknown(r)
}

func brightcoveCheck(service, account, video, policyKey, origin string) probe.Check {
	return probe.Check{Service: service, Tier: probe.TierB, Requests: []probe.Request{{
		URL:    "https://edge.api.brightcove.com/playback/v1/accounts/" + account + "/videos/" + video,
		Header: map[string]string{"Accept": "application/json;pk=" + policyKey, "Origin": origin, "Referer": origin + "/"}}},
		Eval: brightcove}
}

var (
	sharedParamountPlus = probe.Check{Service: "Paramount+", Requests: probe.Get("https://www.paramountplus.com/"), Eval: paramount}
	sharedHBOMax        = probe.Check{Service: "HBO Max", Requests: probe.Get("https://www.hbomax.com/"), Eval: hboMax}
	sharedNBATV         = probe.Check{Service: "NBA TV", Requests: probe.Get("https://www.nba.com/watch/"), Eval: nbaTV}
	sharedFuboTV        = probe.Check{Service: "Fubo TV", Requests: probe.Get("https://api.fubo.tv/v3/location"), Eval: fubo}
	sharedHotstar       = probe.Check{Service: "Hotstar", Requests: noRedirect("https://www.hotstar.com/"), Eval: hotstar}
	sharedViu           = probe.Check{Service: "Viu", Requests: noRedirect("https://www.viu.com/"), Eval: viu}
	sharedWatcha        = probe.Check{Service: "WATCHA", Requests: probe.Get("https://watcha.com/"), Eval: byStatus(http.StatusOK, http.StatusUnavailableForLegalReasons)}
	sharedBritBox       = probe.Check{Service: "BritBox", Requests: noRedirect("https://www.britbox.com/"),
		Eval: byRedirect(regexp.MustCompile(`locationnotsupported|locationnotvalidated|britbox\.co\.uk`), false)}
	sharedAcornTV = probe.Check{Service: "Acorn TV", Requests: probe.Get("https://acorn.tv/"),
		Eval: byMarkers([]string{"not yet available in your", "unavailable in your"}, []string{"signup.acorn.tv"})}
	sharedShudder = probe.Check{Service: "Shudder", Requests: probe.Get("https://www.shudder.com/"),
		Eval: byMarkers([]string{"not available", "not yet available", "403 ERROR"}, []string{"shudder"})}
	sharedAMCPlus = probe.Check{Service: "AMC+", Requests: noRedirect("https://www.amcplus.com/"),
		Eval: byRedirect(regexp.MustCompile(`geographic-restriction`), true)}
	sharedSetanta = probe.Check{Service: "Setanta Sports", Tier: probe.TierB, Requests: []probe.Request{{
		URL:    "https://dce-frontoffice.imggaming.com/api/v2/consent-prompt",
		Header: map[string]string{"Realm": clientids.SetantaSportsRealm, "X-Api-Key": clientids.SetantaSportsAPIKey}}},
		Eval: byBool(`"outsideAllowedTerritories"`, false)}
)

var paramountRegion = regexp.MustCompile(`"pageProps":\{[^{}]*?"region":"([A-Za-z]+)"`)

func paramount(rs []*probe.Response) []probe.Result {
	r := rs[0]
	m := paramountRegion.FindSubmatch(r.Body)
	if r.Status != http.StatusOK || m == nil {
		return unknown(r)
	}
	region := strings.ToUpper(string(m[1]))
	if region == "INTL" {
		return no("international page")
	}
	if country := toCC(region); country != "" {
		return yes(country)
	}
	return unknown(r)
}

var (
	hboCookie    = probe.HeaderRegex("Set-Cookie", `countryCode=([A-Za-z]{2})\b`)
	hboBody      = probe.BodyRegex(`countryCode=([A-Z]{2})\b`)
	hboCountries = regexp.MustCompile(`"url":"/([a-z]{2})/[a-z]{2}"`)
)

func hboMax(rs []*probe.Response) []probe.Result {
	r := rs[0]
	country := toCC(hboCookie(r))
	if country == "" {
		country = toCC(hboBody(r))
	}
	switch {
	case r.Status == http.StatusForbidden:
		return []probe.Result{{Status: probe.IPBlock, Country: country, Reason: "HTTP 403"}}
	case r.Status != http.StatusOK || country == "":
		return unknown(r)
	case country == "US":
		return yes(country)
	}
	list := hboCountries.FindAllSubmatch(r.Body, -1)
	if len(list) == 0 {
		return []probe.Result{{Status: probe.Unknown, Country: country, Reason: "country list not found"}}
	}
	for _, m := range list {
		if strings.EqualFold(string(m[1]), country) {
			return yes(country)
		}
	}
	return []probe.Result{{Status: probe.No, Country: country}}
}

func nbaTV(rs []*probe.Response) []probe.Result {
	r := rs[0]
	switch {
	case r.Status == http.StatusForbidden:
		return []probe.Result{{Status: probe.IPBlock, Reason: "HTTP 403"}}
	case r.Status != http.StatusOK:
		return unknown(r)
	case has(r.Body, "Service is not available in your region"):
		return no("")
	}
	return yes("")
}

var fuboAllowed = regexp.MustCompile(`"network_allowed"\s*:\s*(true|false)`)

func fubo(rs []*probe.Response) []probe.Result {
	r := rs[0]
	country := toCC(probe.JSONPath("country_code2")(r))
	if bytes.Contains(r.Body, []byte("NO_SERVICE_IN_COUNTRY")) {
		return []probe.Result{{Status: probe.No, Country: country, Reason: "no service in country"}}
	}
	m := fuboAllowed.FindSubmatch(r.Body)
	switch {
	case m == nil:
		return unknown(r)
	case string(m[1]) == "true":
		return yes(country)
	}
	return []probe.Result{{Status: probe.IPBlock, Country: country, Reason: "network not allowed"}}
}

var (
	hotstarGeo  = probe.HeaderRegex("Set-Cookie", `^geo=([A-Z]{2})\b`)
	hotstarSite = regexp.MustCompile(`^(?:https?://[^/]+)?/([a-z]{2})(?:[/?#]|$)`)
)

func hotstar(rs []*probe.Response) []probe.Result {
	r := rs[0]
	if r.Status == http.StatusForbidden || r.Status == 475 {
		return no("HTTP " + strconv.Itoa(r.Status))
	}
	geo := toCC(hotstarGeo(r))
	if geo == "" {
		return unknown(r)
	}
	if geo == "US" {
		return []probe.Result{{Status: probe.No, Country: geo, Reason: "discontinued in the US"}}
	}
	if m := hotstarSite.FindStringSubmatch(r.Header.Get("Location")); m != nil && strings.EqualFold(m[1], geo) {
		return yes(geo)
	}
	return []probe.Result{{Status: probe.Unknown, Country: geo, Reason: "site region mismatch"}}
}

var viuRegion = regexp.MustCompile(`^(?:https?://[^/]+)?/ott/([a-z]{2}|no-service)(?:[/?#]|$)`)

func viu(rs []*probe.Response) []probe.Result {
	r := rs[0]
	m := viuRegion.FindStringSubmatch(r.Header.Get("Location"))
	switch {
	case !redirected(r):
		return unknown(r)
	case m == nil:
		return unknownRedirect(r)
	case m[1] == "no-service":
		return no("no service")
	}
	if country := toCC(m[1]); country != "" {
		return yes(country)
	}
	return unknown(r)
}

func uuid4() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
