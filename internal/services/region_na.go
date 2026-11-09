package services

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/arngory/cii/internal/clientids"
	"github.com/arngory/cii/internal/probe"
)

func init() {
	register("NA",
		sharedParamountPlus,
		sharedAcornTV,
		sharedBritBox,
		sharedShudder,
		sharedFuboTV,
		probe.Check{Service: "Tubi TV", Requests: probe.Get("https://tubitv.com/"),
			Eval: byMarkers([]string{"not currently available in your area"}, []string{"manifest"})},
		probe.Check{Service: "Pluto TV", Requests: noRedirect("https://pluto.tv/"),
			Eval: byRedirectMarker(regexp.MustCompile(`plutotv-is-not-available`), "Pluto TV", probe.BodyRegex(`"region":"([A-Z]{2})"`))},
		probe.Check{Service: "KOCOWA", Requests: probe.Get("https://www.kocowa.com/"), Eval: byStatusMarker("KOCOWA", http.StatusForbidden)},
		sharedAMCPlus,
		probe.Check{Service: "NFL+", Requests: noRedirect("https://www.nfl.com/plus"),
			Eval: byRedirectMarker(regexp.MustCompile(`nfl-game-pass|gpi\.nfl\.com`), "NFL+", nil)},
		probe.Check{Service: "Philo", Requests: probe.Get("https://content-us-east-2-fastly-b.www.philo.com/geo"), Eval: naPhilo},
		probe.Check{Service: "FXNOW", Requests: probe.Get("https://fxnow.fxnetworks.com/"),
			Eval: byMarkers([]string{"is not accessible"}, []string{"FX Movies"})},
		probe.Check{Service: "CW TV", Requests: probe.Get("https://www.cwtv.com/"), Eval: byStatusMarker("The CW", http.StatusForbidden, http.StatusUnavailableForLegalReasons)},
		probe.Check{Service: "A&E TV", Requests: probe.Get("https://play.aetv.com/"), Eval: naAETV},
		probe.Check{Service: "Sling TV", Requests: noRedirect("https://www.sling.com/"),
			Eval: byRedirectMarker(regexp.MustCompile(`geo-block`), "Sling", nil)},
		probe.Check{Service: "Peacock TV", Requests: noRedirect("https://www.peacocktv.com/"),
			Eval: byRedirectMarker(regexp.MustCompile(`unavailable`), "Peacock", probe.BodyRegex(`"territory":"([A-Z]{2})"`))},
		probe.Check{Service: "DirecTV Stream", Requests: probe.Get("https://stream.directv.com/watchnow"), Eval: byStatusMarker("DIRECTV", http.StatusForbidden)},
		sharedHotstar,
		probe.Check{Service: "CBC Gem", Requests: probe.Get("https://www.cbc.ca/g/stats/js/cbc-stats-top.js"), Eval: naCBCGem},

		sharedHBOMax,
		sharedNBATV,
		probe.Check{Service: "NBC TV", Tier: probe.TierB, Requests: []probe.Request{{Method: http.MethodPost,
			URL: "https://geolocation.digitalsvc.apps.nbcuni.com/geolocation/live/usa", Body: clientids.NBCGeoBody,
			Header: map[string]string{"Accept": "application/media.geo-v2+json", "Content-Type": "application/json",
				"Authorization": clientids.NBCGeoAuthorization, "Client": clientids.NBCGeoClient, "App-Session-Id": naSessionID(),
				"Origin": "https://www.nbc.com", "Referer": "https://www.nbc.com/"}}}, Eval: naNBC},
		brightcoveCheck("encoreTVB", clientids.EncoreTVBBrightcoveAccount, clientids.EncoreTVBBrightcoveVideo, clientids.EncoreTVBBrightcovePolicyKey, "https://www.encoretvb.com"),
		probe.Check{Service: "Crave", Tier: probe.TierB, Requests: []probe.Request{{
			URL:    "https://capi.9c9media.com" + clientids.CraveManifestPath,
			Header: map[string]string{"Origin": "https://www.crave.ca", "Referer": "https://www.crave.ca/"}}},
			Eval: byMarkers([]string{"Geo Constraint Restrictions"}, []string{"video.9c9media.com"})},
	)
}

func naSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]))
}

func naPhilo(rs []*probe.Response) []probe.Result {
	r := rs[0]
	cc := toCC(probe.JSONPath("country")(r))
	switch probe.JSONPath("status")(r) {
	case "SUCCESS":
		return yes(cc)
	case "FAIL":
		return []probe.Result{{Status: probe.No, Country: cc}}
	}
	return unknown(r)
}

var (
	naAETVHeader = probe.HeaderRegex("Aetn-Country-Code", `^([A-Za-z]{2})$`)
	naAETVCookie = probe.HeaderRegex("Set-Cookie", `AETN-Country-Code=([A-Z]{2})`)
)

func naAETV(rs []*probe.Response) []probe.Result {
	r := rs[0]
	cc := toCC(naAETVHeader(r))
	if cc == "" {
		cc = toCC(naAETVCookie(r))
	}
	switch {
	case cc == "":
		return unknown(r)
	case cc == "US", cc == "CA":
		return yes(cc)
	}
	return []probe.Result{{Status: probe.No, Country: cc}}
}

var naCBCCountry = probe.BodyRegex(`"country"\s*:\s*"([^"]+)"`)

func naCBCGem(rs []*probe.Response) []probe.Result {
	r := rs[0]
	if r.Status != http.StatusOK {
		return unknown(r)
	}
	cc := toCC(naCBCCountry(r))
	switch {
	case cc == "":
		return unknown(r)
	case cc == "CA":
		return yes(cc)
	}
	return []probe.Result{{Status: probe.No, Country: cc}}
}

var naNBCRestricted = regexp.MustCompile(`"restricted"\s*:\s*(true|false)`)

func naNBC(rs []*probe.Response) []probe.Result {
	r := rs[0]
	m := naNBCRestricted.FindSubmatch(r.Body)
	switch {
	case m == nil:
		return unknown(r)
	case string(m[1]) == "false":
		return yes("")
	}
	return no("restricted")
}
