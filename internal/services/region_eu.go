package services

import (
	"bytes"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/arngory/cii/internal/clientids"
	"github.com/arngory/cii/internal/probe"
)

func init() {
	register("EU",
		sharedParamountPlus,
		sharedHBOMax,
		probe.Check{Service: "SkyShowTime", Requests: probe.Get("https://www.skyshowtime.com/"), Eval: eossSkyShowTime},
		sharedBritBox,
		probe.Check{Service: "Megogo", Requests: probe.Get("https://megogo.net/en"), Eval: eossMegogo},
		sharedSetanta,
		sharedHotstar,
		probe.Check{Service: "Channel 4", Requests: probe.Get("https://www.channel4.com/simulcast/channels/C4"), Eval: byStatus(http.StatusOK, http.StatusForbidden)},
		probe.Check{Service: "BBC iPlayer", Requests: probe.Get("https://open.live.bbc.co.uk/mediaselector/6/select/version/2.0/mediaset/pc/vpid/bbc_one_london/format/json/jsfunc/JS_callbacks0"),
			Eval: byMarkers([]string{"geolocation"}, []string{"vs-hls-push-uk"})},
		sharedAcornTV,
		sharedShudder,
		probe.Check{Service: "Canal+", Requests: noRedirect("https://boutique-tunnel.canalplus.com/"),
			Eval: byRedirect(regexp.MustCompile(`other-country-blocking`), false)},
		probe.Check{Service: "Molotov", Requests: probe.Get("https://fapi.molotov.tv/v1/open-europe/is-france"), Eval: byBool(`"is_france"`, true)},
		probe.Check{Service: "ZDF", Requests: probe.Get("https://ssl.zdf.de/geo/de/geo.txt/"), Eval: byStatus(http.StatusNotFound, http.StatusForbidden)},
		probe.Check{Service: "Rai Play", Requests: probe.Get("https://mediapolisvod.rai.it/relinker/relinkerServlet.htm?cont=VxXwi7UcqjApssSlashbjsAghviAeeqqEEqualeeqqEEqual&output=64"), Eval: eossRaiPlay},
		probe.Check{Service: "Sky CH", Requests: noRedirect("https://www.sky.ch/"), Eval: byRedirect(regexp.MustCompile(`out-of-country`), true)},

		probe.Check{Service: "Rakuten TV", Tier: probe.TierB, Requests: []probe.Request{{Method: http.MethodPost,
			URL:  "https://gizmo.rakuten.tv/v3/me/start?device_identifier=web&device_stream_audio_quality=2.0&device_stream_hdr_type=NONE&device_stream_video_quality=FHD",
			Body: clientids.RakutenTVEUStartBody,
			Header: map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/plain, */*",
				"Origin": "https://www.rakuten.tv", "Referer": "https://www.rakuten.tv/"}}}, Eval: eossRakutenTV},
		probe.Check{Service: "Sky Go", Tier: probe.TierB, Requests: probe.Get("https://skyid.sky.com/authorise/skygo?" + clientids.SkyGoUKAuthorizeQuery), Eval: eossSkyGo},
		probe.Check{Service: "ITVX", Tier: probe.TierB, Requests: []probe.Request{{Method: http.MethodPost,
			URL: "https://magni.itv.com/playlist/itvonline/ITV/10_4782_0001.001", Body: clientids.ITVXPlaylistBody,
			Header: map[string]string{"Content-Type": "application/json", "Accept": "application/vnd.itv.vod.playlist.v2+json",
				"Origin": "https://www.itv.com", "Referer": "https://www.itv.com/"}}},
			Eval: byMarkers([]string{"Outside Of Allowed Geographic"}, []string{"Playlist"})},
		probe.Check{Service: "Channel 5", Tier: probe.TierB, Requests: probe.Get("https://cassie.channel5.com/api/v2/live_media/my5desktopng/C5.json?timestamp=" +
			strconv.FormatInt(time.Now().Unix(), 10) + "&auth=" + clientids.Channel5WebAuth), Eval: eossChannel5},
		brightcoveCheck("Sky DE", clientids.SkyDEBrightcoveAccount, clientids.SkyDEBrightcoveVideo, clientids.SkyDEBrightcovePolicyKey, "https://www.sky.de"),
		probe.Check{Service: "Videoland", Tier: probe.TierB, Requests: []probe.Request{{Method: http.MethodPost,
			URL: "https://api.videoland.com/subscribe/videoland-account/graphql", Body: clientids.VideolandGeoQuery,
			Header: map[string]string{"Content-Type": "application/json", "Apollographql-Client-Name": clientids.VideolandApolloClient,
				"Origin": "https://www.videoland.com", "Referer": "https://www.videoland.com/"}}},
			Eval: byBool(`"isOnboardingGeoBlocked"`, false)},
	)
}

var (
	eossSSTTerritory = probe.BodyRegex(`"territory":"([A-Za-z]{2})"`)
	eossSSTCookie    = probe.HeaderRegex("Set-Cookie", `activeTerritory=([A-Z]{2})`)
)

func eossSkyShowTime(rs []*probe.Response) []probe.Result {
	r := rs[0]
	switch {
	case r.Status == http.StatusForbidden:
		return no("HTTP 403")
	case has(r.Body, "where-can-i-stream"):
		return no("")
	case r.Status != http.StatusOK:
		return unknown(r)
	}
	t := eossSSTTerritory(r)
	if strings.EqualFold(t, "XX") {
		return no("territory not supported")
	}
	if cc := toCC(t); cc != "" {
		return yes(cc)
	}
	if cc := toCC(eossSSTCookie(r)); cc != "" {
		return yes(cc)
	}
	return unknown(r)
}

var eossMegogoGeo = probe.BodyRegex(`data-geo="([a-z]{2})"`)

func eossMegogo(rs []*probe.Response) []probe.Result {
	r := rs[0]
	if r.Status != http.StatusOK {
		return unknown(r)
	}
	if has(r.Body, "VPN") {
		return []probe.Result{{Status: probe.IPBlock, Reason: "VPN detected"}}
	}
	if cc := toCC(eossMegogoGeo(r)); cc != "" {
		return yes(cc)
	}
	return unknown(r)
}

var eossRaiGeo = probe.BodyRegex(`<geoprotection>([^<]+)<`)

func eossRaiPlay(rs []*probe.Response) []probe.Result {
	r := rs[0]
	g := strings.TrimSpace(eossRaiGeo(r))
	switch {
	case g == "":
		return unknown(r)
	case bytes.Contains(r.Body, []byte("video_no_available")), g == "N":
		return no("")
	case g == "Y":
		return yes("")
	}
	return unknown(r)
}

var (
	eossRakutenCC = probe.BodyRegex(`"iso3166_code"\s*:\s*"([A-Za-z]{2})"`)
)

func eossRakutenTV(rs []*probe.Response) []probe.Result {
	r := rs[0]
	switch {
	case has(r.Body, "is not available"):
		return no("")
	case has(r.Body, "VPN", "forbidden"):
		return []probe.Result{{Status: probe.IPBlock, Reason: "VPN or forbidden"}}
	}
	cc := toCC(eossRakutenCC(r))
	if cc != "" && bytes.Contains(r.Body, []byte("streaming_drm_types")) {
		return yes(cc)
	}
	return unknown(r)
}

func eossSkyGo(rs []*probe.Response) []probe.Result {
	r := rs[0]
	switch {
	case bytes.Contains(r.Body, []byte("Sign in</h3>")), bytes.Contains(r.Body, []byte("skygoSignin")):
		return yes("")
	case bytes.Contains(r.Body, []byte("Access Denied")) && bytes.Contains(r.Body, []byte("You don't have permission to access")):
		return no("access denied")
	}
	return unknown(r)
}

var eossChannel5Code = probe.BodyRegex(`"code"\s*:\s*"([^"]+)"`)

func eossChannel5(rs []*probe.Response) []probe.Result {
	switch eossChannel5Code(rs[0]) {
	case "3000":
		return no("")
	case "4003":
		return yes("")
	}
	return unknown(rs[0])
}
