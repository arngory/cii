package services

import (
	"bytes"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/arngory/cii/internal/clientids"
	"github.com/arngory/cii/internal/probe"
)

func init() {
	register("JP",
		probe.Check{Service: "DMM TV", Tier: probe.TierB, Requests: []probe.Request{{Method: http.MethodPost,
			URL: "https://api.beacon.dmm.com/v1/streaming/start", Body: clientids.DMMTVStreamingBody,
			Header: map[string]string{"Content-Type": "application/json"}}},
			Eval: jpDMMTV},
		probe.Check{Service: "ABEMA", Requests: probe.Get("https://api.abema.io/v1/ip/check?device=android"), Eval: jpAbema},
		probe.Check{Service: "Niconico", Requests: probe.Get("https://www.nicovideo.jp/watch/so23017073"), Eval: jpNiconico},
		probe.Check{Service: "Telasa", Tier: probe.TierB, Requests: []probe.Request{{
			URL:    "https://api-videopass-anon.kddi-video.com/v1/playback/system_status",
			Header: map[string]string{"X-Device-ID": clientids.TelasaDeviceID}}},
			Eval: jpTelasa},
		probe.Check{Service: "U-NEXT", Tier: probe.TierB, Requests: []probe.Request{{Method: http.MethodPost,
			URL: "https://cc.unext.jp/", Body: clientids.UNextPlaylistQuery,
			Header: map[string]string{"Content-Type": "application/json"}}},
			Eval: jkhtCode(probe.BodyRegex(`"resultStatus"\s*:\s*(\d+)`), "200 475", "467")},
		probe.Check{Service: "Hulu Japan", Requests: []probe.Request{{URL: "https://id.hulu.jp/", NoRedirect: true}}, Eval: byRedirect(regexp.MustCompile(`(?i)restrict`), true)},
		probe.Check{Service: "Lemino", Tier: probe.TierB, Requests: []probe.Request{{Method: http.MethodPost,
			URL: "https://if.lemino.docomo.ne.jp/v1/user/delivery/watch/ready", Body: clientids.LeminoWatchReadyBody,
			Header: map[string]string{"Content-Type": "application/json", "Origin": "https://lemino.docomo.ne.jp", "Referer": "https://lemino.docomo.ne.jp/",
				"X-Service-Token": clientids.LeminoServiceToken, "X-Trace-Id": clientids.LeminoTraceID}}},
			Eval: byStatus(http.StatusOK, http.StatusForbidden)},
		probe.Check{Service: "AnimeFesta", Tier: probe.TierB, Requests: []probe.Request{{
			URL: "https://api-animefesta.iowl.jp/v1/titles/1560",
			Header: map[string]string{"Accept": "application/json", "Origin": "https://animefesta.iowl.jp", "Referer": "https://animefesta.iowl.jp/",
				"Anime-User-Tracking-Id": clientids.AnimeFestaTrackingID, "X-Requested-With": "XMLHttpRequest"}}},
			Eval: byStatus(http.StatusOK, http.StatusForbidden)},
		probe.Check{Service: "d Anime Store", Requests: probe.Get("https://animestore.docomo.ne.jp/animestore/reg_pc"), Eval: jpDAnime},
		probe.Check{Service: "FOD", Requests: probe.Get("https://geocontrol1.stream.ne.jp/fod-geo/check.xml"),
			Eval: jkhtCode(probe.BodyRegex(`<FLAG\s+TYPE="([^"]+)"`), "true", "false")},
		probe.Check{Service: "Radiko", Requests: probe.Get("https://radiko.jp/area"), Eval: jpRadiko},
		probe.Check{Service: "Karaoke@DAM", Requests: probe.Get("http://cds1.clubdam.com/vhls-cds1/site/xbox/sample_1.mp4.m3u8"),
			Eval: byStatus(http.StatusOK, http.StatusForbidden)},
		probe.Check{Service: "J:COM On Demand", Requests: probe.Get("https://auth.id2.zaq.ne.jp/login"),
			Eval: byStatus(http.StatusOK, http.StatusForbidden)},
		sharedWatcha,
		probe.Check{Service: "Rakuten TV JP", Requests: probe.Get("https://api-live.tv.rakuten.co.jp/v1/contents/387878/playinfo?device_id=2"),
			Eval: byMarkers([]string{"IS_FOREIGN"}, []string{"in_vod"})},
		probe.Check{Service: "KanColle", Requests: probe.Get("http://203.104.209.7/kcscontents/twitter/maintenance_info.html"),
			Eval: byStatus(http.StatusOK, http.StatusForbidden)},
		probe.Check{Service: "Uma Musume", Requests: probe.Get("https://api-umamusume.cygames.jp/"),
			Eval: byStatus(http.StatusNotFound, http.StatusForbidden)},
		probe.Check{Service: "Princess Connect! Re:Dive", Requests: probe.Get("https://api-priconne-redive.cygames.jp/"),
			Eval: byStatus(http.StatusNotFound, http.StatusForbidden)},
		probe.Check{Service: "Konosuba Fantastic Days", Tier: probe.TierB, Requests: []probe.Request{{Method: http.MethodPost,
			URL: "https://api.konosubafd.jp/api/masterlist", Header: map[string]string{"User-Agent": clientids.KonosubaFDUserAgent}}},
			Eval: byStatus(http.StatusOK, http.StatusForbidden)},
		probe.Check{Service: "Project Sekai", Tier: probe.TierB, Requests: []probe.Request{{
			URL: "https://game-version.sekai.colorfulpalette.org/" + clientids.ProjectSekaiVersionPath, Header: map[string]string{"User-Agent": clientids.ProjectSekaiUserAgent}}},
			Eval: byStatus(http.StatusOK, http.StatusForbidden)},
		probe.Check{Service: "mora", Requests: probe.Get("https://mora.jp/buy?__requestToken=1713764407153&returnUrl=https%3A%2F%2Fmora.jp%2Fpackage%2F43000087%2FTFDS01006B00Z%2F%3Ffmid%3DTOPRNKS%26trackMaterialNo%3D31168909&fromMoraUx=false&deleteMaterial="),
			Eval: byStatus(http.StatusOK, http.StatusForbidden, http.StatusInternalServerError)},
		probe.Check{Service: "music.jp", Requests: probe.Get("https://overseaauth.music-book.jp/globalIpcheck.js"), Eval: jpMusicJP},
		probe.Check{Service: "EroGameScape", Requests: probe.Get("https://erogamescape.org/"), Eval: jpEroGameScape},
	)
}

func jkhtCode(extract func(*probe.Response) string, yesCodes, noCodes string) func([]*probe.Response) []probe.Result {
	yesSet, noSet := strings.Fields(yesCodes), strings.Fields(noCodes)
	return func(rs []*probe.Response) []probe.Result {
		r := rs[0]
		code := extract(r)
		switch {
		case code == "":
			return unknown(r)
		case slices.Contains(yesSet, code):
			return yes("")
		case slices.Contains(noSet, code):
			return no(probe.Truncate(code, 40))
		}
		return unknownWith(r, "code "+code)
	}
}

func jpAbema(rs []*probe.Response) []probe.Result {
	r := rs[0]
	switch cc := countryOf(r, probe.JSONPath("isoCountryCode")); cc {
	case "JP":
		return yes(cc)
	case "":
		return unknown(r)
	default:
		return []probe.Result{{Status: probe.Partial, Country: cc, Reason: "overseas only"}}
	}
}

var (
	jpNicoMeta   = regexp.MustCompile(`server-response" content="\{&quot;meta&quot;:\{&quot;status&quot;:\d+,&quot;code&quot;:&quot;([A-Z_]+)&quot;`)
	jpNicoReason = regexp.MustCompile(`&quot;reasonCode&quot;:&quot;([A-Z_]+)&quot;`)
)

func jpNiconico(rs []*probe.Response) []probe.Result {
	r := rs[0]
	if bytes.Contains(r.Body, []byte("同じ地域")) {
		return no("domestic only")
	}
	m := jpNicoMeta.FindSubmatch(r.Body)
	if m == nil {
		return unknown(r)
	}
	code, reason := string(m[1]), ""
	if rm := jpNicoReason.FindSubmatch(r.Body); rm != nil {
		reason = string(rm[1])
	}
	switch {
	case code == "OK":
		return yes("")
	case reason == "DOMESTIC_VIDEO":
		return no("domestic only")
	}
	return unknownWith(r, strings.TrimSpace(code+" "+reason))
}

func jpTelasa(rs []*probe.Response) []probe.Result {
	r := rs[0]
	if bytes.Contains(bytes.ToLower(r.Body), []byte("iplocationnotallowed")) {
		return no("IPLocationNotAllowed")
	}
	switch t := probe.JSONPath("status.type")(r); t {
	case "OK":
		return yes("")
	case "":
		return unknown(r)
	default:
		return unknownWith(r, t+" "+probe.JSONPath("status.subtype")(r))
	}
}

func jpDAnime(rs []*probe.Response) []probe.Result {
	r := rs[0]
	switch {
	case bytes.Contains(r.Body, []byte("overseas_warn")), bytes.Contains(r.Body, []byte("海外からのアクセス")):
		return no("overseas access")
	case r.Status == http.StatusOK && bytes.Contains(r.Body, []byte("dアニメストア")):
		return yes("")
	}
	return unknown(r)
}

var jpRadikoArea = regexp.MustCompile(`class="([A-Z0-9]+)">([^<]*)<`)

func jpRadiko(rs []*probe.Response) []probe.Result {
	r := rs[0]
	m := jpRadikoArea.FindSubmatch(r.Body)
	if r.Status != http.StatusOK || m == nil {
		return unknown(r)
	}
	class, area := string(m[1]), probe.Truncate(strings.TrimSpace(string(m[2])), 60)
	switch {
	case class == "OUT":
		return []probe.Result{{Status: probe.No, Detail: area}}
	case strings.HasPrefix(class, "JP"):
		return []probe.Result{{Status: probe.Yes, Country: "JP", Detail: area}}
	}
	return unknownWith(r, "area "+class)
}

func jpMusicJP(rs []*probe.Response) []probe.Result {
	r := rs[0]
	switch {
	case r.Status == http.StatusForbidden:
		return no("HTTP 403")
	case r.Status != http.StatusOK:
		return unknown(r)
	case len(bytes.TrimSpace(r.Body)) == 0:
		return no("empty response")
	case bytes.Contains(bytes.ToLower(r.Body), []byte("checkip")):
		return yes("")
	}
	return unknown(r)
}

func jpEroGameScape(rs []*probe.Response) []probe.Result {
	r := rs[0]
	switch {
	case r.Status == http.StatusForbidden:
		return no("HTTP 403")
	case r.Status == http.StatusOK && bytes.Contains(r.Body, []byte("18歳")):
		return yes("")
	}
	return unknown(r)
}

func jpDMMTV(rs []*probe.Response) []probe.Result {
	r := rs[0]
	switch {
	case has(r.Body, "FOREIGN"):
		return no("FOREIGN")
	case has(r.Body, "UNAUTHORIZED"):
		return yes("")
	}
	return unknown(r)
}
