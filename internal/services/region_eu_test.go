package services

import (
	"net/http"
	"testing"

	"github.com/arngory/cii/internal/probe"
)

type eossCase struct {
	service string
	resp    *probe.Response
	want    probe.Status
	country string
}

func eossResp(status int, body string, header ...string) *probe.Response {
	h := http.Header{}
	for i := 0; i+1 < len(header); i += 2 {
		h.Add(header[i], header[i+1])
	}
	return &probe.Response{Status: status, Header: h, Body: []byte(body)}
}

func eossRun(t *testing.T, code string, cases []eossCase) {
	t.Helper()
	checks := map[string]probe.Check{}
	for _, ch := range catalog(code).checks {
		checks[ch.Service] = ch
	}
	for _, c := range cases {
		ch, ok := checks[c.service]
		if !ok {
			t.Errorf("%s: no check %q", code, c.service)
			continue
		}
		res := ch.Eval([]*probe.Response{c.resp})
		if len(res) == 0 || res[0].Status != c.want || res[0].Country != c.country {
			t.Errorf("%s/%s HTTP %d %.60q = %+v, want %s %s", code, c.service, c.resp.Status, c.resp.Body, res, c.want, c.country)
		}
	}
}

func TestEUChecks(t *testing.T) {
	akamaiDenied := "<HTML><HEAD>\n<TITLE>Access Denied</TITLE>\n</HEAD><BODY>\n<H1>Access Denied</H1>\nYou don't have permission to access \"http&#58;&#47;&#47;example\" on this server.<P>"
	eossRun(t, "EU", []eossCase{
		{"Paramount+", eossResp(200, `<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"intcid":"","promo":"","region":"US","regionFromUrl":null}}}`), probe.Yes, "US"},
		{"Paramount+", eossResp(200, `{"props":{"pageProps":{"region":"intl"}}}`), probe.No, ""},
		{"Paramount+", eossResp(200, `<html>maintenance</html>`), probe.Unknown, ""},
		{"Paramount+", eossResp(503, ``), probe.Failed, ""},

		{"HBO Max", eossResp(403, akamaiDenied, "Set-Cookie", "countryCode=US; path=/; domain=.hbomax.com"), probe.IPBlock, "US"},
		{"HBO Max", eossResp(200, `{"url":"/pl/en"},{"url":"/es/es"}`, "Set-Cookie", "countryCode=PL; path=/"), probe.Yes, "PL"},
		{"HBO Max", eossResp(200, `{"url":"/pl/en"},{"url":"/es/es"}`, "Set-Cookie", "countryCode=RU; path=/"), probe.No, "RU"},
		{"HBO Max", eossResp(200, `<html></html>`, "Set-Cookie", "countryCode=DE; path=/"), probe.Unknown, "DE"},
		{"HBO Max", eossResp(200, `{"url":"/pl/en"}`), probe.Unknown, ""},

		{"SkyShowTime", eossResp(200, `"__ICEBERG_TERRITORY__":{"territoryLocale":"xx"},"territory":"XX"`), probe.No, ""},
		{"SkyShowTime", eossResp(200, `{"territory":"PL","language":"pl-PL"}`), probe.Yes, "PL"},
		{"SkyShowTime", eossResp(200, `<a href="/where-can-i-stream">`), probe.No, ""},
		{"SkyShowTime", eossResp(403, ``), probe.No, ""},
		{"SkyShowTime", eossResp(200, `<html></html>`), probe.Unknown, ""},

		{"BritBox", eossResp(200, `<title>Home | BritBox US</title>`), probe.Yes, ""},
		{"BritBox", eossResp(302, ``, "Location", "https://www.britbox.com/locationnotsupported"), probe.No, ""},
		{"BritBox", eossResp(301, ``, "Location", "https://www.britbox.co.uk/"), probe.No, ""},
		{"BritBox", eossResp(302, ``, "Location", "/us/"), probe.Unknown, ""},

		{"Megogo", eossResp(200, `<html lang="en" data-lang="en" data-geo="us" data-locale="en">`), probe.Yes, "US"},
		{"Megogo", eossResp(200, `<html data-geo="de">Please disable your VPN</html>`), probe.IPBlock, ""},
		{"Megogo", eossResp(200, `<html></html>`), probe.Unknown, ""},

		{"Setanta Sports", eossResp(200, `{"outsideAllowedTerritories":false}`), probe.Yes, ""},
		{"Setanta Sports", eossResp(200, `{"outsideAllowedTerritories": true}`), probe.No, ""},
		{"Setanta Sports", eossResp(401, `{"messages":["bad key"]}`), probe.Failed, ""},

		{"Hotstar", eossResp(302, ``, "Location", "https://www.hotstar.com/us", "Set-Cookie", "AK_SERVER_TIME=1; path=/", "Set-Cookie", "geo=US,TX,DALLAS,32.7874,-96.7989,396982; secure"), probe.No, "US"},
		{"Hotstar", eossResp(302, ``, "Location", "https://www.hotstar.com/sg/home", "Set-Cookie", "geo=SG,01,SINGAPORE; secure"), probe.Yes, "SG"},
		{"Hotstar", eossResp(302, ``, "Location", "https://www.hotstar.com/in", "Set-Cookie", "geo=GB,ENG,LONDON; secure"), probe.Unknown, "GB"},
		{"Hotstar", eossResp(475, ``), probe.No, ""},
		{"Hotstar", eossResp(200, ``), probe.Unknown, ""},

		{"Channel 4", eossResp(200, `<html></html>`), probe.Yes, ""},
		{"Channel 4", eossResp(403, `{"error":{"code":403,"message":"Failed to fetch data"}}`), probe.No, ""},
		{"Channel 4", eossResp(500, ``), probe.Failed, ""},

		{"BBC iPlayer", eossResp(200, `/**/ JS_callbacks0({"disclaimer":"...","result":"geolocation"});`), probe.No, ""},
		{"BBC iPlayer", eossResp(200, `JS_callbacks0({"media":[{"connection":[{"supplier":"mf_akamai","href":"https://vs-hls-push-uk.live.cf.md.bbci.co.uk/x.m3u8"}]}]});`), probe.Yes, ""},
		{"BBC iPlayer", eossResp(200, `JS_callbacks0({"result":"selectionunavailable"});`), probe.Unknown, ""},

		{"Acorn TV", eossResp(200, `<a href="https://signup.acorn.tv/">Start</a>`), probe.Yes, ""},
		{"Acorn TV", eossResp(200, `Acorn TV is not yet available in your country`), probe.No, ""},
		{"Acorn TV", eossResp(502, `bad gateway`), probe.Failed, ""},

		{"Shudder", eossResp(200, `<title>SHUDDER</title><a>Movies</a>`), probe.Yes, ""},
		{"Shudder", eossResp(200, `Shudder is not available in your region`), probe.No, ""},
		{"Shudder", eossResp(200, `<html></html>`), probe.Unknown, ""},

		{"Canal+", eossResp(302, ``, "Location", "https://boutique-tunnel.canalplus.com/other-country-blocking"), probe.No, ""},
		{"Canal+", eossResp(200, `<html></html>`), probe.Yes, ""},
		{"Canal+", eossResp(403, `{"message":"Unexpected Request"}`), probe.Failed, ""},

		{"Molotov", eossResp(200, `{"is_france":false}`), probe.No, ""},
		{"Molotov", eossResp(200, `{"is_france":true}`), probe.Yes, ""},
		{"Molotov", eossResp(200, `{}`), probe.Unknown, ""},

		{"ZDF", eossResp(404, ``), probe.Yes, ""},
		{"ZDF", eossResp(403, akamaiDenied), probe.No, ""},
		{"ZDF", eossResp(200, ``), probe.Unknown, ""},

		{"Rai Play", eossResp(200, `<Mediapolis><url type="content"><![CDATA[https://download-rai-it.akamaized.net/video_no_available.mp4]]></url><geoprotection>N</geoprotection></Mediapolis>`), probe.No, ""},
		{"Rai Play", eossResp(200, `<Mediapolis><url type="content"><![CDATA[https://x/manifest.mpd]]></url><geoprotection>Y</geoprotection></Mediapolis>`), probe.Yes, ""},
		{"Rai Play", eossResp(200, `<Mediapolis></Mediapolis>`), probe.Unknown, ""},

		{"Sky CH", eossResp(403, `{"Message": "", "Code": "FW_ERROR"}`), probe.No, ""},
		{"Sky CH", eossResp(302, ``, "Location", "https://www.sky.ch/en/out-of-country"), probe.No, ""},
		{"Sky CH", eossResp(200, `<html></html>`), probe.Yes, ""},
		{"Sky CH", eossResp(302, ``, "Location", "https://www.sky.ch/de"), probe.Unknown, ""},

		{"Rakuten TV", eossResp(200, `{"data":{"user":{"profile":{"streaming_drm_types":[]}},"market":{"iso3166_code":"es"}}}`), probe.Yes, "ES"},
		{"Rakuten TV", eossResp(403, `{"errors":[{"code":"forbidden_vpn","message":"VPN detected"}]}`), probe.IPBlock, ""},
		{"Rakuten TV", eossResp(422, `{"errors":[{"message":"Rakuten TV is not available in your country"}]}`), probe.No, ""},
		{"Rakuten TV", eossResp(200, `{"data":{}}`), probe.Unknown, ""},

		{"Sky Go", eossResp(200, `<div id="skygoSignin">`), probe.Yes, ""},
		{"Sky Go", eossResp(403, akamaiDenied), probe.No, ""},
		{"Sky Go", eossResp(200, `<html></html>`), probe.Unknown, ""},

		{"ITVX", eossResp(200, `{"Playlist":{"Video":{}}}`), probe.Yes, ""},
		{"ITVX", eossResp(403, `{"Message":"Outside Of Allowed Geographic Region"}`), probe.No, ""},
		{"ITVX", eossResp(400, `{"Message":"bad request"}`), probe.Failed, ""},

		{"Channel 5", eossResp(403, `{"code":"3000","message":"geo"}`), probe.No, ""},
		{"Channel 5", eossResp(403, `{"code":"4003","message":"auth"}`), probe.Yes, ""},
		{"Channel 5", eossResp(200, `{}`), probe.Unknown, ""},

		{"Sky DE", eossResp(403, `[{"error_code":"ACCESS_DENIED","error_subcode":"CLIENT_GEO","client_geo":"us"}]`), probe.No, ""},
		{"Sky DE", eossResp(200, `{"sources":[{"src":"https://x"}],"id":"6247131490001"}`), probe.Yes, ""},
		{"Sky DE", eossResp(403, `[{"error_code":"ACCESS_DENIED","error_subcode":"CLIENT_IP"}]`), probe.Failed, ""},
		{"Sky DE", eossResp(200, `{}`), probe.Unknown, ""},

		{"Videoland", eossResp(200, `{"data":{"isOnboardingGeoBlocked":false}}`), probe.Yes, ""},
		{"Videoland", eossResp(200, `{"data":{"isOnboardingGeoBlocked":true}}`), probe.No, ""},
		{"Videoland", eossResp(500, `{"errors":[]}`), probe.Failed, ""},
	})
}

func TestEOSSCatalogHosts(t *testing.T) {
	for _, code := range []string{"EU", "OC", "SEA", "SPORT"} {
		seen := map[string]bool{}
		for _, ch := range catalog(code).checks {
			if seen[ch.Service] {
				t.Errorf("%s: duplicate service %q", code, ch.Service)
			}
			seen[ch.Service] = true
			for _, rq := range ch.Requests {
				if rq.URL == "" || rq.URL[:8] != "https://" {
					t.Errorf("%s/%s: bad URL %q", code, ch.Service, rq.URL)
				}
			}
		}
		if len(seen) == 0 {
			t.Errorf("%s: empty catalog", code)
		}
	}
}
