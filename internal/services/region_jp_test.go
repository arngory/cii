package services

import (
	"net/http"
	"testing"

	"github.com/arngory/cii/internal/probe"
)

type jkhtCase struct {
	service string
	resp    *probe.Response
	want    probe.Status
	country string
}

func jkhtCheck(t *testing.T, code, service string) probe.Check {
	t.Helper()
	for _, c := range catalog(code).checks {
		if c.Service == service {
			return c
		}
	}
	t.Fatalf("%s: no check %q", code, service)
	return probe.Check{}
}

func jkhtRun(t *testing.T, code string, cases []jkhtCase) {
	t.Helper()
	for _, c := range cases {
		got := jkhtCheck(t, code, c.service).Eval([]*probe.Response{c.resp})[0]
		if got.Status != c.want || got.Country != c.country {
			t.Errorf("%s/%s %d %.80q = %+v, want %s %q", code, c.service, c.resp.Status, c.resp.Body, got, c.want, c.country)
		}
	}
}

func jkhtTiers(t *testing.T, code string, tierB ...string) {
	t.Helper()
	b := map[string]bool{}
	for _, s := range tierB {
		b[s] = true
	}
	for _, c := range catalog(code).checks {
		if (c.Tier == probe.TierB) != b[c.Service] {
			t.Errorf("%s/%s: tier %d", code, c.Service, c.Tier)
		}
		delete(b, c.Service)
	}
	for s := range b {
		t.Errorf("%s/%s: missing", code, s)
	}
}

func jkhtLoc(status int, loc string) *probe.Response {
	return &probe.Response{Status: status, Header: http.Header{"Location": {loc}}}
}

func TestJPCatalog(t *testing.T) {
	jkhtTiers(t, "JP", "DMM TV", "Telasa", "U-NEXT", "Lemino", "AnimeFesta", "Konosuba Fantastic Days", "Project Sekai")
	nicoBlocked := `<meta name="server-response" content="{&quot;meta&quot;:{&quot;status&quot;:200,&quot;code&quot;:&quot;FORBIDDEN&quot;},&quot;data&quot;:{&quot;reasonCode&quot;:&quot;DOMESTIC_VIDEO&quot;}}">`
	nicoOK := `<meta name="server-response" content="{&quot;meta&quot;:{&quot;status&quot;:200,&quot;code&quot;:&quot;OK&quot;},&quot;data&quot;:{}}">`
	jkhtRun(t, "JP", []jkhtCase{
		{"DMM TV", r(403, `{"errors":[{"code":"FOREIGN"}]}`), probe.No, ""},
		{"DMM TV", r(401, `{"errors":[{"code":"UNAUTHORIZED"}]}`), probe.Yes, ""},
		{"DMM TV", r(503, `maintenance`), probe.Failed, ""},
		{"ABEMA", r(200, `{"isoCountryCode":"JP","timeZone":"Asia/Tokyo"}`), probe.Yes, "JP"},
		{"ABEMA", r(200, `{"isoCountryCode":"US","timeZone":"America/Chicago","utcOffset":"-06:00","division":1}`), probe.Partial, "US"},
		{"ABEMA", r(403, `{}`), probe.Failed, ""},
		{"Niconico", r(200, nicoBlocked), probe.No, ""},
		{"Niconico", r(200, nicoOK), probe.Yes, ""},
		{"Niconico", r(200, `<html>maintenance</html>`), probe.Unknown, ""},
		{"Telasa", r(200, `{"status":{"type":"OK","subtype":null},"data":{}}`), probe.Yes, ""},
		{"Telasa", r(403, `{"status":{"type":"Forbidden","subtype":"IPLocationNotAllowed"}}`), probe.No, ""},
		{"Telasa", r(400, `{"status":{"type":"BadRequest","subtype":"InvalidDeviceID","message":"Header X-Device-ID not specify"},"data":null}`), probe.Failed, ""},
		{"U-NEXT", r(200, `{"data":{"webfront_playlistUrl":{"resultStatus":475}}}`), probe.Yes, ""},
		{"U-NEXT", r(200, `{"data":{"webfront_playlistUrl":{"resultStatus":467}}}`), probe.No, ""},
		{"U-NEXT", r(200, `{"data":{"webfront_playlistUrl":{"resultStatus":500}}}`), probe.Unknown, ""},
		{"Hulu Japan", r(403, `<title>Hulu</title>`), probe.No, ""},
		{"Hulu Japan", jkhtLoc(302, "https://www.hulu.jp/restrict"), probe.No, ""},
		{"Hulu Japan", r(200, `<html></html>`), probe.Yes, ""},
		{"Hulu Japan", jkhtLoc(302, "https://id.hulu.jp/login"), probe.Unknown, ""},
		{"Lemino", r(200, `{}`), probe.Yes, ""},
		{"Lemino", r(403, `{}`), probe.No, ""},
		{"Lemino", r(401, `{}`), probe.Failed, ""},
		{"AnimeFesta", r(403, `<title>403 Forbidden</title>`), probe.No, ""},
		{"d Anime Store", r(200, `<title>海外からのアクセスについて</title><meta http-equiv="refresh" content="0; url=/animestore/CF/overseas_warn">`), probe.No, ""},
		{"d Anime Store", r(200, `<title>dアニメストア</title>`), probe.Yes, ""},
		{"d Anime Store", r(200, `<html></html>`), probe.Unknown, ""},
		{"FOD", r(200, `<?xml version="1.0" encoding="UTF-8" ?><RESULT><FLAG TYPE="false" /></RESULT>`), probe.No, ""},
		{"FOD", r(200, `<RESULT><FLAG TYPE="true" /></RESULT>`), probe.Yes, ""},
		{"FOD", r(200, ``), probe.Unknown, ""},
		{"Radiko", r(200, `document.write('<span class="OUT">CALIFORNIA UNITED STATES OF AMERICA</span>');`), probe.No, ""},
		{"Radiko", r(200, `document.write('<span class="JP13">TOKYO JAPAN</span>');`), probe.Yes, "JP"},
		{"Radiko", r(500, ``), probe.Failed, ""},
		{"Karaoke@DAM", r(403, `<title>403 Forbidden</title>`), probe.No, ""},
		{"Karaoke@DAM", r(200, `#EXTM3U`), probe.Yes, ""},
		{"J:COM On Demand", r(403, `Sorry, you have been blocked`), probe.No, ""},
		{"WATCHA", r(451, ``), probe.No, ""},
		{"WATCHA", r(200, `<title>왓챠</title>`), probe.Yes, ""},
		{"Rakuten TV JP", r(403, `{"result":{"code":"40312349342","message":"IS_FOREIGN, IP:192.0.2.1","exception":"NotDomesticException"},"status":"fail"}`), probe.No, ""},
		{"Rakuten TV JP", r(200, `{"result":{"in_vod":true}}`), probe.Yes, ""},
		{"Rakuten TV JP", r(502, `bad gateway`), probe.Failed, ""},
		{"KanColle", r(503, `upstream connect error`), probe.Failed, ""},
		{"Uma Musume", r(404, ``), probe.Yes, ""},
		{"Uma Musume", r(403, ``), probe.No, ""},
		{"Uma Musume", r(200, ``), probe.Unknown, ""},
		{"Princess Connect! Re:Dive", r(404, ``), probe.Yes, ""},
		{"Konosuba Fantastic Days", r(200, `{}`), probe.Yes, ""},
		{"Project Sekai", r(403, ``), probe.No, ""},
		{"mora", r(500, `error`), probe.No, ""},
		{"mora", r(200, `<html>`), probe.Yes, ""},
		{"music.jp", r(403, ``), probe.No, ""},
		{"music.jp", r(200, ``), probe.No, ""},
		{"music.jp", r(200, `function checkIp(){}`), probe.Yes, ""},
		{"music.jp", r(200, `<html>error</html>`), probe.Unknown, ""},
		{"EroGameScape", r(200, `<p>18歳未満の方は</p>`), probe.Yes, ""},
		{"EroGameScape", r(200, `<html></html>`), probe.Unknown, ""},
	})
}
