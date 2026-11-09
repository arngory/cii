package services

import (
	"net/http"
	"testing"

	"github.com/arngory/cii/internal/probe"
)

type naCase struct {
	service string
	resp    *probe.Response
	want    probe.Status
	country string
}

func naResp(status int, body string, kv ...string) *probe.Response {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return &probe.Response{Status: status, Header: h, Body: []byte(body)}
}

func naCheck(t *testing.T, code, service string) probe.Check {
	t.Helper()
	c := catalog(code)
	if c == nil {
		t.Fatalf("no catalog %s", code)
	}
	for _, ch := range c.checks {
		if ch.Service == service {
			return ch
		}
	}
	t.Fatalf("no check %s/%s", code, service)
	return probe.Check{}
}

func naRun(t *testing.T, code string, cases []naCase) {
	t.Helper()
	for _, c := range cases {
		res := naCheck(t, code, c.service).Eval([]*probe.Response{c.resp})[0]
		if res.Status != c.want || res.Country != c.country {
			t.Errorf("%s/%s %d %q %v = %+v, want %s %q", code, c.service, c.resp.Status, c.resp.Body, c.resp.Header, res, c.want, c.country)
		}
	}
}

const naAkamai = `<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY>You don't have permission to access "http&#58;&#47;&#47;www&#46;nba&#46;com&#47;watch&#47;" on this server.</BODY></HTML>`

func TestNorthAmerica(t *testing.T) {
	naRun(t, "NA", []naCase{
		{"Paramount+", naResp(200, `{"props":{"pageProps":{"intcid":"","cbscidmt":"","promo":"","region":"US"}}}`), probe.Yes, "US"},
		{"Paramount+", naResp(200, `{"pageProps":{"region":"intl"}}`), probe.No, ""},
		{"Paramount+", naResp(200, `<html>Paramount</html>`), probe.Unknown, ""},
		{"Paramount+", naResp(503, ``), probe.Failed, ""},

		{"Acorn TV", naResp(200, `<a href="https://signup.acorn.tv/">Start</a>`), probe.Yes, ""},
		{"Acorn TV", naResp(200, `Acorn TV is not yet available in your country`), probe.No, ""},
		{"Acorn TV", naResp(200, `<html></html>`), probe.Unknown, ""},

		{"BritBox", naResp(200, `<title>Home | BritBox US</title><a href="https://www.britbox.co.uk/">UK</a>`), probe.Yes, ""},
		{"BritBox", naResp(302, ``, "Location", "https://www.britbox.com/locationnotsupported"), probe.No, ""},
		{"BritBox", naResp(301, ``, "Location", "https://www.britbox.co.uk/"), probe.No, ""},
		{"BritBox", naResp(302, ``, "Location", "https://www.britbox.com/us/"), probe.Unknown, ""},

		{"Shudder", naResp(200, `<title>SHUDDER | Stream Horror</title>`), probe.Yes, ""},
		{"Shudder", naResp(403, `<H1>403 ERROR</H1>The request could not be satisfied.`), probe.No, ""},
		{"Shudder", naResp(200, `<html></html>`), probe.Unknown, ""},

		{"Fubo TV", naResp(200, `{"country_code":"USA","country_code2":"US","country_name":"united states","network_allowed":true}`), probe.Yes, "US"},
		{"Fubo TV", naResp(200, `{"country_code2":"DE","network_allowed":false}`), probe.IPBlock, "DE"},
		{"Fubo TV", naResp(403, `{"error":{"code":"NO_SERVICE_IN_COUNTRY"}}`), probe.No, ""},
		{"Fubo TV", naResp(500, `oops`), probe.Failed, ""},

		{"Tubi TV", naResp(200, `<link rel="manifest" href="/manifest.json">`), probe.Yes, ""},
		{"Tubi TV", naResp(200, `Tubi is not currently available in your area.`), probe.No, ""},

		{"Pluto TV", naResp(200, `<title>Pluto TV</title>{"region":"US"} unavailable`), probe.Yes, "US"},
		{"Pluto TV", naResp(302, ``, "Location", "https://pluto.tv/en/plutotv-is-not-available"), probe.No, ""},
		{"Pluto TV", naResp(302, ``, "Location", "https://pluto.tv/latam/"), probe.Unknown, ""},

		{"KOCOWA", naResp(200, `<title>KOCOWA+ - Premium streaming</title>`), probe.Yes, ""},
		{"KOCOWA", naResp(403, ``), probe.No, ""},
		{"KOCOWA", naResp(200, `<html></html>`), probe.Unknown, ""},

		{"AMC+", naResp(200, `<title>AMC+ | Premium Streaming Service</title>`), probe.Yes, ""},
		{"AMC+", naResp(302, ``, "Location", "https://www.amcplus.com/pages/geographic-restriction"), probe.No, ""},
		{"AMC+", naResp(403, ``), probe.No, ""},

		{"NFL+", naResp(200, `<title>NFL+ Home</title>`), probe.Yes, ""},
		{"NFL+", naResp(302, ``, "Location", "https://www.nflgamepass.com/nfl-game-pass"), probe.No, ""},
		{"NFL+", naResp(308, ``, "Location", "/plus/"), probe.Unknown, ""},

		{"Philo", naResp(200, `{"status": "SUCCESS", "city": "san francisco", "country": "US", "connection": "broadband"}`), probe.Yes, "US"},
		{"Philo", naResp(200, `{"status": "FAIL", "country": "GB"}`), probe.No, "GB"},
		{"Philo", naResp(200, `{}`), probe.Unknown, ""},

		{"FXNOW", naResp(200, `<title>FXNOW - Watch Full Episodes of FX Shows &amp; Movies</title>FX Movies`), probe.Yes, ""},
		{"FXNOW", naResp(200, `FXNOW is not accessible outside the U.S.`), probe.No, ""},

		{"CW TV", naResp(200, `<title>The CW Network</title>`), probe.Yes, ""},
		{"CW TV", naResp(451, ``), probe.No, ""},

		{"A&E TV", naResp(200, ``, "Aetn-Country-Code", "US"), probe.Yes, "US"},
		{"A&E TV", naResp(200, ``, "Set-Cookie", "AETN-Country-Code=CA; path=/"), probe.Yes, "CA"},
		{"A&E TV", naResp(200, ``, "Aetn-Country-Code", "DE"), probe.No, "DE"},
		{"A&E TV", naResp(200, ``), probe.Unknown, ""},

		{"Sling TV", naResp(200, `<title>Sling TV: Stream Live TV</title> unavailable`), probe.Yes, ""},
		{"Sling TV", naResp(302, ``, "Location", "https://www.sling.com/geo-block"), probe.No, ""},

		{"Peacock TV", naResp(200, `<title>Peacock: Stream TV</title>{"territory":"US"} unavailable`), probe.Yes, "US"},
		{"Peacock TV", naResp(302, ``, "Location", "https://www.peacocktv.com/unavailable"), probe.No, ""},

		{"DirecTV Stream", naResp(200, `<title>Stream TV, Watch Live Television Online | DIRECTV</title>`), probe.Yes, ""},
		{"DirecTV Stream", naResp(403, ``), probe.No, ""},

		{"Hotstar", naResp(302, ``, "Location", "https://www.hotstar.com/us", "Set-Cookie", "geo=US,TX,DALLAS,32.7874,-96.7989,396982; secure"), probe.No, "US"},
		{"Hotstar", naResp(302, ``, "Location", "https://www.hotstar.com/ca", "Set-Cookie", "geo=CA,ON,TORONTO"), probe.Yes, "CA"},
		{"Hotstar", naResp(302, ``, "Location", "https://www.hotstar.com/ca", "Set-Cookie", "geo=SG,SG,SINGAPORE"), probe.Unknown, "SG"},
		{"Hotstar", naResp(475, ``), probe.No, ""},
		{"Hotstar", naResp(200, ``), probe.Unknown, ""},

		{"CBC Gem", naResp(200, `var s = {"country":"CA","region":"ON"};`), probe.Yes, "CA"},
		{"CBC Gem", naResp(200, `var s = {"country" : "US"};`), probe.No, "US"},
		{"CBC Gem", naResp(200, `var s = {};`), probe.Unknown, ""},

		{"HBO Max", naResp(200, `<html>`, "Set-Cookie", "countryCode=US; Path=/"), probe.Yes, "US"},
		{"HBO Max", naResp(200, `[{"url":"/es/es"},{"url":"/br/pt"}]`, "Set-Cookie", "countryCode=BR; Path=/"), probe.Yes, "BR"},
		{"HBO Max", naResp(200, `[{"url":"/es/es"}] countryCode=RU`), probe.No, "RU"},
		{"HBO Max", naResp(200, `countryCode=RU`), probe.Unknown, "RU"},
		{"HBO Max", naResp(403, naAkamai), probe.IPBlock, ""},

		{"NBA TV", naResp(200, `<title>NBA League Pass</title>`), probe.Yes, ""},
		{"NBA TV", naResp(200, `Service is not available in your region`), probe.No, ""},
		{"NBA TV", naResp(403, naAkamai), probe.IPBlock, ""},

		{"NBC TV", naResp(200, `{"restricted":false,"requestorCountry":"US"}`), probe.Yes, ""},
		{"NBC TV", naResp(200, `{"restricted": true}`), probe.No, ""},
		{"NBC TV", naResp(401, `{"message":"Unauthorized"}`), probe.Failed, ""},

		{"encoreTVB", naResp(200, `{"id":"6005570109001","sources":[{"src":"https://x"}]}`), probe.Yes, ""},
		{"encoreTVB", naResp(403, `[{"error_code":"ACCESS_DENIED","error_subcode":"CLIENT_GEO","message":"Access to this resource is forbidden by access policy."}]`), probe.No, ""},
		{"encoreTVB", naResp(404, `[{"error_code":"RESOURCE_NOT_FOUND","error_subcode":"VIDEO_NOT_FOUND"}]`), probe.Failed, ""},
		{"encoreTVB", naResp(200, `{}`), probe.Unknown, ""},

		{"Crave", naResp(200, `<MPD><BaseURL>https://video.9c9media.com/x</BaseURL></MPD>`), probe.Yes, ""},
		{"Crave", naResp(403, `{"Message":"Geo Constraint Restrictions"}`), probe.No, ""},
		{"Crave", naResp(404, ``), probe.Failed, ""},
	})
}

func TestNorthAmericaTiers(t *testing.T) {
	for _, s := range []string{"NBC TV", "encoreTVB", "Crave"} {
		if naCheck(t, "NA", s).Tier != probe.TierB {
			t.Errorf("%s must be tier B", s)
		}
	}
	for _, s := range []string{"Paramount+", "Fubo TV", "Philo", "Hotstar", "A&E TV", "HBO Max", "NBA TV"} {
		if naCheck(t, "NA", s).Tier != probe.TierA {
			t.Errorf("%s must be tier A", s)
		}
	}
	if id := naSessionID(); len(id) != 36 || id == naSessionID() {
		t.Errorf("session id %q", id)
	}
}
