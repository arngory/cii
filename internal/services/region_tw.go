package services

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net/http"
	"regexp"

	"github.com/arngory/cii/internal/clientids"
	"github.com/arngory/cii/internal/probe"
)

func init() {
	register("TW",
		probe.Check{Service: "KKTV", Requests: probe.Get("https://api.kktv.me/v3/ipcheck"), Eval: twKKTV},
		probe.Check{Service: "LiTV", Tier: probe.TierB, Requests: []probe.Request{{Method: http.MethodPost,
			URL: "https://www.litv.tv/api/get-urls-no-auth", Body: fmt.Sprintf(clientids.LiTVURLsBodyFormat, twUUID()),
			Header: map[string]string{"Content-Type": "application/json", "Origin": "https://www.litv.tv", "Referer": "https://www.litv.tv/drama/watch/VOD00328856"}}},
			Eval: twLiTV},
		probe.Check{Service: "MyVideo", Requests: []probe.Request{{URL: "https://www.myvideo.net.tw/login.do", NoRedirect: true}}, Eval: byRedirect(regexp.MustCompile(`(?i)serviceAreaBlock`), true)},
		probe.Check{Service: "4GTV", Tier: probe.TierB, Requests: []probe.Request{{
			URL:    "https://api2.4gtv.tv/Web/IsTaiwanArea",
			Header: map[string]string{"Origin": "https://www.4gtv.tv", "Referer": "https://www.4gtv.tv/"}}},
			Eval: jkhtCode(probe.BodyRegex(`"Data"\s*:\s*"([^"]+)"`), "Y", "N")},
		probe.Check{Service: "LINE TV", Tier: probe.TierB, Requests: probe.Get("https://www.linetv.tw/api/part/11829/eps/1/part?appId=" + clientids.LineTVTWAppID + "&productType=FAST&version=10.38.0"),
			Eval: twLineTV},
		probe.Check{Service: "Hami Video", Requests: probe.Get("https://hamivideo.hinet.net/api/play.do?id=OTT_VOD_0000249064&freeProduct=1"),
			Eval: jkhtCode(probe.BodyRegex(`"code"\s*:\s*"([^"]+)"`), "06001-107", "06001-106")},
		probe.Check{Service: "CatchPlay+", Tier: probe.TierB, Requests: []probe.Request{{
			URL: "https://sunapi.catchplay.com/geo", Header: map[string]string{"Authorization": "Basic " + clientids.CatchPlayBasicAuth}}},
			Eval: jkhtCode(probe.BodyRegex(`"code"\s*:\s*"([^"]+)"`), "0", "100016")},
		sharedHBOMax,
		hkBilibili("Bilibili TW", "avid=50762638&cid=100279344&ep_id=268176"),
	)
}

var twKKTVAllowed = regexp.MustCompile(`"is_allowed"\s*:\s*(true|false)`)

func twKKTV(rs []*probe.Response) []probe.Result {
	r := rs[0]
	cc := countryOf(r, probe.JSONPath("data.country"))
	allowed := ""
	if m := twKKTVAllowed.FindSubmatch(r.Body); m != nil {
		allowed = string(m[1])
	}
	switch {
	case allowed == "true", allowed == "" && cc == "TW":
		return yes(cc)
	case allowed == "false", cc != "":
		return []probe.Result{{Status: probe.No, Country: cc}}
	}
	return unknown(r)
}

var twLiTVCode = probe.BodyRegex(`"code"\s*:\s*(\d+)`)

func twLiTV(rs []*probe.Response) []probe.Result {
	if bytes.Contains(rs[0].Body, []byte("AssetURLs")) {
		return yes("")
	}
	return jkhtCode(twLiTVCode, "42000075", "42000087")(rs)
}

var twLineTVCountry = probe.BodyRegex(`"countryCode"\s*:\s*(\d+)`)

func twLineTV(rs []*probe.Response) []probe.Result {
	r := rs[0]
	switch code := twLineTVCountry(r); code {
	case "228":
		return yes("")
	case "":
		return unknown(r)
	default:
		return no("countryCode " + code)
	}
}

func twUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
