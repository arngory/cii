package services

import (
	"net/http"

	"github.com/arngory/cii/internal/clientids"
	"github.com/arngory/cii/internal/probe"
)

func init() {
	register("HK",
		probe.Check{Service: "Now E", Tier: probe.TierB, Requests: []probe.Request{{Method: http.MethodPost,
			URL: "https://webtvapi.nowe.com/16/1/getVodURL", Body: clientids.NowEVodBody,
			Header: map[string]string{"Content-Type": "text/plain", "Origin": "https://www.nowe.com", "Referer": "https://www.nowe.com/"}}},
			Eval: jkhtCode(probe.BodyRegex(`"OTTAPI_ResponseCode"\s*:\s*"([^"]+)"`), "SUCCESS", "GEO_CHECK_FAIL")},
		sharedViu,
		probe.Check{Service: "Viu.TV", Tier: probe.TierB, Requests: []probe.Request{{Method: http.MethodPost,
			URL: "https://api.viu.now.com/p8/3/getLiveURL", Body: clientids.ViuTVLiveBody,
			Header: map[string]string{"Content-Type": "application/json"}}},
			Eval: jkhtCode(probe.BodyRegex(`"responseCode"\s*:\s*"([^"]+)"`), "SUCCESS", "GEO_CHECK_FAIL")},
		probe.Check{Service: "myTV SUPER", Requests: probe.Get("https://www.mytvsuper.com/api/auth/getSession/self/"), Eval: hkMyTVSuper},
		sharedHBOMax,
		hkBilibili("Bilibili HK/MO/TW", "avid=18281381&cid=29892777&ep_id=183799"),
	)
}

func hkBilibili(service, ids string) probe.Check {
	return probe.Check{Service: service,
		Requests: probe.Get("https://api.bilibili.com/pgc/player/web/playurl?" + ids + "&qn=0&type=&otype=json&fourk=1&fnver=0&fnval=16&module=bangumi"),
		Eval:     jkhtCode(probe.BodyRegex(`"code"\s*:\s*(-?\d+)`), "0", "-10403")}
}

func hkMyTVSuper(rs []*probe.Response) []probe.Result {
	r := rs[0]
	c := probe.CountryResult(probe.JSONPath("country_code")(r), r.Status)
	switch {
	case c.Status != probe.OK:
		return []probe.Result{c}
	case c.Country == "HK":
		return yes(c.Country)
	}
	return []probe.Result{{Status: probe.No, Country: c.Country}}
}
