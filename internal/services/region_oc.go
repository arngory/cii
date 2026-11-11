package services

import (
	"bytes"
	"net/http"

	"github.com/arngory/cii/internal/clientids"
	"github.com/arngory/cii/internal/probe"
)

func init() {
	register("OC",
		sharedNBATV,
		sharedAcornTV,
		sharedBritBox,
		sharedParamountPlus,
		sharedAMCPlus,
		probe.Check{Service: "DocPlay", Requests: noRedirect("https://www.docplay.com/subscribe"), Eval: eossDocPlay},
		probe.Check{Service: "ABC iview", Requests: probe.Get("https://api.iview.abc.net.au/v2/show/abc-kids-live-stream/video/LS1604H001S00?embed=highlightVideo,selectedSeries"),
			Eval: byMarkers([]string{"unavailable outside Australia"}, []string{`"playable":true`})},
		probe.Check{Service: "9Now", Requests: probe.Get("https://login.nine.com.au/"), Eval: byMarkers([]string{"Geoblock"}, []string{"Log in to"})},
		probe.Check{Service: "10 Play", Requests: probe.Get("https://e410fasadvz.global.ssl.fastly.net/geo"), Eval: byBool(`"allow"`, true)},
		probe.Check{Service: "SBS On Demand", Requests: probe.Get("https://www.sbs.com.au/api/v3/network?context=odwebsite"), Eval: eossSBS},

		probe.Check{Service: "Sky Go NZ", Tier: probe.TierB, Requests: probe.Get("https://login.sky.co.nz/authorize?" + clientids.SkyGoNZAuthorizeQuery),
			Eval: byStatus(http.StatusOK, http.StatusForbidden)},
	)
}

func eossDocPlay(rs []*probe.Response) []probe.Result {
	r := rs[0]
	switch {
	case bytes.Contains([]byte(r.Header.Get("Location")), []byte("geoblocked")), r.Status == http.StatusForbidden:
		return no("")
	case r.Status != http.StatusOK:
		return unknown(r)
	case has(r.Body, "launched in your part of the world", "background-geoblocked"):
		return no("not launched in this country")
	case has(r.Body, "DocPlay"):
		return yes("")
	}
	return unknown(r)
}

var eossSBSCountry = probe.JSONPath("get.response.country_code")

func eossSBS(rs []*probe.Response) []probe.Result {
	r := rs[0]
	cc := toCC(eossSBSCountry(r))
	switch {
	case cc == "AU":
		return yes(cc)
	case cc != "":
		return []probe.Result{{Status: probe.No, Country: cc}}
	}
	return unknown(r)
}
