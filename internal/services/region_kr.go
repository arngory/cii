package services

import (
	"net/http"
	"regexp"

	"github.com/arngory/cii/internal/clientids"
	"github.com/arngory/cii/internal/probe"
)

func init() {
	register("KR",
		probe.Check{Service: "Wavve", Tier: probe.TierB, Requests: probe.Get("https://apis.wavve.com/fz/streaming?" + clientids.WavveStreamingQuery),
			Eval: byStatus(http.StatusOK, http.StatusForbidden, 550)},
		probe.Check{Service: "TVING", Tier: probe.TierB, Requests: probe.Get("https://api.tving.com/v2a/media/stream/info?apiKey=" + clientids.TvingAPIKey + "&mediaCode=RV60891248"),
			Eval: byMarkers([]string{"available in South Korea"}, []string{"vod_type"})},
		sharedWatcha,
		probe.Check{Service: "Coupang Play", Requests: []probe.Request{{URL: "https://www.coupangplay.com/", NoRedirect: true}}, Eval: byRedirect(regexp.MustCompile(`(?i)not-available`), true)},
		brightcoveCheck("SPOTV NOW", "5764318566001", "6349973203112", clientids.SpotvNowBrightcoveKey, "https://www.spotvnow.co.kr"),
		probe.Check{Service: "KBS Domestic", Requests: probe.Get("https://vod.kbs.co.kr/index.html?source=episode&sname=vod&stype=vod&program_code=T2022-0690&program_id=PS-2022164275-01-000&broadcast_complete_yn=N&local_station_code=00&section_code=03"),
			Eval: krKBS},
	)
}

var krKBSDomestic = regexp.MustCompile(`ipck[^\n]*?Domestic\\?"\s*:\s*(true|false)`)

func krKBS(rs []*probe.Response) []probe.Result {
	r := rs[0]
	m := krKBSDomestic.FindSubmatch(r.Body)
	switch {
	case m == nil:
		return unknown(r)
	case string(m[1]) == "true":
		return yes("")
	}
	return no("not domestic")
}
