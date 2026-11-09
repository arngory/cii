package services

import (
	"net/http"

	"github.com/arngory/cii/internal/probe"
)

func init() {
	register("SEA",
		sharedViu,
		sharedHotstar,
		sharedHBOMax,
		eossBGlobal("B-Global (Southeast Asia)", "347666"),
		eossBGlobal("B-Global (Thailand)", "10077726"),
		eossBGlobal("B-Global (Indonesia)", "11130043"),
		eossBGlobal("B-Global (Vietnam)", "11405745"),
		probe.Check{Service: "meWATCH", Requests: probe.Get("https://cdn.mewatch.sg/api/items/97098/videos?delivery=stream%2Cprogressive&ff=idp%2Cldp%2Crpt%2Ccd&lang=en&resolution=External&segments=all"),
			Eval: eossMeWatch},
	)
}

var eossBGlobalCode = probe.BodyRegex(`"code"\s*:\s*(-?\d+)`)

func eossBGlobal(service, episode string) probe.Check {
	return probe.Check{Service: service,
		Requests: probe.Get("https://api.bilibili.tv/intl/gateway/web/playurl?s_locale=en_US&platform=web&ep_id=" + episode),
		Eval: func(rs []*probe.Response) []probe.Result {
			r := rs[0]
			switch code := eossBGlobalCode(r); code {
			case "0":
				return yes("")
			case "10003003", "10004001":
				return no("")
			case "":
				return unknown(r)
			default:
				return []probe.Result{{Status: probe.Unknown, Reason: "code " + probe.Truncate(code, 16)}}
			}
		}}
}

var eossMeWatchCode = probe.BodyRegex(`"code"\s*:\s*(\d+)`)

func eossMeWatch(rs []*probe.Response) []probe.Result {
	r := rs[0]
	if code := eossMeWatchCode(r); code != "" {
		return no("code " + code)
	}
	if r.Status == http.StatusOK && has(r.Body, "stream") {
		return yes("")
	}
	return unknown(r)
}
