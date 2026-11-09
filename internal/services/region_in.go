package services

import (
	"net/http"

	"github.com/arngory/cii/internal/probe"
)

func init() {
	register("IN",
		sharedHotstar,
		probe.Check{Service: "MX Player", Requests: probe.Get("https://www.mxplayer.in/"), Eval: inMXPlayer},
		sharedNBATV,
		probe.Check{Service: "Zee5", Requests: probe.Get("https://www.zee5.com/"), Eval: inZee5},
	)
}

func inMXPlayer(rs []*probe.Response) []probe.Result {
	r := rs[0]
	switch {
	case has(r.Body, "403 ERROR", "not available in your"):
		return no("")
	case r.Status == http.StatusOK && len(r.Header.Values("Set-Cookie")) > 0:
		return yes("")
	}
	return unknown(r)
}

var (
	inZee5Cookie = probe.HeaderRegex("Set-Cookie", `country=([A-Z]{2})\b`)
	inZee5Body   = probe.BodyRegex(`country=([A-Z]{2})\b`)
)

func inZee5(rs []*probe.Response) []probe.Result {
	r := rs[0]
	if r.Status != http.StatusOK {
		return unknown(r)
	}
	cc := toCC(inZee5Cookie(r))
	if cc == "" {
		cc = toCC(inZee5Body(r))
	}
	if cc == "" {
		return unknown(r)
	}
	return yes(cc)
}
