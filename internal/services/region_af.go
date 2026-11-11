package services

import (
	"net/http"
	"strconv"

	"github.com/arngory/cii/internal/probe"
)

func init() {
	register("AF",
		probe.Check{Service: "DStv", Requests: probe.Get("https://authentication.dstv.com/favicon.ico"), Eval: afDStv},
		sharedViu,
	)
}

func afDStv(rs []*probe.Response) []probe.Result {
	r := rs[0]
	switch r.Status {
	case http.StatusNotFound:
		return yes("")
	case http.StatusForbidden, http.StatusUnavailableForLegalReasons:
		return no("HTTP " + strconv.Itoa(r.Status))
	}
	return unknown(r)
}
