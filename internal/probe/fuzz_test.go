package probe_test

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/risk"
	"github.com/arngory/cii/internal/services"
)

func allChecks() []probe.Check {
	k := config.Keys{IPinfoToken: "k", MaxMindAccountID: "k", MaxMindLicenseKey: "k", IPRegistryKey: "k", GeoapifyKey: "k",
		IP2LocationKey: "k", IPAPIisKey: "k", ProxyCheckKey: "k", AbuseIPDBKey: "k", IPQSKey: "k", IPDataKey: "k"}
	var codes []string
	for _, c := range services.Catalogs {
		codes = append(codes, c.Code)
	}
	cs := region.Select(k, true)
	cs = append(cs, services.Select(k, true)...)
	cs = append(cs, services.SelectRegional(codes, k, true)...)
	return append(cs, risk.Checks(k, true)...)
}

func FuzzEvals(f *testing.F) {
	for _, seed := range []string{"", "{}", "[]", "null", `{"data":null}`, `{"data":{"asns":[]}}`, "<html><title>x</title></html>", "\x00\xff", `)]}'` + "\n[[null]]"} {
		for _, status := range []int{200, 302, 403, 503} {
			f.Add(status, []byte(seed), "https://example.invalid/blocked")
		}
	}
	checks := allChecks()
	ip := netip.MustParseAddr("203.0.113.7")
	f.Fuzz(func(t *testing.T, status int, body []byte, location string) {
		h := http.Header{}
		h.Set("Location", location)
		h.Set("X-Served-By", location)
		for _, c := range checks {
			rs := make([]*probe.Response, len(c.Requests))
			for i := range rs {
				rs[i] = &probe.Response{Status: status, Header: h, Body: body}
			}
			for i, r := range c.Requests {
				if r.BodyFrom != nil {
					r.BodyFrom(ip, rs[:i])
				}
			}
			c.Eval(rs)
		}
	})
}
