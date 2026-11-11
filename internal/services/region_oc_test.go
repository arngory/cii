package services

import (
	"testing"

	"github.com/arngory/cii/internal/probe"
)

func TestOCChecks(t *testing.T) {
	eossRun(t, "OC", []eossCase{
		{"NBA TV", eossResp(200, `<html><title>Watch NBA</title></html>`), probe.Yes, ""},
		{"NBA TV", eossResp(200, `Service is not available in your region`), probe.No, ""},
		{"NBA TV", eossResp(403, `<TITLE>Access Denied</TITLE>`), probe.IPBlock, ""},
		{"NBA TV", eossResp(500, ``), probe.Failed, ""},

		{"Acorn TV", eossResp(200, `https://signup.acorn.tv/`), probe.Yes, ""},
		{"BritBox", eossResp(302, ``, "Location", "https://www.britbox.com/locationnotvalidated"), probe.No, ""},
		{"Paramount+", eossResp(200, `{"pageProps":{"region":"AU"}}`), probe.Yes, "AU"},

		{"AMC+", eossResp(200, `<title>AMC+ | Premium Streaming Service</title>`), probe.Yes, ""},
		{"AMC+", eossResp(302, ``, "Location", "https://www.amcplus.com/pages/geographic-restriction"), probe.No, ""},
		{"AMC+", eossResp(403, ``), probe.No, ""},
		{"AMC+", eossResp(302, ``, "Location", "https://www.amcplus.com/au"), probe.Unknown, ""},

		{"DocPlay", eossResp(200, `<div style="background-image: url(https://x/background-geoblocked-01.jpg)">Sorry! DocPlay hasn't launched in your part of the world yet.`), probe.No, ""},
		{"DocPlay", eossResp(302, ``, "Location", "https://www.docplay.com/geoblocked"), probe.No, ""},
		{"DocPlay", eossResp(200, `<title>DocPlay - Subscribe</title>`), probe.Yes, ""},
		{"DocPlay", eossResp(200, `<html></html>`), probe.Unknown, ""},

		{"ABC iview", eossResp(200, `{"title":"ABC Kids Live Stream","playable":false,"unavailableMessage":"This program is unavailable outside Australia."}`), probe.No, ""},
		{"ABC iview", eossResp(200, `{"title":"ABC Kids Live Stream","playable":true}`), probe.Yes, ""},
		{"ABC iview", eossResp(200, `{"playable":false}`), probe.Unknown, ""},

		{"9Now", eossResp(403, `<title>login.nine.com.au | Geoblocked</title>`), probe.No, ""},
		{"9Now", eossResp(200, `<h1>Log in to 9Now</h1>`), probe.Yes, ""},
		{"9Now", eossResp(200, `<html></html>`), probe.Unknown, ""},

		{"10 Play", eossResp(200, "\n    { \"state\": \"WA\",\n     \"allow\": false }\n"), probe.No, ""},
		{"10 Play", eossResp(200, `{"state":"NSW","allow":true}`), probe.Yes, ""},
		{"10 Play", eossResp(503, ``), probe.Failed, ""},

		{"SBS On Demand", eossResp(200, `{"get":{"response":{"georegion":"285","country_code":"US","region_code":"TX"},"status":true}}`), probe.No, "US"},
		{"SBS On Demand", eossResp(200, `{"get":{"response":{"country_code":"AU"},"status":true}}`), probe.Yes, "AU"},
		{"SBS On Demand", eossResp(200, `{"get":{}}`), probe.Unknown, ""},

		{"Sky Go NZ", eossResp(200, `<html>login</html>`), probe.Yes, ""},
		{"Sky Go NZ", eossResp(403, ``), probe.No, ""},
		{"Sky Go NZ", eossResp(400, ``), probe.Failed, ""},
	})
}
