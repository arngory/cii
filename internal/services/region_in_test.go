package services

import (
	"testing"

	"github.com/arngory/cii/internal/probe"
)

func TestIndia(t *testing.T) {
	naRun(t, "IN", []naCase{
		{"Hotstar", naResp(302, ``, "Location", "https://www.hotstar.com/in", "Set-Cookie", "geo=IN,MH,MUMBAI"), probe.Yes, "IN"},
		{"Hotstar", naResp(403, ``), probe.No, ""},

		{"MX Player", naResp(200, `<html><title>MX Player</title>`, "Set-Cookie", "platform=com.mxplay.desktop; Path=/"), probe.Yes, ""},
		{"MX Player", naResp(200, `<title>MX Player</title><h2 class="sub-message">We are currently not available in your region.</h2>`), probe.No, ""},
		{"MX Player", naResp(200, `<title>MX Player</title>`), probe.Unknown, ""},
		{"MX Player", naResp(502, ``), probe.Failed, ""},

		{"NBA TV", naResp(200, `Service is not available in your region`), probe.No, ""},

		{"Zee5", naResp(200, `<html>`, "Set-Cookie", "country=IN; Path=/"), probe.Yes, "IN"},
		{"Zee5", naResp(200, `<script>var a="?country=GB&state=";</script>`), probe.Yes, "GB"},
		{"Zee5", naResp(200, `<html></html>`), probe.Unknown, ""},
		{"Zee5", naResp(403, `<TITLE>Access Denied</TITLE>`), probe.Failed, ""},
	})
	if naCheck(t, "IN", "Zee5").Tier != probe.TierA {
		t.Error("Zee5 must be tier A")
	}
}
