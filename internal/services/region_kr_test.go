package services

import (
	"testing"

	"github.com/arngory/cii/internal/probe"
)

func TestKRCatalog(t *testing.T) {
	jkhtTiers(t, "KR", "Wavve", "TVING", "SPOTV NOW")
	kbs := func(v string) string {
		return `var ipck = JSON.parse('{\"ret\": \"ok\", \"Domestic\": ` + v + `, \"American\": true, \"myIP\": \"192.0.2.1\"}');`
	}
	jkhtRun(t, "KR", []jkhtCase{
		{"Wavve", r(200, ``), probe.Yes, ""},
		{"Wavve", r(550, ``), probe.No, ""},
		{"Wavve", r(403, ``), probe.No, ""},
		{"Wavve", r(500, ``), probe.Failed, ""},
		{"TVING", r(200, `{"body":{"stream":{"broadcast":{"vod_type":"x"}}}}`), probe.Yes, ""},
		{"TVING", r(200, `{"header":{"message":"This content is only available in South Korea."}}`), probe.No, ""},
		{"TVING", r(200, `{}`), probe.Unknown, ""},
		{"WATCHA", r(451, ``), probe.No, ""},
		{"Coupang Play", r(403, `<TITLE>Access Denied</TITLE>`), probe.No, ""},
		{"Coupang Play", jkhtLoc(302, "https://www.coupangplay.com/not-available"), probe.No, ""},
		{"Coupang Play", r(200, `<html></html>`), probe.Yes, ""},
		{"Coupang Play", r(502, ``), probe.Failed, ""},
		{"SPOTV NOW", r(403, `[{"error_code":"ACCESS_DENIED","error_subcode":"CLIENT_GEO"}]`), probe.No, ""},
		{"SPOTV NOW", r(200, `{"id":"6349973203112","sources":[]}`), probe.Yes, ""},
		{"SPOTV NOW", r(401, `[{"error_code":"INVALID_POLICY_KEY","error_subcode":"KEY_INVALID"}]`), probe.Failed, ""},
		{"KBS Domestic", r(200, kbs("false")), probe.No, ""},
		{"KBS Domestic", r(200, kbs("true")), probe.Yes, ""},
		{"KBS Domestic", r(200, `<html></html>`), probe.Unknown, ""},
	})
}
