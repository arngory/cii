package services

import (
	"regexp"
	"strings"
	"testing"

	"github.com/arngory/cii/internal/probe"
)

func TestTWCatalog(t *testing.T) {
	jkhtTiers(t, "TW", "LiTV", "4GTV", "LINE TV", "CatchPlay+")
	jkhtRun(t, "TW", []jkhtCase{
		{"KKTV", r(200, `{"status":{"type":"OK"},"data":{"country":"US","ip":"192.0.2.1","is_allowed":false}}`), probe.No, "US"},
		{"KKTV", r(200, `{"status":{"type":"OK"},"data":{"country":"TW","ip":"192.0.2.1","is_allowed":true}}`), probe.Yes, "TW"},
		{"KKTV", r(200, `{"data":{"country":"TW"}}`), probe.Yes, "TW"},
		{"KKTV", r(502, `bad gateway`), probe.Failed, ""},
		{"LiTV", r(200, `{"result":{"AssetURLs":["https://example.invalid/a.m3u8"]}}`), probe.Yes, ""},
		{"LiTV", r(200, `{"error":{"code":42000087,"message":"geo"}}`), probe.No, ""},
		{"LiTV", r(200, `{"error":{"code":42000075}}`), probe.Yes, ""},
		{"LiTV", r(200, `<html>`), probe.Unknown, ""},
		{"MyVideo", jkhtLoc(302, "https://www.myvideo.net.tw/serviceAreaBlock.do"), probe.No, ""},
		{"MyVideo", r(200, `<html></html>`), probe.Yes, ""},
		{"MyVideo", r(403, ``), probe.No, ""},
		{"4GTV", r(200, `{"Success":true,"Data":"N"}`), probe.No, ""},
		{"4GTV", r(200, `{"Success":true,"Data":"Y"}`), probe.Yes, ""},
		{"4GTV", r(403, `<div>抱歉，這個頁面無法取得</div>`), probe.Failed, ""},
		{"LINE TV", r(200, `{"countryCode":228}`), probe.Yes, ""},
		{"LINE TV", r(200, `{"countryCode":1}`), probe.No, ""},
		{"LINE TV", r(200, `{}`), probe.Unknown, ""},
		{"Hami Video", r(200, `{"contentID":"OTT_VOD_0000249064","code":"06001-106","msg":"抱歉"}`), probe.No, ""},
		{"Hami Video", r(200, `{"code":"06001-107"}`), probe.Yes, ""},
		{"Hami Video", r(200, `{"code":"06001-999"}`), probe.Unknown, ""},
		{"CatchPlay+", r(200, `{"code":"0","data":{"isoCode":"TW"}}`), probe.Yes, ""},
		{"CatchPlay+", r(200, `{"code":"100016","message":"not allowed"}`), probe.No, ""},
		{"CatchPlay+", r(401, `{"code":"401"}`), probe.Failed, ""},
		{"Bilibili TW", r(200, `{"code":-10403}`), probe.No, ""},
	})
}

func TestTWUUID(t *testing.T) {
	id := uuid4()
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(id) || id == uuid4() {
		t.Errorf("uuid4() = %q", id)
	}
	for _, c := range catalog("TW").checks {
		if c.Service == "LiTV" && strings.Contains(c.Requests[0].Body, "%s") {
			t.Error("LiTV body not formatted")
		}
	}
}
