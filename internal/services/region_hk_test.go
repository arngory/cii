package services

import (
	"testing"

	"github.com/arngory/cii/internal/probe"
)

func TestHKCatalog(t *testing.T) {
	jkhtTiers(t, "HK", "Now E", "Viu.TV")
	jkhtRun(t, "HK", []jkhtCase{
		{"Now E", r(200, `{"OTTAPI_ResponseCode":"GEO_CHECK_FAIL"}`), probe.No, ""},
		{"Now E", r(200, `{"OTTAPI_ResponseCode" : "SUCCESS"}`), probe.Yes, ""},
		{"Now E", r(200, `{"OTTAPI_ResponseCode":"NEED_LOGIN"}`), probe.Unknown, ""},
		{"Viu", jkhtLoc(302, "https://www.viu.com/ott/no-service/"), probe.No, ""},
		{"Viu", jkhtLoc(302, "https://www.viu.com/ott/hk/zh/"), probe.Yes, "HK"},
		{"Viu", jkhtLoc(302, "/ott/sg/en/"), probe.Yes, "SG"},
		{"Viu", r(200, `<html></html>`), probe.Unknown, ""},
		{"Viu", r(503, ``), probe.Failed, ""},
		{"Viu.TV", r(200, `{"responseCode":"GEO_CHECK_FAIL"}`), probe.No, ""},
		{"Viu.TV", r(200, `{"responseCode":"SUCCESS","asset":[]}`), probe.Yes, ""},
		{"myTV SUPER", r(200, `{"region":2,"country_code":"US","supported_country":false,"is_europe":false}`), probe.No, "US"},
		{"myTV SUPER", r(200, `{"region":1,"country_code":"HK","supported_country":true}`), probe.Yes, "HK"},
		{"myTV SUPER", r(200, `{}`), probe.Unknown, ""},
		{"myTV SUPER", r(429, ``), probe.Failed, ""},
		{"Bilibili HK/MO/TW", r(200, `{"code":-10403,"message":"抱歉您所在地区不可观看！"}`), probe.No, ""},
		{"Bilibili HK/MO/TW", r(200, `{"code":0,"message":"success","result":{"code":0}}`), probe.Yes, ""},
		{"Bilibili HK/MO/TW", r(200, `{"code":-404,"message":"啥都木有"}`), probe.Unknown, ""},
		{"Bilibili HK/MO/TW", r(412, `<html>`), probe.Failed, ""},
	})
}
