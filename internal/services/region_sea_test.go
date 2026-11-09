package services

import (
	"testing"

	"github.com/arngory/cii/internal/probe"
)

func TestSEAChecks(t *testing.T) {
	eossRun(t, "SEA", []eossCase{
		{"Viu", eossResp(302, `Found`, "Location", "https://www.viu.com/ott/no-service/"), probe.No, ""},
		{"Viu", eossResp(302, ``, "Location", "https://www.viu.com/ott/sg/"), probe.Yes, "SG"},
		{"Viu", eossResp(302, ``, "Location", "/ott/my/en"), probe.Yes, "MY"},
		{"Viu", eossResp(200, `<html></html>`), probe.Unknown, ""},

		{"Hotstar", eossResp(302, ``, "Location", "/id", "Set-Cookie", "geo=ID,JK,JAKARTA"), probe.Yes, "ID"},
		{"HBO Max", eossResp(200, `{"url":"/sg/en"},{"url":"/th/th"}`, "Set-Cookie", "countryCode=TH; path=/"), probe.Yes, "TH"},

		{"B-Global (Southeast Asia)", eossResp(200, `{"code":10004001,"message":"10004001","ttl":1,"data":null}`), probe.No, ""},
		{"B-Global (Thailand)", eossResp(200, `{"code":0,"message":"0","data":{"playurl":{}}}`), probe.Yes, ""},
		{"B-Global (Indonesia)", eossResp(200, `{"code":10003003,"message":"x"}`), probe.No, ""},
		{"B-Global (Vietnam)", eossResp(200, `{"code":-412,"message":"request was banned"}`), probe.Unknown, ""},
		{"B-Global (Vietnam)", eossResp(502, `bad gateway`), probe.Failed, ""},

		{"meWATCH", eossResp(403, `{"code":8002,"message":"You are accessing this item from a location that is not permitted by the license"}`), probe.No, ""},
		{"meWATCH", eossResp(200, `[{"url":"https://x/master.m3u8","deliveryType":"Stream"}]`), probe.Yes, ""},
		{"meWATCH", eossResp(200, `[]`), probe.Unknown, ""},
	})
}
