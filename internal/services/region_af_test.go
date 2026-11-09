package services

import (
	"testing"

	"github.com/arngory/cii/internal/probe"
)

func TestAfrica(t *testing.T) {
	naRun(t, "AF", []naCase{
		{"DStv", naResp(404, ``), probe.Yes, ""},
		{"DStv", naResp(403, `<H1>403 ERROR</H1>`), probe.No, ""},
		{"DStv", naResp(451, ``), probe.No, ""},
		{"DStv", naResp(200, `icon`), probe.Unknown, ""},
		{"DStv", naResp(500, ``), probe.Failed, ""},

		{"Viu", naResp(302, `Found. Redirecting to /ott/za/`, "Location", "/ott/za/"), probe.Yes, "ZA"},
		{"Viu", naResp(302, ``, "Location", "https://www.viu.com/ott/ke/en/"), probe.Yes, "KE"},
		{"Viu", naResp(302, `Found. Redirecting to /ott/no-service/`, "Location", "https://www.viu.com/ott/no-service/"), probe.No, ""},
		{"Viu", naResp(302, ``, "Location", "https://www.viu.com/maintenance"), probe.Unknown, ""},
		{"Viu", naResp(200, `<html>`), probe.Unknown, ""},
	})
}
