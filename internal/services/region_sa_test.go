package services

import (
	"testing"

	"github.com/arngory/cii/internal/probe"
)

func TestLatinAmerica(t *testing.T) {
	naRun(t, "SA", []naCase{
		{"Paramount+", naResp(200, `{"pageProps":{"region":"br"}}`), probe.Yes, "BR"},
		{"Paramount+", naResp(200, `{"pageProps":{"region":"intl"}}`), probe.No, ""},
		{"HBO Max", naResp(200, `[{"url":"/mx/es"},{"url":"/br/pt"}]`, "Set-Cookie", "countryCode=MX; Path=/"), probe.Yes, "MX"},
		{"HBO Max", naResp(200, `[{"url":"/mx/es"}]`, "Set-Cookie", "countryCode=VE; Path=/"), probe.No, "VE"},
	})
	if naCheck(t, "SA", "HBO Max").Tier != probe.TierA {
		t.Error("HBO Max must be tier A")
	}
}
