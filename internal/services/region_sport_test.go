package services

import (
	"testing"

	"github.com/arngory/cii/internal/probe"
)

func TestSPORTChecks(t *testing.T) {
	eossRun(t, "SPORT", []eossCase{
		{"NBA TV", eossResp(200, `<html></html>`), probe.Yes, ""},
		{"Fubo TV", eossResp(200, `{"postal":"94104","country_code":"USA","country_code2":"US","network_allowed":true}`), probe.Yes, "US"},
		{"Fubo TV", eossResp(200, `{"country_code2":"NL","network_allowed":false}`), probe.IPBlock, "NL"},
		{"Fubo TV", eossResp(403, `{"error":{"code":"NO_SERVICE_IN_COUNTRY"},"country_code2":"RU"}`), probe.No, "RU"},
		{"Fubo TV", eossResp(200, `{}`), probe.Unknown, ""},
		{"Setanta Sports", eossResp(200, `{"outsideAllowedTerritories":true}`), probe.No, ""},
	})
}
