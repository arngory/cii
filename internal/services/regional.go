package services

import (
	"slices"
	"strings"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/probe"
)

type Catalog struct {
	Code      string
	Title     string
	Countries []string
	checks    []probe.Check
}

var Catalogs = []*Catalog{
	{Code: "HK", Title: "Hong Kong", Countries: []string{"HK", "MO"}},
	{Code: "TW", Title: "Taiwan", Countries: []string{"TW"}},
	{Code: "JP", Title: "Japan", Countries: []string{"JP"}},
	{Code: "KR", Title: "Korea", Countries: []string{"KR"}},
	{Code: "NA", Title: "North America", Countries: []string{"US", "CA"}},
	{Code: "SA", Title: "Latin America", Countries: strings.Fields("MX AR BO BR CL CO EC GY PY PE SR UY VE CR PA GT HN SV NI DO PR")},
	{Code: "EU", Title: "Europe", Countries: strings.Fields("AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE GB NO IS LI CH AL BA ME MK RS XK UA MD BY RU AD MC SM VA GI")},
	{Code: "OC", Title: "Oceania", Countries: []string{"AU", "NZ"}},
	{Code: "SEA", Title: "Southeast Asia", Countries: strings.Fields("SG TH MY PH ID VN KH LA MM BN")},
	{Code: "AF", Title: "Africa", Countries: strings.Fields("DZ AO BJ BW BF BI CV CM CF TD KM CG CD CI DJ EG GQ ER SZ ET GA GM GH GN GW KE LS LR LY MG MW ML MR MU MA MZ NA NE NG RW ST SN SC SL SO ZA SS SD TZ TG TN UG ZM ZW")},
}

func catalog(code string) *Catalog {
	for _, c := range Catalogs {
		if c.Code == code {
			return c
		}
	}
	return nil
}

func register(code string, checks ...probe.Check) {
	c := catalog(code)
	if c == nil {
		panic("services: unknown catalog " + code)
	}
	for _, ch := range checks {
		ch.Group = probe.Group(code)
		c.checks = append(c.checks, ch)
	}
}

func CatalogsFor(country string) []string {
	var out []string
	for _, c := range Catalogs {
		if slices.Contains(c.Countries, strings.ToUpper(country)) {
			out = append(out, c.Code)
		}
	}
	return out
}

func SelectRegional(codes []string, k config.Keys, extended bool) []probe.Check {
	var out []probe.Check
	for _, code := range codes {
		if c := catalog(strings.ToUpper(code)); c != nil {
			out = append(out, probe.Select(Module, c.checks, k, extended)...)
		}
	}
	return out
}

func Title(g probe.Group) string {
	if c := catalog(string(g)); c != nil {
		return c.Title
	}
	return ""
}
