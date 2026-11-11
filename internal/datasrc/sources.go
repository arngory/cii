package datasrc

import (
	"fmt"
	"net/url"
	"time"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/netx"
)

const Module = "data"

type Archive int

const (
	Raw Archive = iota
	Gzip
	TarGz
)

type Source struct {
	ID          string
	Title       string
	Kind        string
	License     string
	Attribution string
	Homepage    string
	Default     bool
	NeedsKey    string
	Archive     Archive
	Hosts       []string

	urls func(now time.Time, k config.Keys) (candidates []string, user, pass string, err error)
}

func dbipURLs(name string) func(time.Time, config.Keys) ([]string, string, string, error) {
	return func(now time.Time, _ config.Keys) ([]string, string, string, error) {
		cur := now.UTC()
		prev := time.Date(cur.Year(), cur.Month()-1, 1, 0, 0, 0, 0, time.UTC)
		f := "https://download.db-ip.com/free/dbip-%s-lite-%s.mmdb.gz"
		return []string{
			fmt.Sprintf(f, name, cur.Format("2006-01")),
			fmt.Sprintf(f, name, prev.Format("2006-01")),
		}, "", "", nil
	}
}

func maxmindURLs(edition string) func(time.Time, config.Keys) ([]string, string, string, error) {
	return func(_ time.Time, k config.Keys) ([]string, string, string, error) {
		if k.MaxMindAccountID == "" || k.MaxMindLicenseKey == "" {
			return nil, "", "", fmt.Errorf("requires your own %s in config", "maxmind_account_id + maxmind_license_key")
		}
		u := "https://download.maxmind.com/geoip/databases/" + edition + "/download?suffix=tar.gz"
		return []string{u}, k.MaxMindAccountID, k.MaxMindLicenseKey, nil
	}
}

var maxmindHosts = []string{"download.maxmind.com", "*.r2.cloudflarestorage.com"}

var Registry = []Source{
	{
		ID: "dbip-country-lite", Title: "DB-IP IP to Country Lite", Kind: "country",
		License: "CC BY 4.0", Attribution: "IP Geolocation by DB-IP (https://db-ip.com)",
		Homepage: "https://db-ip.com/db/download/ip-to-country-lite", Default: true,
		Archive: Gzip, Hosts: []string{"download.db-ip.com"}, urls: dbipURLs("country"),
	},
	{
		ID: "dbip-asn-lite", Title: "DB-IP IP to ASN Lite", Kind: "asn",
		License: "CC BY 4.0", Attribution: "IP Geolocation by DB-IP (https://db-ip.com)",
		Homepage: "https://db-ip.com/db/download/ip-to-asn-lite", Default: true,
		Archive: Gzip, Hosts: []string{"download.db-ip.com"}, urls: dbipURLs("asn"),
	},
	{
		ID: "dbip-city-lite", Title: "DB-IP IP to City Lite (~130 MB)", Kind: "city",
		License: "CC BY 4.0", Attribution: "IP Geolocation by DB-IP (https://db-ip.com)",
		Homepage: "https://db-ip.com/db/download/ip-to-city-lite",
		Archive:  Gzip, Hosts: []string{"download.db-ip.com"}, urls: dbipURLs("city"),
	},
	{
		ID: "ipinfo-lite", Title: "IPinfo Lite (country + ASN)", Kind: "country+asn",
		License: "CC BY-SA 4.0", Attribution: "IP address data powered by IPinfo (https://ipinfo.io)",
		Homepage: "https://ipinfo.io/lite", NeedsKey: "ipinfo_token",
		Archive: Raw, Hosts: []string{"ipinfo.io"},
		urls: func(_ time.Time, k config.Keys) ([]string, string, string, error) {
			if k.IPinfoToken == "" {
				return nil, "", "", fmt.Errorf("requires your own %s in config", "ipinfo_token")
			}
			return []string{"https://ipinfo.io/data/ipinfo_lite.mmdb?token=" + url.QueryEscape(k.IPinfoToken)}, "", "", nil
		},
	},
	{
		ID: "geolite2-country", Title: "MaxMind GeoLite2 Country", Kind: "country",
		License: "GeoLite2 EULA (no redistribution)", Attribution: "This product includes GeoLite2 data created by MaxMind (https://www.maxmind.com)",
		Homepage: "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data", NeedsKey: "maxmind_license_key",
		Archive: TarGz, Hosts: maxmindHosts, urls: maxmindURLs("GeoLite2-Country"),
	},
	{
		ID: "geolite2-city", Title: "MaxMind GeoLite2 City", Kind: "city",
		License: "GeoLite2 EULA (no redistribution)", Attribution: "This product includes GeoLite2 data created by MaxMind (https://www.maxmind.com)",
		Homepage: "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data", NeedsKey: "maxmind_license_key",
		Archive: TarGz, Hosts: maxmindHosts, urls: maxmindURLs("GeoLite2-City"),
	},
	{
		ID: "geolite2-asn", Title: "MaxMind GeoLite2 ASN", Kind: "asn",
		License: "GeoLite2 EULA (no redistribution)", Attribution: "This product includes GeoLite2 data created by MaxMind (https://www.maxmind.com)",
		Homepage: "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data", NeedsKey: "maxmind_license_key",
		Archive: TarGz, Hosts: maxmindHosts, urls: maxmindURLs("GeoLite2-ASN"),
	},
}

func ByID(id string) (Source, bool) {
	for _, s := range Registry {
		if s.ID == id {
			return s, true
		}
	}
	return Source{}, false
}

func Rules(srcs []Source) []netx.Rule {
	var rules []netx.Rule
	for _, s := range srcs {
		for _, h := range s.Hosts {
			rules = append(rules, netx.Rule{Module: Module, Pattern: h, Purpose: "download " + s.ID})
		}
	}
	return rules
}
