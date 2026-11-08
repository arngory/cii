package geodb

import "testing"

func TestNormaliseGeoIP2(t *testing.T) {
	r := normalise(map[string]any{
		"country":            map[string]any{"iso_code": "DE", "names": map[string]any{"en": "Germany"}},
		"registered_country": map[string]any{"iso_code": "NL"},
		"continent":          map[string]any{"code": "EU"},
		"city":               map[string]any{"names": map[string]any{"en": "Berlin"}},
		"subdivisions":       []any{map[string]any{"names": map[string]any{"en": "Land Berlin"}}},
		"location":           map[string]any{"latitude": 52.5, "longitude": 13.4},
	})
	if r.Country != "DE" || r.CountryName != "Germany" || r.RegisteredCountry != "NL" || r.City != "Berlin" ||
		r.Region != "Land Berlin" || r.Continent != "EU" || r.Latitude == nil || *r.Latitude != 52.5 {
		t.Fatalf("normalise = %+v", r)
	}
	a := normalise(map[string]any{"autonomous_system_number": uint64(13335), "autonomous_system_organization": "Cloudflare"})
	if a.ASN != 13335 || a.ASOrg != "Cloudflare" {
		t.Fatalf("asn = %+v", a)
	}
}

func TestNormaliseIPinfoLite(t *testing.T) {
	r := normalise(map[string]any{
		"country_code": "US", "country": "United States", "continent_code": "NA",
		"asn": "AS15169", "as_name": "Google LLC", "as_domain": "google.com",
	})
	if r.Country != "US" || r.CountryName != "United States" || r.ASN != 15169 || r.ASOrg != "Google LLC" || r.ASDomain != "google.com" {
		t.Fatalf("normalise = %+v", r)
	}
}
