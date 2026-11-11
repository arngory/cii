package refdata

import "testing"

func TestLookups(t *testing.T) {
	if CountryName("de") != "Germany" || CountryName("ZZ") != "" {
		t.Errorf("CountryName: de=%q ZZ=%q", CountryName("de"), CountryName("ZZ"))
	}
	for name, want := range map[string]string{"United States": "US", "united  states.": "US", "Congo (DRC)": "CD", "Atlantis": ""} {
		if got := CountryByName(name); got != want {
			t.Errorf("CountryByName(%q) = %q, want %q", name, got, want)
		}
	}
	if IATACountry("yyz") != "CA" || IATACountry("FRA") != "DE" || IATACountry("ZZZ") != "" {
		t.Error("IATACountry mismatch")
	}
	if !IsCountry("RU") || IsCountry("XX") {
		t.Error("IsCountry mismatch")
	}
}
