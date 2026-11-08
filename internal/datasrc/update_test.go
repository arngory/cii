package datasrc

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/arngory/cii/internal/config"
)

func TestStripSecrets(t *testing.T) {
	got := stripSecrets("https://user:pw@ipinfo.io/data/ipinfo_lite.mmdb?token=SECRET&x=1")
	if strings.Contains(got, "SECRET") || strings.Contains(got, "pw") {
		t.Fatalf("secret leaked: %s", got)
	}
	err := redact(&url.Error{Op: "Get", URL: "https://ipinfo.io/?token=SECRET", Err: errors.New("boom")}, "https://ipinfo.io/?token=SECRET")
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("secret leaked in error: %v", err)
	}
}

func TestURLs(t *testing.T) {
	now := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	s, _ := ByID("dbip-country-lite")
	urls, _, _, err := s.urls(now, config.Keys{})
	if err != nil || len(urls) != 2 || !strings.Contains(urls[0], "2026-01") || !strings.Contains(urls[1], "2025-12") {
		t.Fatalf("dbip urls = %v, %v", urls, err)
	}
	for _, id := range []string{"ipinfo-lite", "geolite2-city"} {
		s, _ := ByID(id)
		if _, _, _, err := s.urls(now, config.Keys{}); err == nil {
			t.Errorf("%s: missing key not reported", id)
		}
	}
	for _, s := range Registry {
		if len(s.Hosts) == 0 || s.urls == nil {
			t.Errorf("%s: incomplete registry entry", s.ID)
		}
	}
}
