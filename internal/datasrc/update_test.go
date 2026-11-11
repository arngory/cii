package datasrc

import (
	"strings"
	"testing"
	"time"

	"github.com/arngory/cii/internal/config"
)

func TestURLs(t *testing.T) {
	now := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	s, _ := ByID("dbip-country-lite")
	urls, _, _, err := s.urls(now, config.Keys{})
	if err != nil || len(urls) != 2 || !strings.Contains(urls[0], "2026-01") || !strings.Contains(urls[1], "2025-12") {
		t.Fatalf("dbip urls = %v, %v", urls, err)
	}
	urls, _, _, _ = s.urls(time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC), config.Keys{})
	if !strings.Contains(urls[1], "2026-02") {
		t.Fatalf("previous month after month-end = %v", urls)
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
