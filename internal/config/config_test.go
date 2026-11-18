package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestLoadServices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `services:
  - url: https://wiki.example.org/health
  - name: Shop
    url: https://shop.example.org/
    expect: 200
    contains: cart
    blocked: not available
    group: Work
  - url: https://api.example.org/
    expect: [401, 403]
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil || len(c.Services) != 3 {
		t.Fatalf("services = %+v, err = %v", c, err)
	}
	s := c.Services
	if s[0].URL != "https://wiki.example.org/health" || s[0].Expect != nil ||
		s[1].Name != "Shop" || !slices.Equal(s[1].Expect, Codes{200}) || s[1].Contains != "cart" || s[1].Blocked != "not available" || s[1].Group != "Work" ||
		!slices.Equal(s[2].Expect, Codes{401, 403}) {
		t.Errorf("services = %+v", s)
	}
	if err := os.WriteFile(path, []byte("services:\n  - url: https://example.org/\n    expect: ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("a non-numeric expect was accepted")
	}
}
