package netx

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestStripSecrets(t *testing.T) {
	got := StripSecrets("https://user:pw@ipinfo.io/data/ipinfo_lite.mmdb?token=SECRET&apiKey=K2&x=1")
	for _, leak := range []string{"SECRET", "K2", "pw"} {
		if strings.Contains(got, leak) {
			t.Fatalf("secret %s leaked: %s", leak, got)
		}
	}
	if !strings.Contains(got, "x=1") {
		t.Fatalf("non-secret parameter dropped: %s", got)
	}
}

func TestRedact(t *testing.T) {
	raw := "https://ipinfo.io/?token=SECRET"
	err := Redact(&url.Error{Op: "Get", URL: raw, Err: errors.New("boom")}, raw)
	if strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Redact = %v", err)
	}
	if Redact(nil, raw) != nil {
		t.Fatal("Redact(nil) != nil")
	}
}
