package risk

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/arngory/cii/internal/probe"
)

func TestOfflineChecksOnlyDownloadedLists(t *testing.T) {
	base := t.TempDir()
	dir := dataDir(base)
	if got := Offline(base, netip.MustParseAddr("203.0.113.7")); got != nil {
		t.Fatalf("no data = %+v", got)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("manifest.json", `{"aws":{"id":"aws"},"gcp":{"id":"gcp"}}`)
	write("aws.txt", "198.51.100.0/24\tAWS EC2 eu-central-1\n")
	clean := Offline(base, netip.MustParseAddr("203.0.113.7"))
	if len(clean) != 1 || clean[0].Status != probe.Yes || clean[0].Detail != "not in: aws" {
		t.Errorf("clean = %+v", clean)
	}
	hit := Offline(base, netip.MustParseAddr("198.51.100.9"))
	if len(hit) != 1 || hit[0].Status != probe.Partial || hit[0].Detail != "AWS EC2 eu-central-1" {
		t.Errorf("hit = %+v", hit)
	}
	write("manifest.json", `{"gcp":{"id":"gcp"}}`)
	if got := Offline(base, netip.MustParseAddr("203.0.113.7")); got != nil {
		t.Errorf("listed but missing file = %+v", got)
	}
}
