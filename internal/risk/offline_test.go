package risk

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arngory/cii/internal/probe"
)

func TestOfflineChecksOnlyDownloadedLists(t *testing.T) {
	base := t.TempDir()
	dir := dataDir(base)
	if got := Offline(base, netip.MustParseAddr("203.0.113.7"), 0); got != nil {
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
	missing := "; not downloaded: tor-exits, oracle, cloudflare, digitalocean, spamhaus-drop"
	clean := Offline(base, netip.MustParseAddr("203.0.113.7"), 0)
	if len(clean) != 2 || clean[0].Service != "PeeringDB" || clean[0].Status != probe.Unknown || !strings.Contains(clean[0].Reason, "risk:peeringdb") {
		t.Fatalf("clean = %+v", clean)
	}
	if clean[1].Status != probe.Yes || clean[1].Detail != "not in: aws"+missing {
		t.Errorf("clean ranges = %+v", clean[1])
	}
	hit := Offline(base, netip.MustParseAddr("198.51.100.9"), 0)
	if len(hit) != 2 || hit[1].Status != probe.Partial || hit[1].Detail != "AWS EC2 eu-central-1"+missing {
		t.Errorf("hit = %+v", hit)
	}
	write("manifest.json", `{"gcp":{"id":"gcp"}}`)
	if got := Offline(base, netip.MustParseAddr("203.0.113.7"), 0); len(got) != 1 || got[0].Service != "PeeringDB" {
		t.Errorf("listed but missing file = %+v", got)
	}
}

func TestOfflineDROPAndPeeringDB(t *testing.T) {
	base := t.TempDir()
	dir := dataDir(base)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("manifest.json", `{"spamhaus-drop":{"id":"spamhaus-drop"},"peeringdb":{"id":"peeringdb"}}`)
	write("spamhaus-drop.txt", "198.51.100.0/24\tSpamhaus DROP SBL1\n")
	write("peeringdb.txt", "AS64500\tCable/DSL/ISP\nAS64501\tContent\n")
	rs := Offline(base, netip.MustParseAddr("198.51.100.9"), 64501)
	if len(rs) != 2 || rs[0].Service != "PeeringDB" || rs[0].Facts.Usage != "hosting" || rs[0].Detail != "AS64501 Content" {
		t.Fatalf("results = %+v", rs)
	}
	if rs[1].Status != probe.No || !strings.HasPrefix(rs[1].Detail, "Spamhaus DROP SBL1; not downloaded: tor-exits") {
		t.Errorf("DROP hit = %+v", rs[1])
	}
	clean := Offline(base, netip.MustParseAddr("203.0.113.7"), 64999)
	if len(clean) != 2 || clean[0].Status != probe.Unknown || clean[0].Reason != "this AS is not registered in PeeringDB" || !strings.HasPrefix(clean[1].Detail, "not in: spamhaus-drop; not downloaded:") {
		t.Errorf("clean = %+v", clean)
	}
	if noASN := Offline(base, netip.MustParseAddr("203.0.113.7"), 0); !strings.Contains(noASN[0].Reason, "ASN unknown") {
		t.Errorf("no ASN = %+v", noASN[0])
	}
}

func TestParseDROPAndPeeringDB(t *testing.T) {
	var got []string
	add := func(k, l string) { got = append(got, k+"="+l) }
	parseDROP(strings.NewReader(`{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}`+"\n"+`{"type":"metadata","records":1}`), add)
	parsePeeringDB(strings.NewReader(`{"data":[{"asn":4436,"info_types":["NSP"]},{"asn":7,"info_types":[]}]}`), add)
	if strings.Join(got, ";") != "1.10.16.0/20=Spamhaus DROP SBL256894;AS4436=NSP" {
		t.Errorf("parsed = %v", got)
	}
}
