package risk

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/paths"
	"github.com/arngory/cii/internal/probe"
)

const DataModule = "data"

const maxDataDownload = 32 << 20

type DataSource struct {
	ID       string
	Title    string
	Kind     string
	Terms    string
	Homepage string
	URLs     []string
	ByASN    bool
	parse    func(r io.Reader, add func(key, label string)) error
}

var DataSources = []DataSource{
	{ID: "tor-exits", Title: "Tor bulk exit list", Kind: "tor", Terms: "public data of The Tor Project",
		Homepage: "https://check.torproject.org/", URLs: []string{"https://check.torproject.org/torbulkexitlist"}, parse: parseLines("Tor exit")},
	{ID: "aws", Title: "AWS IP address ranges", Kind: "cloud", Terms: "published by AWS for allow-listing",
		Homepage: "https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html", URLs: []string{"https://ip-ranges.amazonaws.com/ip-ranges.json"}, parse: parseAWS},
	{ID: "gcp", Title: "Google Cloud IP ranges", Kind: "cloud", Terms: "published by Google for allow-listing",
		Homepage: "https://cloud.google.com/compute/docs/faq#find_ip_range", URLs: []string{"https://www.gstatic.com/ipranges/cloud.json"}, parse: parseGCP},
	{ID: "oracle", Title: "Oracle Cloud public IP ranges", Kind: "cloud", Terms: "published by Oracle for allow-listing",
		Homepage: "https://docs.oracle.com/en-us/iaas/Content/General/Concepts/addressranges.htm", URLs: []string{"https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"}, parse: parseOracle},
	{ID: "cloudflare", Title: "Cloudflare IP ranges", Kind: "cdn", Terms: "published by Cloudflare for allow-listing",
		Homepage: "https://www.cloudflare.com/ips/", URLs: []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"}, parse: parseLines("Cloudflare")},
	{ID: "digitalocean", Title: "DigitalOcean geofeed", Kind: "cloud", Terms: "RFC 8805 geofeed published by DigitalOcean",
		Homepage: "https://docs.digitalocean.com/platform/", URLs: []string{"https://www.digitalocean.com/geo/google.csv"}, parse: parseGeofeed("DigitalOcean")},
	{ID: "spamhaus-drop", Title: "Spamhaus DROP", Kind: "abuse", Terms: "free of charge under the Spamhaus DROP terms",
		Homepage: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/", URLs: []string{"https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json"}, parse: parseDROP},
	{ID: "peeringdb", Title: "PeeringDB network types", Kind: "asn-type", Terms: "PeeringDB acceptable use policy: for your own use, not to be passed on in bulk", ByASN: true,
		Homepage: "https://www.peeringdb.com/", URLs: []string{"https://www.peeringdb.com/api/net?fields=asn,info_types"}, parse: parsePeeringDB},
}

func DataSourceByID(id string) (DataSource, bool) {
	for _, s := range DataSources {
		if s.ID == id {
			return s, true
		}
	}
	return DataSource{}, false
}

func DataRules() []netx.Rule {
	var rules []netx.Rule
	for _, s := range DataSources {
		for _, u := range s.URLs {
			if pu, err := url.Parse(u); err == nil {
				rules = append(rules, netx.Rule{Module: DataModule, Pattern: pu.Hostname(), Purpose: DataModule + ": " + s.Title})
			}
		}
	}
	return rules
}

type DataEntry struct {
	ID        string    `json:"id"`
	File      string    `json:"file"`
	URLs      []string  `json:"urls"`
	FetchedAt time.Time `json:"fetched_at"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	Prefixes  int       `json:"prefixes"`
}

type Match struct {
	Source string `json:"source"`
	Kind   string `json:"kind"`
	Label  string `json:"label"`
	Prefix string `json:"prefix"`
}

func dataDir(base string) string { return filepath.Join(base, "risk") }

func DataManifest(base string) (map[string]DataEntry, error) {
	m := map[string]DataEntry{}
	b, err := os.ReadFile(filepath.Join(dataDir(base), "manifest.json"))
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("risk manifest: %w", err)
	}
	return m, nil
}

func saveManifest(dir string, m map[string]DataEntry) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return paths.WriteFileAtomic(filepath.Join(dir, "manifest.json"), b, 0o644)
}

func loadOrResetManifest(base string) map[string]DataEntry {
	if m, err := DataManifest(base); err == nil {
		return m
	}
	return map[string]DataEntry{}
}

func Update(ctx context.Context, n *netx.Net, base string, ids ...string) ([]DataEntry, error) {
	client := n.HTTPClient(DataModule)
	client.Timeout = 2 * time.Minute
	return update(ctx, client, base, ids)
}

func update(ctx context.Context, client *http.Client, base string, ids []string) ([]DataEntry, error) {
	sources := DataSources
	if len(ids) > 0 {
		sources = nil
		for _, id := range ids {
			s, ok := DataSourceByID(id)
			if !ok {
				return nil, fmt.Errorf("unknown risk data source %q", id)
			}
			sources = append(sources, s)
		}
	}
	dir := dataDir(base)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	m := loadOrResetManifest(base)
	var done []DataEntry
	var errs []error
	for _, s := range sources {
		e, err := fetchSource(ctx, client, dir, s)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.ID, err))
			continue
		}
		m[s.ID] = e
		if err := saveManifest(dir, m); err != nil {
			errs = append(errs, err)
			continue
		}
		done = append(done, e)
	}
	return done, errors.Join(errs...)
}

func fetchSource(ctx context.Context, client *http.Client, dir string, s DataSource) (DataEntry, error) {
	seen := map[string]bool{}
	var lines []string
	add := func(key, label string) {
		if s.ByASN {
			if !asnKey.MatchString(key) {
				return
			}
		} else {
			p, err := parsePrefix(key)
			if err != nil {
				return
			}
			key = p.String()
		}
		label = strings.Join(strings.Fields(label), " ")
		line := key + "\t" + label
		if !seen[line] {
			seen[line] = true
			lines = append(lines, line)
		}
	}
	var clean []string
	for _, u := range s.URLs {
		clean = append(clean, netx.StripSecrets(u))
		if err := download(ctx, client, u, func(r io.Reader) error { return s.parse(r, add) }); err != nil {
			return DataEntry{}, err
		}
	}
	if len(lines) == 0 {
		return DataEntry{}, errors.New("no prefixes parsed")
	}
	sort.Strings(lines)
	data := []byte(strings.Join(lines, "\n") + "\n")
	file := s.ID + ".txt"
	if err := paths.WriteFileAtomic(filepath.Join(dir, file), data, 0o644); err != nil {
		return DataEntry{}, err
	}
	sum := sha256.Sum256(data)
	return DataEntry{ID: s.ID, File: file, URLs: clean, FetchedAt: time.Now().UTC(),
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)), Prefixes: len(lines)}, nil
}

func download(ctx context.Context, client *http.Client, rawURL string, parse func(io.Reader) error) error {
	clean := netx.StripSecrets(rawURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return netx.Redact(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", clean, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDataDownload+1))
	if err != nil {
		return fmt.Errorf("%s: %w", clean, err)
	}
	if len(body) > maxDataDownload {
		return fmt.Errorf("%s: exceeds %d bytes", clean, maxDataDownload)
	}
	if err := parse(bytes.NewReader(body)); err != nil {
		return fmt.Errorf("%s: %w", clean, err)
	}
	return nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("mapped prefix %s", s)
	}
	return p.Masked(), nil
}

var asnKey = regexp.MustCompile(`^AS[0-9]+$`)

func parseDROP(r io.Reader, add func(string, string)) error {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		var e struct {
			CIDR  string `json:"cidr"`
			SBLID string `json:"sblid"`
		}
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.CIDR != "" {
			add(e.CIDR, strings.TrimSpace("Spamhaus DROP "+e.SBLID))
		}
	}
	return sc.Err()
}

func parsePeeringDB(r io.Reader, add func(string, string)) error {
	var d struct {
		Data []struct {
			ASN   uint32   `json:"asn"`
			Types []string `json:"info_types"`
		} `json:"data"`
	}
	if err := json.NewDecoder(r).Decode(&d); err != nil {
		return err
	}
	for _, n := range d.Data {
		if n.ASN != 0 && len(n.Types) > 0 {
			add(fmt.Sprintf("AS%d", n.ASN), strings.Join(n.Types, ", "))
		}
	}
	return nil
}

func parseLines(label string) func(io.Reader, func(string, string)) error {
	return func(r io.Reader, add func(string, string)) error {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			add(strings.Fields(line)[0], label)
		}
		return sc.Err()
	}
}

func parseAWS(r io.Reader, add func(string, string)) error {
	var d struct {
		Prefixes []struct {
			IP      string `json:"ip_prefix"`
			Region  string `json:"region"`
			Service string `json:"service"`
		} `json:"prefixes"`
		IPv6 []struct {
			IP      string `json:"ipv6_prefix"`
			Region  string `json:"region"`
			Service string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.NewDecoder(r).Decode(&d); err != nil {
		return err
	}
	for _, p := range d.Prefixes {
		add(p.IP, "AWS "+p.Service+" "+p.Region)
	}
	for _, p := range d.IPv6 {
		add(p.IP, "AWS "+p.Service+" "+p.Region)
	}
	return nil
}

func parseGCP(r io.Reader, add func(string, string)) error {
	var d struct {
		Prefixes []struct {
			V4    string `json:"ipv4Prefix"`
			V6    string `json:"ipv6Prefix"`
			Scope string `json:"scope"`
		} `json:"prefixes"`
	}
	if err := json.NewDecoder(r).Decode(&d); err != nil {
		return err
	}
	for _, p := range d.Prefixes {
		label := "Google Cloud " + p.Scope
		if p.V4 != "" {
			add(p.V4, label)
		}
		if p.V6 != "" {
			add(p.V6, label)
		}
	}
	return nil
}

func parseOracle(r io.Reader, add func(string, string)) error {
	var d struct {
		Regions []struct {
			Region string `json:"region"`
			CIDRs  []struct {
				CIDR string `json:"cidr"`
			} `json:"cidrs"`
		} `json:"regions"`
	}
	if err := json.NewDecoder(r).Decode(&d); err != nil {
		return err
	}
	for _, reg := range d.Regions {
		for _, c := range reg.CIDRs {
			add(c.CIDR, "Oracle Cloud "+reg.Region)
		}
	}
	return nil
}

func parseGeofeed(provider string) func(io.Reader, func(string, string)) error {
	return func(r io.Reader, add func(string, string)) error {
		cr := csv.NewReader(r)
		cr.FieldsPerRecord = -1
		cr.Comment = '#'
		for {
			rec, err := cr.Read()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
			label := provider
			if len(rec) > 1 && rec[1] != "" {
				label += " " + rec[1]
			}
			if len(rec) > 3 && rec[3] != "" {
				label += " " + rec[3]
			}
			add(rec[0], label)
		}
	}
}

func lookupFile(path string, s DataSource, ip netip.Addr) ([]Match, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	type hit struct {
		p     netip.Prefix
		label string
	}
	var hits []hit
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		prefix, label, _ := strings.Cut(sc.Text(), "\t")
		p, err := netip.ParsePrefix(prefix)
		if err != nil || !p.Contains(ip) {
			continue
		}
		if i := slices.IndexFunc(hits, func(h hit) bool { return h.label == label }); i >= 0 {
			if p.Bits() > hits[i].p.Bits() {
				hits[i].p = p
			}
			continue
		}
		hits = append(hits, hit{p, label})
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].p.Bits() > hits[j].p.Bits() })
	out := make([]Match, 0, len(hits))
	for _, h := range hits {
		out = append(out, Match{Source: s.ID, Kind: s.Kind, Label: h.label, Prefix: h.p.String()})
	}
	return out, sc.Err()
}

const Network probe.Group = "network"

func Offline(base string, ip netip.Addr, asn uint) []probe.Result {
	ip = ip.Unmap()
	m, err := DataManifest(base)
	if err != nil || len(m) == 0 || !ip.IsValid() {
		return nil
	}
	var out []probe.Result
	pdb := probe.Result{Group: Network, Service: "PeeringDB", Status: probe.Unknown}
	_, havePDB := m["peeringdb"]
	switch {
	case !havePDB:
		pdb.Reason = "not downloaded: cii data update risk:peeringdb"
	case asn == 0:
		pdb.Reason = "ASN unknown: needs the DB-IP ASN database (cii data update)"
	default:
		if r, found := networkType(filepath.Join(dataDir(base), "peeringdb.txt"), asn); found {
			pdb = r
		} else {
			pdb.Reason = "this AS is not registered in PeeringDB"
		}
	}
	out = append(out, pdb)
	var matches []Match
	var checked, missing []string
	for _, s := range DataSources {
		if s.ByASN {
			continue
		}
		if _, ok := m[s.ID]; !ok {
			missing = append(missing, s.ID)
			continue
		}
		found, err := lookupFile(filepath.Join(dataDir(base), s.ID+".txt"), s, ip)
		if err != nil {
			continue
		}
		checked = append(checked, s.ID)
		matches = append(matches, found...)
	}
	note := ""
	if len(missing) > 0 {
		note = "; not downloaded: " + strings.Join(missing, ", ")
	}
	switch {
	case len(checked) == 0:
		return out
	case len(matches) == 0:
		return append(out, probe.Result{Group: Network, Service: "Known ranges", Status: probe.Yes, Detail: "not in: " + strings.Join(checked, ", ") + note})
	}
	var labels []string
	bad := false
	for _, m := range matches {
		labels = append(labels, m.Label)
		bad = bad || m.Kind == "tor" || m.Kind == "abuse"
	}
	status := probe.Partial
	if bad {
		status = probe.No
	}
	return append(out, probe.Result{Group: Network, Service: "Known ranges", Status: status, Detail: probe.Truncate(strings.Join(labels, "; ")+note, 200)})
}

var peeringdbUsage = map[string]string{
	"Cable/DSL/ISP": "isp", "NSP": "isp", "Content": "hosting", "Network Services": "hosting",
	"Enterprise": "business", "Non-Profit": "business", "Educational/Research": "education", "Government": "government",
}

func networkType(path string, asn uint) (probe.Result, bool) {
	f, err := os.Open(path)
	if err != nil {
		return probe.Result{}, false
	}
	defer f.Close()
	want := fmt.Sprintf("AS%d\t", asn)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, want) {
			continue
		}
		types := strings.TrimPrefix(line, want)
		facts := &probe.Facts{}
		for _, t := range strings.Split(types, ", ") {
			if u := peeringdbUsage[t]; u != "" && facts.Usage == "" {
				facts.Usage = u
			}
		}
		return probe.Result{Group: Network, Service: "PeeringDB", Status: probe.Yes, Detail: fmt.Sprintf("AS%d %s", asn, types), Facts: facts.OrNil()}, true
	}
	return probe.Result{}, false
}
