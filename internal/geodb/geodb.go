package geodb

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/arngory/cii/internal/datasrc"
)

type Record struct {
	Source            string       `json:"source"`
	Network           netip.Prefix `json:"network"`
	Country           string       `json:"country,omitempty"`
	CountryName       string       `json:"country_name,omitempty"`
	RegisteredCountry string       `json:"registered_country,omitempty"`
	Continent         string       `json:"continent,omitempty"`
	Region            string       `json:"region,omitempty"`
	City              string       `json:"city,omitempty"`
	Latitude          *float64     `json:"latitude,omitempty"`
	Longitude         *float64     `json:"longitude,omitempty"`
	ASN               uint         `json:"asn,omitempty"`
	ASOrg             string       `json:"as_org,omitempty"`
	ASDomain          string       `json:"as_domain,omitempty"`
}

type DB struct {
	ID     string
	Path   string
	Type   string
	Built  int64
	reader *maxminddb.Reader
}

type Set struct {
	DBs []*DB
}

func Open(dir string) (*Set, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return &Set{}, nil
	}
	if err != nil {
		return nil, err
	}
	s := &Set{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".mmdb") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		r, err := maxminddb.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", path, err)
			continue
		}
		id := strings.TrimSuffix(filepath.Base(path), ".mmdb")
		s.DBs = append(s.DBs, &DB{ID: id, Path: path, Type: r.Metadata.DatabaseType, Built: int64(r.Metadata.BuildEpoch), reader: r})
	}
	return s, nil
}

func (s *Set) Close() {
	for _, d := range s.DBs {
		d.reader.Close()
	}
}

func (s *Set) Lookup(ip netip.Addr) []Record {
	var out []Record
	for _, d := range s.DBs {
		res := d.reader.Lookup(ip.Unmap())
		if res.Err() != nil || !res.Found() {
			continue
		}
		var raw map[string]any
		if err := res.Decode(&raw); err != nil {
			continue
		}
		rec := normalise(raw)
		rec.Source = d.ID
		rec.Network = res.Prefix()
		out = append(out, rec)
	}
	return out
}

func (s *Set) Attribution() []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range s.DBs {
		if src, ok := datasrc.ByID(d.ID); ok && !seen[src.Attribution] {
			seen[src.Attribution] = true
			out = append(out, src.Attribution)
		}
	}
	return out
}

func normalise(m map[string]any) Record {
	var r Record
	r.Country = str(m, "country", "iso_code")
	r.CountryName = str(m, "country", "names", "en")
	r.RegisteredCountry = str(m, "registered_country", "iso_code")
	r.Continent = str(m, "continent", "code")
	r.City = str(m, "city", "names", "en")
	if subs, ok := m["subdivisions"].([]any); ok && len(subs) > 0 {
		if sub, ok := subs[0].(map[string]any); ok {
			r.Region = str(sub, "names", "en")
		}
	}
	if loc, ok := m["location"].(map[string]any); ok {
		r.Latitude, r.Longitude = num(loc["latitude"]), num(loc["longitude"])
	}
	if v, ok := m["autonomous_system_number"]; ok {
		if f := num(v); f != nil {
			r.ASN = uint(*f)
		}
	}
	r.ASOrg = str(m, "autonomous_system_organization")

	if r.Country == "" {
		r.Country = str(m, "country_code")
	}
	if r.CountryName == "" {
		if s, ok := m["country"].(string); ok {
			r.CountryName = s
		}
	}
	if r.Continent == "" {
		r.Continent = str(m, "continent_code")
	}
	if s, ok := m["asn"].(string); ok && r.ASN == 0 {
		if n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(s), "AS"), 10, 32); err == nil {
			r.ASN = uint(n)
		}
	}
	if r.ASOrg == "" {
		r.ASOrg = str(m, "as_name")
	}
	r.ASDomain = str(m, "as_domain")
	return r
}

func str(m map[string]any, path ...string) string {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[p]
	}
	s, _ := cur.(string)
	return s
}

func num(v any) *float64 {
	var f float64
	switch x := v.(type) {
	case float64:
		f = x
	case float32:
		f = float64(x)
	case uint64:
		f = float64(x)
	case int32:
		f = float64(x)
	default:
		return nil
	}
	return &f
}
