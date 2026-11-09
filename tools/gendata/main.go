package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	cldrURL    = "https://raw.githubusercontent.com/unicode-org/cldr-json/main/cldr-json/cldr-localenames-full/main/en/territories.json"
	airportURL = "https://davidmegginson.github.io/ourairports-data/airports.csv"
)

var client = &http.Client{Timeout: 2 * time.Minute}

func main() {
	out := flag.String("out", "internal/refdata", "output directory")
	flag.Parse()
	if err := countries(filepath.Join(*out, "countries.tsv")); err != nil {
		log.Fatal(err)
	}
	if err := airports(filepath.Join(*out, "iata.tsv")); err != nil {
		log.Fatal(err)
	}
}

func fetch(url string) (io.ReadCloser, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return resp.Body, nil
}

var territoryKey = regexp.MustCompile(`^([A-Z]{2})(-alt-[a-z]+)?$`)

func countries(path string) error {
	body, err := fetch(cldrURL)
	if err != nil {
		return err
	}
	defer body.Close()
	var doc struct {
		Main map[string]struct {
			LocaleDisplayNames struct {
				Territories map[string]string `json:"territories"`
			} `json:"localeDisplayNames"`
		} `json:"main"`
	}
	if err := json.NewDecoder(body).Decode(&doc); err != nil {
		return err
	}
	names := map[string]string{}
	alts := map[string][]string{}
	for k, v := range doc.Main["en"].LocaleDisplayNames.Territories {
		m := territoryKey.FindStringSubmatch(k)
		if m == nil || m[1] == "ZZ" || m[1] == "EU" || m[1] == "EZ" || m[1] == "UN" || m[1] == "QO" {
			continue
		}
		if m[2] == "" {
			names[m[1]] = v
		} else {
			alts[m[1]] = append(alts[m[1]], v)
		}
	}
	if len(names) < 200 {
		return fmt.Errorf("CLDR: only %d territories", len(names))
	}
	var b strings.Builder
	for _, cc := range sortedKeys(names) {
		sort.Strings(alts[cc])
		fmt.Fprintf(&b, "%s\t%s\t%s\n", cc, names[cc], strings.Join(alts[cc], "|"))
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func airports(path string) error {
	body, err := fetch(airportURL)
	if err != nil {
		return err
	}
	defer body.Close()
	r := csv.NewReader(body)
	header, err := r.Read()
	if err != nil {
		return err
	}
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	for _, need := range []string{"type", "iso_country", "iata_code"} {
		if _, ok := col[need]; !ok {
			return fmt.Errorf("airports.csv: no %q column", need)
		}
	}
	rank := map[string]int{"large_airport": 4, "medium_airport": 3, "small_airport": 2}
	type entry struct {
		cc   string
		rank int
	}
	best := map[string]entry{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		code := strings.ToUpper(strings.TrimSpace(rec[col["iata_code"]]))
		cc := rec[col["iso_country"]]
		typ := rec[col["type"]]
		if len(code) != 3 || len(cc) != 2 || typ == "closed" {
			continue
		}
		if e, ok := best[code]; !ok || rank[typ] > e.rank {
			best[code] = entry{cc, rank[typ]}
		}
	}
	if len(best) < 5000 {
		return fmt.Errorf("airports.csv: only %d IATA codes", len(best))
	}
	var b strings.Builder
	for _, code := range sortedKeys(best) {
		fmt.Fprintf(&b, "%s\t%s\n", code, best[code].cc)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
