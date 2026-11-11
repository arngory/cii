package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/arngory/cii/internal/datasrc"
)

var licenseFile = regexp.MustCompile(`(?i)^(licen[cs]e|copying|notice|patents)(\.(md|txt))?$`)

func main() {
	var err error
	switch {
	case len(os.Args) == 3 && os.Args[1] == "licenses":
		err = licenses(os.Args[2])
	case len(os.Args) == 4 && os.Args[1] == "data":
		err = dataNotice(os.Args[2], os.Args[3])
	default:
		err = fmt.Errorf("usage: notices licenses <out> | notices data <data-dir> <out>")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "notices:", err)
		os.Exit(1)
	}
}

type module struct{ path, version, dir string }

func goOut(env []string, args ...string) (string, error) {
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

func modules() ([]module, error) {
	seen := map[string]module{}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		out, err := goOut([]string{"GOOS=" + goos, "CGO_ENABLED=0"}, "list", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}{{end}}", "./cmd/cii")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			f := strings.Split(line, "\t")
			if len(f) != 3 || f[0] == "" || f[2] == "" {
				return nil, fmt.Errorf("%s: cannot locate module source in %q", goos, line)
			}
			seen[f[0]] = module{f[0], f[1], f[2]}
		}
	}
	var mods []module
	for _, m := range seen {
		mods = append(mods, m)
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].path < mods[j].path })
	return mods, nil
}

func licenseTexts(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && licenseFile.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("%s: no license file", dir)
	}
	var out []string
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out = append(out, "--- "+n+" ---\n\n"+strings.TrimSpace(string(b)))
	}
	return out, nil
}

func section(b *bytes.Buffer, title string, texts ...string) {
	fmt.Fprintf(b, "%s\n%s\n\n", strings.Repeat("=", 72), title)
	for _, t := range texts {
		fmt.Fprintf(b, "%s\n\n", t)
	}
}

func licenses(out string) error {
	var b bytes.Buffer
	b.WriteString("Third-party software and data included in the cii binary.\n\ncii itself is licensed under the GNU Affero General Public License v3.0 only; see LICENSE.\n\n")
	goroot, err := goOut(nil, "env", "GOROOT")
	if err != nil {
		return err
	}
	gover, err := goOut(nil, "env", "GOVERSION")
	if err != nil {
		return err
	}
	texts, err := licenseTexts(goroot)
	if err != nil {
		return err
	}
	section(&b, "The Go standard library and runtime "+gover, texts...)
	mods, err := modules()
	if err != nil {
		return err
	}
	for _, m := range mods {
		texts, err := licenseTexts(m.dir)
		if err != nil {
			return err
		}
		section(&b, m.path+" "+m.version, texts...)
	}
	unicode, err := os.ReadFile("internal/refdata/LICENSE-unicode.txt")
	if err != nil {
		return err
	}
	section(&b, "Unicode CLDR territory names (internal/refdata/countries.tsv)", strings.TrimSpace(string(unicode)))
	section(&b, "OurAirports airport codes (internal/refdata/iata.tsv)", "Source: https://ourairports.com/data/\nReleased by OurAirports into the Public Domain.")
	return os.WriteFile(out, b.Bytes(), 0o644)
}

func dataNotice(dir, out string) error {
	m, err := datasrc.LoadManifest(dir)
	if err != nil {
		return err
	}
	if len(m.Entries) == 0 {
		return fmt.Errorf("%s: manifest has no entries", dir)
	}
	ids := make([]string, 0, len(m.Entries))
	for id := range m.Entries {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var b bytes.Buffer
	b.WriteString("Third-party IP databases attached to this release.\n\nEach .mmdb.gz file is an unmodified copy of the database as published, compressed with gzip. The databases are not part of cii and are not covered by its license. Their licensors provide them as-is; see the disclaimer of warranties in each license.\n\n")
	for _, id := range ids {
		e := m.Entries[id]
		src, ok := datasrc.ByID(id)
		if !ok {
			return fmt.Errorf("%s: unknown source", id)
		}
		if src.LicenseURL == "" || src.Attribution == "" {
			return fmt.Errorf("%s: missing license or attribution", id)
		}
		fmt.Fprintf(&b, "%s.gz\n", e.File)
		fmt.Fprintf(&b, "  %s\n", src.Title)
		fmt.Fprintf(&b, "  %s\n", src.Attribution)
		fmt.Fprintf(&b, "  Source:  %s\n", src.Homepage)
		fmt.Fprintf(&b, "  License: %s, %s\n", src.License, src.LicenseURL)
		fmt.Fprintf(&b, "  Built:   %s\n", time.Unix(int64(e.BuildEpoch), 0).UTC().Format("2006-01-02"))
		fmt.Fprintf(&b, "  SHA256 of the uncompressed file: %s\n\n", e.SHA256)
	}
	return os.WriteFile(out, b.Bytes(), 0o644)
}
