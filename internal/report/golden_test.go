package report

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arngory/cii/internal/probe"
)

var update = flag.Bool("update", false, "rewrite golden screen files")

func goldenReport() *Report {
	r := screenReport()
	r.Tool = Tool{Name: "cii", Version: "golden"}
	r.Censor = []probe.Result{{Group: "dns", Service: "Cloudflare DoH", Status: probe.Yes}, {Group: "telegram", Service: "DC2", Status: probe.No, Detail: "reset"}}
	r.Bench = sampleBench()
	return r
}

func TestGoldenScreens(t *testing.T) {
	for name, st := range map[string]Style{
		"screen-80":        {Unicode: true, Width: 80},
		"screen-150":       {Unicode: true, Width: 150},
		"screen-220":       {Unicode: true, Width: 220},
		"screen-150-ascii": {Width: 150},
		"screen-150-ru":    {Unicode: true, Width: 150, Lang: "ru"},
	} {
		got := strings.Join(goldenReport().Screen(st, "cii golden", []string{"footer"}), "\n") + "\n"
		path := filepath.Join("testdata", name+".golden")
		if *update {
			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run go test ./internal/report -run Golden -update)", name, err)
		}
		if got != string(want) {
			t.Errorf("%s changed; review and run go test ./internal/report -run Golden -update\n--- got\n%s", name, got)
		}
	}
}
