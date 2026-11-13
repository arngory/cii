package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/arngory/cii/internal/report"
)

func main() {
	for name, spec := range report.DemoImages() {
		svg, err := report.DemoSVG(spec[0].(string), spec[1].(int))
		if err == nil {
			err = os.WriteFile(filepath.Join("docs", "img", name), svg, 0o644)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "gendemo:", err)
			os.Exit(1)
		}
	}
}
