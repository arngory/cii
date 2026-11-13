package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/arngory/cii/internal/report"
)

func main() {
	for _, img := range report.DemoImages() {
		svg, err := report.DemoSVG(img.Lang, img.Width)
		if err == nil {
			err = os.WriteFile(filepath.Join("docs", "img", img.File), svg, 0o644)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "gendemo:", err)
			os.Exit(1)
		}
	}
}
