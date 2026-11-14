package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/arngory/cii/internal/report"
)

const (
	socialWidth  = 1280
	socialHeight = 640
	socialCols   = 118
	socialHead   = `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">
<rect width="100%%" height="100%%" fill="#010409"/>
<g font-family="'JetBrains Mono','DejaVu Sans Mono',Menlo,Consolas,monospace" fill="#e6edf3">
<text x="64" y="150" font-size="112" font-weight="bold">cii</text>
<text x="64" y="212" font-size="28" fill-opacity="0.8">complete information</text>
<text x="64" y="250" font-size="28" fill-opacity="0.8">about current IP</text>
<text x="64" y="352" font-size="22" fill="#3fb950">region · IP quality · services</text>
<text x="64" y="388" font-size="22" fill="#3fb950">censorship · routes · benchmark</text>
<text x="64" y="556" font-size="20" fill-opacity="0.6">one static binary, AGPL-3.0</text>
<text x="64" y="588" font-size="20" fill-opacity="0.6">github.com/arngory/cii</text>
</g>
<svg x="520" y="92" width="744" height="456" `
)

var demoOpen = regexp.MustCompile(`^<svg [^>]*viewBox="([^"]+)">`)

func social() ([]byte, error) {
	demo, err := report.DemoSVG("en", socialCols)
	if err != nil {
		return nil, err
	}
	m := demoOpen.FindSubmatchIndex(demo)
	if m == nil {
		return nil, fmt.Errorf("unexpected start of the demo picture")
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, socialHead, socialWidth, socialHeight, socialWidth, socialHeight)
	fmt.Fprintf(&b, "viewBox=\"%s\">", demo[m[2]:m[3]])
	b.Write(demo[m[1]:])
	b.WriteString("</svg>\n")
	return b.Bytes(), nil
}

func main() {
	write := func(name string, data []byte, err error) {
		if err == nil {
			err = os.WriteFile(filepath.Join("docs", "img", name), data, 0o644)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "gendemo:", err)
			os.Exit(1)
		}
	}
	for _, img := range report.DemoImages() {
		svg, err := report.DemoSVG(img.Lang, img.Width)
		write(img.File, svg, err)
	}
	if len(os.Args) > 1 && os.Args[1] == "social" {
		svg, err := social()
		write("social-preview.svg", svg, err)
	}
}
