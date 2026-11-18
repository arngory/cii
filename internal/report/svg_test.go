package report

import (
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestWriteSVG(t *testing.T) {
	c := paint(true)
	lines := []string{"┌─ " + c.bold("Title") + " ─┐", "│ " + c.badge(badgeBad, "HOST") + " a<b & \"c\" " + c.green("✓") + " │", "│ " + c.green("■") + c.dim("□□") + " x │", "└────────┘"}
	var b strings.Builder
	if err := WriteSVG(&b, lines); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	d := xml.NewDecoder(strings.NewReader(out))
	for {
		if _, err := d.Token(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("invalid XML: %v\n%s", err, out)
		}
	}
	for _, want := range []string{`font-weight="bold">Title<`, `fill="#da3633"`, `a&lt;b`, `&amp;`, `&#34;c&#34;`, `fill="#3fb950">✓<`} {
		if !strings.Contains(out, want) && !(want == `&#34;c&#34;` && strings.Contains(out, `&quot;c&quot;`)) {
			t.Errorf("%q missing\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") || strings.Contains(out, "textLength") {
		t.Errorf("escape codes or stretched text in SVG\n%s", out)
	}
	if regexp.MustCompile(`(?:width|height)="[0-9.]*%`).MatchString(out) {
		t.Errorf("a percentage size: SVG Tiny renderers such as Qt read 100%% as 100 units\n%s", out)
	}
	if fonts := regexp.MustCompile(`font-family="([^"]*)"`).FindAllStringSubmatch(out, -1); len(fonts) != 1 || fonts[0][1] != "monospace" {
		t.Errorf("font families = %q: Qt takes the attribute as one name, so it must be a single family", fonts)
	}
	if strings.Contains(out, "<style") || strings.Contains(out, "font-family:") {
		t.Errorf("CSS fonts override the single family in Qt\n%s", out)
	}
	for _, m := range regexp.MustCompile(`<text[^>]*>([^<]*)</text>`).FindAllStringSubmatch(out, -1) {
		if strings.ContainsAny(m[1], "─│┌┐└┘■□") {
			t.Errorf("frame or bar glyph %q drawn as text", m[1])
		}
	}
	if !strings.Contains(out, `<rect x="0" y="0" width="`) || !regexp.MustCompile(`<path fill="none"[^>]* d="M[^"]*H[^"]*V`).MatchString(out) {
		t.Errorf("background or frame path missing\n%s", out)
	}
	if w := words("  ab  c "); len(w) != 2 || w[0] != (word{2, "ab"}) || w[1] != (word{6, "c"}) {
		t.Errorf("words = %+v", w)
	}
}

func TestWriteHTML(t *testing.T) {
	c := paint(true)
	lines := []string{"┌─ " + c.bold("Title") + " ─┐", "│ " + c.badge(badgeBad, "HOST") + " a<b & \"c\" " + c.green("✓") + " " + c.dim("note") + " │"}
	var b strings.Builder
	if err := WriteHTML(&b, `cii <demo> & "more"`, "ru", lines); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"<!doctype html>", `<html lang="ru">`, `<meta charset="utf-8">`, "<title>cii &lt;demo&gt; &amp; &#34;more&#34;</title>",
		`<span class="b">Title</span>`, `background:#da3633`, "a&lt;b &amp; &#34;c&#34;", `<span style="color:#3fb950">✓</span>`, `<span class="d">note</span>`, "┌─ ", "</pre>\n</body>\n</html>\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") || strings.Contains(out, "<script") || strings.Contains(out, "http") {
		t.Errorf("escape codes, scripts or outside resources in the page\n%s", out)
	}
	if strings.Count(out, "<span") != strings.Count(out, "</span>") {
		t.Errorf("unbalanced spans\n%s", out)
	}
}

func TestDemoUsesDocumentationData(t *testing.T) {
	r := Demo("online")
	var js strings.Builder
	if err := r.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	screen := strings.Join(r.Screen(Style{Unicode: true, Width: 150}, "cii demo", nil), "\n")
	if !strings.Contains(screen, "203.0.113.7") || !strings.Contains(screen, "Benchmark") || !strings.Contains(screen, "Censorship") {
		t.Errorf("demo screen incomplete:\n%s", screen)
	}
	allowed := regexp.MustCompile(`^(203\.0\.113\.|198\.51\.100\.|192\.0\.2\.|1\.1\.1\.1$|8\.8\.8\.8$)`)
	for _, ip := range regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`).FindAllString(js.String()+screen, -1) {
		if !allowed.MatchString(ip) {
			t.Errorf("demo carries a non-documentation address %s", ip)
		}
	}
}

func TestDemoImagesAreCurrent(t *testing.T) {
	for _, img := range DemoImages() {
		want, err := DemoSVG(img.Lang, img.Width)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join("..", "..", "docs", "img", img.File))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("docs/img/%s is out of date: run `make demo` (%v)", img.File, err)
		}
	}
}

func TestSVGPathMergesTouchingSegments(t *testing.T) {
	got := svgPath([]segment{
		{20, 10, 30, 10}, {10, 10, 20, 10}, {40, 10, 50, 10},
		{5, 0, 5, 18}, {5, 18, 5, 36}, {5, 50, 5, 60}, {9, 0, 9, 5},
	})
	want := "M10.0 10.0H30.0M40.0 10.0H50.0M5.0 0.0V36.0M5.0 50.0V60.0M9.0 0.0V5.0"
	if got != want {
		t.Errorf("path = %s\nwant   %s", got, want)
	}
	var b strings.Builder
	WriteSVG(&b, []string{"┌──┐", "│  │", "│  │", "└──┘"})
	paths := regexp.MustCompile(`d="([^"]*)"`).FindAllStringSubmatch(b.String(), -1)
	if len(paths) != 1 || strings.Count(paths[0][1], "M") != 4 {
		t.Errorf("a box should be one path of four strokes: %q", paths)
	}
}
