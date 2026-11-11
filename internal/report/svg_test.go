package report

import (
	"encoding/xml"
	"io"
	"regexp"
	"strings"
	"testing"
)

func TestWriteSVG(t *testing.T) {
	c := paint(true)
	lines := []string{"┌─ " + c.bold("Title") + " ─┐", "│ " + c.badge(badgeBad, "HOST") + " a<b & \"c\" " + c.green("✓") + " │"}
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
	if w := words("  ab  c "); len(w) != 2 || w[0] != (word{2, "ab"}) || w[1] != (word{6, "c"}) {
		t.Errorf("words = %+v", w)
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
