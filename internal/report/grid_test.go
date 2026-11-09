package report

import (
	"strings"
	"testing"
)

func TestGridIgnoresColourCodes(t *testing.T) {
	var b strings.Builder
	red := func(s string) string { return "\x1b[31m" + s + "\x1b[0m" }
	writeGrid(&b, [][]gcell{
		{plain("name"), plain("v4"), plain("end")},
		{plain("ü"), {text: "no", style: red}, plain("x")},
	})
	strip := strings.NewReplacer("\x1b[31m", "", "\x1b[0m", "")
	lines := strings.Split(strings.TrimSuffix(strip.Replace(b.String()), "\n"), "\n")
	if lines[0] != "name  v4  end" || lines[1] != "ü     no  x" {
		t.Fatalf("grid = %q", lines)
	}
}
