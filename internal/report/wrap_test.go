package report

import (
	"strings"
	"testing"
)

func TestWrapVisible(t *testing.T) {
	c := paint(true)
	line := c.dim("DNSBL ") + " " + c.yellow("?") + " zen.spamhaus.org " + c.dim("127.255.255.254 refused: query via public/open resolver, use your own resolver to get an answer")
	got := wrapVisible(line, 40)
	if len(got) < 3 {
		t.Fatalf("not wrapped: %q", got)
	}
	var plain []string
	for _, l := range got {
		if visibleLen(l) > 40 {
			t.Errorf("line too long (%d): %q", visibleLen(l), l)
		}
		if esc := ansiSeq.FindAllString(l, -1); len(esc) > 0 && esc[len(esc)-1] != "\x1b[0m" {
			t.Errorf("style left open: %q", l)
		}
		plain = append(plain, ansiSeq.ReplaceAllString(l, ""))
	}
	joined := strings.Join(strings.Fields(strings.Join(plain, " ")), " ")
	if strings.Contains(joined, "…") || !strings.HasSuffix(joined, "use your own resolver to get an answer") {
		t.Errorf("text lost:\n%s", joined)
	}
	for _, l := range plain[1:] {
		if !strings.HasPrefix(l, "       ") || strings.HasPrefix(l, "        ") {
			t.Errorf("continuation not aligned under the text after the label: %q", l)
		}
	}
	if !strings.HasPrefix(got[1], "       \x1b[2m") {
		t.Errorf("continuation does not reopen the dim style: %q", got[1])
	}
	if w := wrapVisible("short", 40); len(w) != 1 || w[0] != "short" {
		t.Errorf("short line = %q", w)
	}
	long := strings.Repeat("x", 95)
	for _, l := range wrapVisible(long, 40) {
		if visibleLen(l) > 40 {
			t.Errorf("unbroken word overflows: %q", l)
		}
	}
}
