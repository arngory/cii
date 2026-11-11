package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	svgFontSize   = 14
	svgCharWidth  = 8.4
	svgLineHeight = 18
	svgPad        = 16
)

var svgColors = map[int]string{
	30: "#0d1117", 31: "#f85149", 32: "#3fb950", 33: "#d29922", 97: "#ffffff",
	41: "#da3633", 42: "#2ea043", 43: "#bb8009",
}

type svgStyle struct {
	bold, dim bool
	fg, bg    string
}

type svgRun struct {
	col  int
	text string
	st   svgStyle
}

func (st *svgStyle) apply(seq string) {
	params := strings.TrimSuffix(strings.TrimPrefix(seq, "\x1b["), "m")
	if params == "" {
		*st = svgStyle{}
		return
	}
	for _, p := range strings.Split(params, ";") {
		n, err := strconv.Atoi(p)
		switch {
		case err != nil:
		case n == 0:
			*st = svgStyle{}
		case n == 1:
			st.bold = true
		case n == 2:
			st.dim = true
		case n >= 30 && n <= 37 || n >= 90 && n <= 97:
			st.fg = svgColors[n]
		case n >= 40 && n <= 47:
			st.bg = svgColors[n]
		}
	}
}

func svgRuns(line string) []svgRun {
	var runs []svgRun
	var st svgStyle
	col := 0
	var cur strings.Builder
	start := 0
	flush := func() {
		if cur.Len() > 0 {
			runs = append(runs, svgRun{start, cur.String(), st})
			cur.Reset()
		}
		start = col
	}
	for i := 0; i < len(line); {
		if loc := ansiSeq.FindStringIndex(line[i:]); loc != nil && loc[0] == 0 {
			seq := line[i : i+loc[1]]
			i += loc[1]
			if strings.HasSuffix(seq, "m") {
				flush()
				st.apply(seq)
			}
			continue
		}
		r, size := utf8.DecodeRuneInString(line[i:])
		cur.WriteRune(r)
		col++
		i += size
	}
	flush()
	return runs
}

type word struct {
	col  int
	text string
}

func words(s string) []word {
	var out []word
	col, start := 0, -1
	var cur []rune
	for _, r := range s {
		if r == ' ' {
			if start >= 0 {
				out = append(out, word{start, string(cur)})
				start, cur = -1, cur[:0]
			}
		} else {
			if start < 0 {
				start = col
			}
			cur = append(cur, r)
		}
		col++
	}
	if start >= 0 {
		out = append(out, word{start, string(cur)})
	}
	return out
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func WriteSVG(w io.Writer, lines []string) error {
	cols := 0
	for _, l := range lines {
		cols = max(cols, visibleLen(l))
	}
	width := float64(svgPad*2) + float64(cols)*svgCharWidth
	height := svgPad*2 + len(lines)*svgLineHeight
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%.0f" height="%d" viewBox="0 0 %.0f %d">`+"\n", width, height, width, height)
	fmt.Fprintf(&b, `<rect width="100%%" height="100%%" rx="8" fill="#0d1117"/>`+"\n")
	fmt.Fprintf(&b, `<g font-family="'JetBrains Mono','DejaVu Sans Mono',Menlo,Consolas,monospace" font-size="%d" fill="#e6edf3" xml:space="preserve" style="white-space:pre;font-variant-ligatures:none">`+"\n", svgFontSize)
	for i, l := range lines {
		y := svgPad + i*svgLineHeight
		for _, r := range svgRuns(l) {
			x := float64(svgPad) + float64(r.col)*svgCharWidth
			n := utf8.RuneCountInString(r.text)
			if r.st.bg != "" {
				fmt.Fprintf(&b, `<rect x="%.1f" y="%d" width="%.1f" height="%d" fill="%s"/>`, x, y, float64(n)*svgCharWidth, svgLineHeight, r.st.bg)
			}
			attrs := ""
			if r.st.fg != "" {
				attrs += ` fill="` + r.st.fg + `"`
			}
			if r.st.bold {
				attrs += ` font-weight="bold"`
			}
			if r.st.dim {
				attrs += ` fill-opacity="0.6"`
			}
			for _, w := range words(r.text) {
				fmt.Fprintf(&b, `<text x="%.1f" y="%d"%s>%s</text>`, x+float64(w.col)*svgCharWidth, y+svgLineHeight-5, attrs, xmlEscape(w.text))
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("</g>\n</svg>\n")
	_, err := io.WriteString(w, b.String())
	return err
}
