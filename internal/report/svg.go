package report

import (
	"cmp"
	"fmt"
	"io"
	"slices"
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

const svgForeground = "#e6edf3"

func (st svgStyle) stroke() string {
	key := `stroke="` + cmp.Or(st.fg, svgForeground) + `"`
	if st.dim {
		key += ` stroke-opacity="0.6"`
	}
	return key
}

func (st svgStyle) paint() string {
	key := `fill="` + cmp.Or(st.fg, svgForeground) + `"`
	if st.dim {
		key += ` fill-opacity="0.6"`
	}
	return key
}

type segment struct{ x1, y1, x2, y2 float64 }

func svgPath(segs []segment) string {
	var flat, upright []segment
	for _, s := range segs {
		if s.y1 == s.y2 {
			flat = append(flat, s)
		} else {
			upright = append(upright, s)
		}
	}
	slices.SortFunc(flat, func(a, b segment) int { return cmp.Or(cmp.Compare(a.y1, b.y1), cmp.Compare(a.x1, b.x1)) })
	slices.SortFunc(upright, func(a, b segment) int { return cmp.Or(cmp.Compare(a.x1, b.x1), cmp.Compare(a.y1, b.y1)) })
	var d strings.Builder
	const touch = 0.01
	for i := 0; i < len(flat); {
		s := flat[i]
		for i++; i < len(flat) && flat[i].y1 == s.y1 && flat[i].x1 <= s.x2+touch; i++ {
			s.x2 = max(s.x2, flat[i].x2)
		}
		fmt.Fprintf(&d, "M%.1f %.1fH%.1f", s.x1, s.y1, s.x2)
	}
	for i := 0; i < len(upright); {
		s := upright[i]
		for i++; i < len(upright) && upright[i].x1 == s.x1 && upright[i].y1 <= s.y2+touch; i++ {
			s.y2 = max(s.y2, upright[i].y2)
		}
		fmt.Fprintf(&d, "M%.1f %.1fV%.1f", s.x1, s.y1, s.y2)
	}
	return d.String()
}

func boxGeometry(r rune) (left, right, up, down bool, ok bool) {
	switch r {
	case '─':
		return true, true, false, false, true
	case '│':
		return false, false, true, true, true
	case '┌':
		return false, true, false, true, true
	case '┐':
		return true, false, false, true, true
	case '└':
		return false, true, true, false, true
	case '┘':
		return true, false, true, false, true
	}
	return false, false, false, false, false
}

func WriteSVG(w io.Writer, lines []string) error {
	cols := 0
	for _, l := range lines {
		cols = max(cols, visibleLen(l))
	}
	width := float64(svgPad*2) + float64(cols)*svgCharWidth
	height := svgPad*2 + len(lines)*svgLineHeight
	var b, shapes strings.Builder
	strokes := map[string][]segment{}
	var strokeOrder []string
	addSegment := func(key string, s segment) {
		if _, ok := strokes[key]; !ok {
			strokeOrder = append(strokeOrder, key)
		}
		strokes[key] = append(strokes[key], s)
	}
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%.0f" height="%d" viewBox="0 0 %.0f %d">`+"\n", width, height, width, height)
	fmt.Fprintf(&b, `<rect x="0" y="0" width="%.0f" height="%d" rx="8" ry="8" fill="#0d1117"/>`+"\n", width, height)
	fmt.Fprintf(&b, `<g font-family="monospace" font-size="%d" fill="%s" xml:space="preserve" style="white-space:pre;font-variant-ligatures:none">`+"\n", svgFontSize, svgForeground)
	for i, l := range lines {
		y := svgPad + i*svgLineHeight
		top, mid, bottom := float64(y), float64(y)+svgLineHeight/2, float64(y+svgLineHeight)
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
			text := []rune(r.text)
			for k, ch := range text {
				left, cx := x+float64(k)*svgCharWidth, x+float64(k)*svgCharWidth+svgCharWidth/2
				right := left + svgCharWidth
				if l, rt, up, down, ok := boxGeometry(ch); ok {
					key := r.st.stroke()
					switch {
					case l && rt:
						addSegment(key, segment{left, mid, right, mid})
					case l:
						addSegment(key, segment{left, mid, cx, mid})
					case rt:
						addSegment(key, segment{cx, mid, right, mid})
					}
					switch {
					case up && down:
						addSegment(key, segment{cx, top, cx, bottom})
					case up:
						addSegment(key, segment{cx, top, cx, mid})
					case down:
						addSegment(key, segment{cx, mid, cx, bottom})
					}
					text[k] = ' '
					continue
				}
				side := svgCharWidth - 2
				switch ch {
				case '■':
					fmt.Fprintf(&shapes, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" %s/>`, cx-side/2, mid-side/2, side, side, r.st.paint())
					text[k] = ' '
				case '□':
					fmt.Fprintf(&shapes, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="none" %s/>`, cx-side/2+0.5, mid-side/2+0.5, side-1, side-1, r.st.stroke())
					text[k] = ' '
				}
			}
			for _, w := range words(string(text)) {
				fmt.Fprintf(&b, `<text x="%.1f" y="%d"%s>%s</text>`, x+float64(w.col)*svgCharWidth, y+svgLineHeight-5, attrs, xmlEscape(w.text))
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("</g>\n")
	b.WriteString(shapes.String())
	for _, key := range strokeOrder {
		fmt.Fprintf(&b, `<path fill="none" stroke-width="1" stroke-linecap="square" %s d="%s"/>`+"\n", key, svgPath(strokes[key]))
	}
	b.WriteString("</svg>\n")
	_, err := io.WriteString(w, b.String())
	return err
}
