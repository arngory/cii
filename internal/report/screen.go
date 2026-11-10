package report

import (
	"bytes"
	"cmp"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/risk"
)

const (
	twoColumns   = 110
	threeColumns = 200
)

type frameChars struct{ tl, tr, bl, br, h, v string }

var (
	unicodeFrame = frameChars{"┌", "┐", "└", "┘", "─", "│"}
	asciiFrame   = frameChars{"+", "+", "+", "+", "-", "|"}
)

var ansiSeq = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

func visibleLen(s string) int { return utf8.RuneCountInString(ansiSeq.ReplaceAllString(s, "")) }

func clipVisible(s string, n int) string {
	if visibleLen(s) <= n {
		return s
	}
	if n <= 0 {
		return ""
	}
	var b strings.Builder
	count, styled := 0, false
	for i := 0; i < len(s); {
		if loc := ansiSeq.FindStringIndex(s[i:]); loc != nil && loc[0] == 0 {
			b.WriteString(s[i : i+loc[1]])
			styled = true
			i += loc[1]
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if count == n-1 {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		count++
		i += size
	}
	if styled {
		b.WriteString("\x1b[0m")
	}
	return b.String()
}

func padVisible(s string, n int) string {
	s = clipVisible(s, n)
	return s + strings.Repeat(" ", max(0, n-visibleLen(s)))
}

type panel struct {
	title string
	lines []string
}

func (p panel) box(c paint, f frameChars, width int) []string {
	inner := width - 4
	title := clipVisible(p.title, max(0, width-6))
	top := f.tl + f.h + " " + c.bold(title) + " " + strings.Repeat(f.h, max(0, width-visibleLen(title)-5)) + f.tr
	out := []string{top}
	for _, l := range p.lines {
		out = append(out, f.v+" "+padVisible(l, inner)+" "+f.v)
	}
	return append(out, f.bl+strings.Repeat(f.h, max(0, width-2))+f.br)
}

func columnWidths(width int) []int {
	switch {
	case width < twoColumns:
		return []int{width}
	case width < threeColumns:
		left := min(max(width*2/5, 60), 76)
		return []int{left, width - left - 1}
	}
	left, right := 66, 58
	return []int{left, width - left - right - 2, right}
}

func bufferLines(write func(*bytes.Buffer)) []string {
	var b bytes.Buffer
	write(&b)
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

func (r *Report) Screen(st Style, header string, footer []string) []string {
	c := paint(st.Color)
	m, f := asciiMarks, asciiFrame
	if st.Unicode {
		m, f = unicodeMarks, unicodeFrame
	}
	width := max(st.Width, 60)
	widths := columnWidths(width)
	cols := make([][]panel, len(widths))
	last := len(widths) - 1
	place := func(i int, p panel) {
		if len(p.lines) > 0 {
			cols[min(i, last)] = append(cols[min(i, last)], p)
		}
	}

	fams := r.families()
	for _, fm := range fams {
		place(0, panel{"IP quality · " + fm.label, qualityLines(c, m, fm.label, fm.host, widths[0]-4)})
	}
	mid := min(1, last)
	place(mid, panel{"Region & services", serviceLines(c, m, fams, widths[mid]-4)})
	place(2, panel{"Reputation lists & mail", checkLines(c, m, fams, widths[min(2, last)]-4)})

	var out []string
	if header != "" {
		out = append(out, clipVisible(header, width))
	}
	out = append(out, joinColumns(c, f, cols, widths)...)
	if len(footer) > 0 {
		parts := make([]gcell, len(footer))
		for i, s := range footer {
			parts[i] = gcell{text: s, style: c.dim}
		}
		out = append(out, bufferLines(func(b *bytes.Buffer) { writeLine(b, width, m.sep, "", 0, parts) })...)
	}
	return out
}

func joinColumns(c paint, f frameChars, cols [][]panel, widths []int) []string {
	var rendered [][]string
	var used []int
	for i, ps := range cols {
		if len(ps) == 0 {
			continue
		}
		var lines []string
		for _, p := range ps {
			lines = append(lines, p.box(c, f, widths[i])...)
		}
		rendered = append(rendered, lines)
		used = append(used, widths[i])
	}
	height := 0
	for _, l := range rendered {
		height = max(height, len(l))
	}
	out := make([]string, height)
	for row := range out {
		var b strings.Builder
		for i, l := range rendered {
			if i > 0 {
				b.WriteByte(' ')
			}
			cell := ""
			if row < len(l) {
				cell = l[row]
			}
			if i < len(rendered)-1 {
				cell = padVisible(cell, used[i])
			}
			b.WriteString(cell)
		}
		out[row] = strings.TrimRight(b.String(), " ")
	}
	return out
}

func qualityLines(c paint, m marks, label string, h *Host, iw int) []string {
	if h.Address == "" {
		return []string{c.dim("unavailable")}
	}
	field := func(name, value string, style func(string) string) string {
		return c.dim(pad(name, 9)) + style(value)
	}
	lines := []string{field("Address", h.Address, c.green)}
	if place := bestPlace(h.Geo); place != "" {
		lines = append(lines, field("Place", place, func(s string) string { return s }))
	}
	if as := bestASN(h.Geo); as != "" {
		lines = append(lines, field("ASN", as, func(s string) string { return s }))
	}
	p := h.Profile
	if text, discrepant := p.registryText(); text != "" {
		style := c.green
		if discrepant {
			style = c.yellow
		}
		lines = append(lines, field("Reg.", strings.TrimPrefix(text, "registered "), style))
	}
	if p != nil {
		var typ []gcell
		typ = append(typ, voteCells(c, "", p.Usage)...)
		typ = append(typ, voteCells(c, "company ", p.Company)...)
		if len(typ) > 0 {
			lines = append(lines, bufferLines(func(b *bytes.Buffer) { writeLine(b, iw, m.sep, c.dim(pad("Type", 9)), 9, typ) })...)
		}
		if t := factorTable(c, h, iw); len(t) > 0 {
			lines = append(append(lines, ""), t...)
		}
	}
	var pending, notes []string
	for _, r := range h.Services {
		if r.Group != risk.Reputation {
			continue
		}
		switch {
		case r.Status == probe.Pending:
			pending = append(pending, serviceName(r))
		case coveredByProfile(h, r):
		default:
			sym, style := mark(c, m, r, true)
			text := serviceName(r)
			if d := cmp.Or(detailOf(r), r.Reason); d != "" {
				text += ": " + d
			}
			notes = append(notes, style(sym)+" "+text)
		}
	}
	if len(notes) > 0 {
		lines = append(append(lines, ""), notes...)
	}
	if len(pending) > 0 {
		lines = append(lines, c.dim(m.pending+" waiting: "+strings.Join(pending, ", ")))
	}
	return lines
}

var factorHeads = map[probe.Flag]string{
	probe.Proxy: "proxy", probe.VPN: "VPN", probe.Tor: "Tor", probe.Hosting: "host", probe.Abuser: "abuse", probe.Bot: "bot",
}

const factorCell = 6

func factorTable(c paint, h *Host, iw int) []string {
	var rows []probe.Result
	nameW := 0
	for _, r := range h.factResults() {
		if r.Facts != nil && (r.Facts.Score != nil || len(r.Facts.Flags) > 0) {
			rows = append(rows, r)
			nameW = max(nameW, utf8.RuneCountInString(serviceName(r)))
		}
	}
	if len(rows) == 0 {
		return nil
	}
	nameW = min(nameW, max(8, iw-factorCell*(len(probe.Flags)+1)))
	head := pad("", nameW) + fmt.Sprintf("%*s", factorCell, "score")
	for _, f := range probe.Flags {
		head += fmt.Sprintf("%*s", factorCell, factorHeads[f])
	}
	out := []string{c.dim(head)}
	cell := func(text string, style func(string) string) string {
		return strings.Repeat(" ", max(0, factorCell-utf8.RuneCountInString(text))) + style(text)
	}
	for _, r := range rows {
		f := r.Facts
		line := padVisible(serviceName(r), nameW)
		if f.Score != nil {
			line += cell(strconv.Itoa(*f.Score), scoreStyle(c, *f.Score))
		} else {
			line += cell("—", c.dim)
		}
		for _, flag := range probe.Flags {
			on, ok := f.Flags[flag]
			switch {
			case !ok:
				line += cell("—", c.dim)
			case on:
				line += cell("yes", c.red)
			default:
				line += cell("no", c.green)
			}
		}
		out = append(out, line)
	}
	return out
}

func serviceLines(c paint, m marks, fams []fam, iw int) []string {
	var lines []string
	var regions []fam
	for _, f := range fams {
		if f.host.Region != nil {
			regions = append(regions, f)
		}
	}
	for _, f := range regions {
		label := "Region"
		if len(regions) > 1 {
			label += " " + f.label
		}
		lw := utf8.RuneCountInString(label)
		lines = append(lines, bufferLines(func(b *bytes.Buffer) {
			writeLine(b, iw, m.sep, c.bold(label)+"  ", lw+2, regionParts(c, f.host.Region, nil))
			if edges := cdnParts(c, f.host.Region); len(edges) > 0 {
				writeLine(b, iw, m.sep, c.dim(pad("CDN", lw))+"  ", lw+2, edges)
			}
		})...)
	}
	grid := bufferLines(func(b *bytes.Buffer) {
		writeServiceGrid(b, c, m, iw, fams, func(_ *Host, r probe.Result) bool { return !isRiskGroup(r.Group) })
	})
	if len(grid) > 0 {
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, grid...)
	}
	return lines
}

func checkLines(c paint, m marks, fams []fam, iw int) []string {
	return bufferLines(func(b *bytes.Buffer) {
		writeServiceGrid(b, c, m, iw, fams, func(_ *Host, r probe.Result) bool {
			return isRiskGroup(r.Group) && r.Group != risk.Reputation
		})
	})
}

func isRiskGroup(g probe.Group) bool {
	return g == risk.Reputation || g == risk.DNSBL || g == risk.Mail || g == risk.Network
}

func Progress(r *Report) (done, total int) {
	for _, res := range r.allResults() {
		total++
		if res.Status != probe.Pending {
			done++
		}
	}
	return done, total
}
