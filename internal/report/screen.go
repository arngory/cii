package report

import (
	"bytes"
	"cmp"
	"fmt"
	"regexp"
	"slices"
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

func columnCount(width int) int {
	switch {
	case width < twoColumns:
		return 1
	case width < threeColumns:
		return 2
	}
	return 3
}

func columnWidths(width, n int) []int {
	switch n {
	case 1:
		return []int{width}
	case 2:
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
	width := st.Width
	if width <= 0 {
		width = 80
	}
	ps := slices.DeleteFunc(r.panels(c, m), func(p slotPanel) bool { return len(p.lines(width-4)) == 0 })
	var slots []int
	for _, p := range ps {
		if !slices.Contains(slots, p.slot) {
			slots = append(slots, p.slot)
		}
	}
	slices.Sort(slots)
	n := max(1, min(len(slots), columnCount(width)))
	widths := columnWidths(width, n)
	cols := make([][]panel, n)
	for _, p := range ps {
		i := min(slices.Index(slots, p.slot), n-1)
		cols[i] = append(cols[i], panel{p.title, p.lines(widths[i] - 4)})
	}

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

type slotPanel struct {
	slot  int
	title string
	lines func(iw int) []string
}

func (r *Report) panels(c paint, m marks) []slotPanel {
	fams := r.families()
	var ps []slotPanel
	for _, fm := range fams {
		ps = append(ps, slotPanel{0, "IP quality · " + fm.label, func(iw int) []string { return qualityLines(c, m, fm.host, iw) }})
	}
	if r.Bench != nil {
		ps = append(ps, slotPanel{0, "Benchmark", func(iw int) []string {
			return bufferLines(func(b *bytes.Buffer) { writeBenchCompact(b, c, m, iw, r.Bench) })
		}})
	}
	ps = append(ps,
		slotPanel{1, "Region & services", func(iw int) []string { return serviceLines(c, m, fams, iw) }},
		slotPanel{2, "Reputation lists & mail", func(iw int) []string { return checkLines(c, m, fams, iw) }},
	)
	if len(r.Censor) > 0 {
		ps = append(ps, slotPanel{2, "Censorship", func(iw int) []string {
			if r.Mode == "censor" {
				return bufferLines(func(b *bytes.Buffer) { writeGrid2(b, c, m, iw, []column{newColumn("", r.Censor)}, [][]string{nil}) })
			}
			return summaryLines(c, m, r.Censor, iw)
		}})
	}
	return ps
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
			writeLine(b, iw, m.sep, c.bold(label)+"  ", lw+2, regionParts(c, f.host.Region))
			if edges := cdnParts(c, f.host.Region); len(edges) > 0 {
				writeLine(b, iw, m.sep, c.dim(pad("CDN", lw))+"  ", lw+2, edges)
			}
		})...)
	}
	grid := bufferLines(func(b *bytes.Buffer) {
		writeServiceGrid(b, c, m, iw, fams, func(r probe.Result) bool { return !isRiskGroup(r.Group) })
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
		writeServiceGrid(b, c, m, iw, fams, func(r probe.Result) bool {
			return isRiskGroup(r.Group) && r.Group != risk.Reputation && r.Service != risk.PTRService
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

const maxFindings = 8

func summaryLines(c paint, m marks, rs []probe.Result, iw int) []string {
	var groups []probe.Group
	labelW := 0
	for _, r := range rs {
		if !slices.Contains(groups, r.Group) {
			groups = append(groups, r.Group)
			labelW = max(labelW, utf8.RuneCountInString(groupTitle(r.Group)))
		}
	}
	var lines, findings []string
	for _, g := range groups {
		counts := map[probe.Status]int{}
		var hits []probe.Result
		for _, r := range rs {
			if r.Group != g {
				continue
			}
			st := r.Status
			if st == probe.OK {
				st = probe.Yes
			}
			counts[st]++
			if st == probe.No || st == probe.Partial || st == probe.IPBlock {
				hits = append(hits, r)
			}
		}
		var parts []gcell
		for _, st := range []probe.Status{probe.Yes, probe.No, probe.Partial, probe.IPBlock, probe.Unknown, probe.Failed, probe.Pending} {
			if n := counts[st]; n > 0 {
				sym, style := mark(c, m, probe.Result{Status: st}, true)
				parts = append(parts, gcell{text: sym + " " + strconv.Itoa(n), style: style})
			}
		}
		label := c.bold(pad(groupTitle(g), labelW)) + "  "
		lines = append(lines, bufferLines(func(b *bytes.Buffer) { writeLine(b, iw, m.sep, label, labelW+2, parts) })...)
		for _, r := range hits {
			sym, style := mark(c, m, r, true)
			text := style(sym) + " " + groupTitle(g) + ": " + serviceName(r)
			if d := cmp.Or(r.Detail, r.Reason); d != "" {
				text += " " + c.dim(d)
			}
			findings = append(findings, text)
		}
	}
	if len(findings) > maxFindings {
		more := len(findings) - maxFindings
		findings = append(findings[:maxFindings], c.dim(fmt.Sprintf("… %d more in --debug and the log", more)))
	}
	if len(findings) > 0 {
		lines = append(append(lines, ""), findings...)
	}
	return lines
}
