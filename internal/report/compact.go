package report

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/arngory/cii/internal/censor"
	"github.com/arngory/cii/internal/geodb"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/refdata"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/risk"
	"github.com/arngory/cii/internal/services"
)

type Style struct {
	Color   bool
	Unicode bool
	Width   int
	Lang    string
}

type marks struct {
	yes, no, partial, block, unknown, failed, none, sep, down, up, pending string
	rule, barOn, barOff, warn                                              string
	lang                                                                   string
}

var (
	unicodeMarks = marks{"✓", "✗", "◐", "⊘", "?", "!", "·", " · ", "↓", "↑", "◌", "─", "■", "□", "⚠", ""}
	asciiMarks   = marks{"+", "-", "~", "x", "?", "!", ".", " | ", "down", "up", "o", "-", "#", ".", "!", ""}
)

func UnicodeTerminal() bool {
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := os.Getenv(k); v != "" {
			v = strings.ToUpper(v)
			return strings.Contains(v, "UTF-8") || strings.Contains(v, "UTF8")
		}
	}
	return true
}

type fam struct {
	label string
	host  *Host
}

func (r *Report) allResults() []probe.Result {
	out := append([]probe.Result(nil), r.Censor...)
	for _, f := range r.families() {
		if f.host.Region != nil {
			out = append(out, f.host.Region.Results...)
		}
		out = append(out, f.host.Services...)
	}
	return out
}

func (r *Report) FailedChecks() int {
	n := 0
	for _, res := range r.allResults() {
		if res.Status == probe.Failed {
			n++
		}
	}
	return n
}

func (r *Report) Extended() bool {
	for _, res := range r.allResults() {
		if res.Extended {
			return true
		}
	}
	return false
}

func (r *Report) families() []fam {
	var out []fam
	for _, f := range []fam{{"IPv4", r.IPv4}, {"IPv6", r.IPv6}} {
		if f.host != nil {
			out = append(out, f)
		}
	}
	for _, h := range r.Exits {
		out = append(out, fam{h.Query, h})
	}
	return out
}

func unavailableReason(h *Host) string {
	if strings.Contains(h.Error, "offline") {
		return "not on local interfaces (offline)"
	}
	return "unavailable"
}

func pad(s string, n int) string {
	return s + strings.Repeat(" ", max(0, n-utf8.RuneCountInString(s)))
}

func bestPlace(geo []geodb.Record) string {
	var country, name, city string
	for _, g := range geo {
		if country == "" && g.Country != "" {
			country, name = g.Country, g.CountryName
		}
		if city == "" && g.City != "" {
			city = g.City
		}
	}
	if country == "" {
		return ""
	}
	if name == "" {
		name = refdata.CountryName(country)
	}
	s := strings.TrimSpace(country + " " + name)
	if city != "" {
		s += ", " + city
	}
	return s
}

func bestASN(geo []geodb.Record) string {
	for _, g := range geo {
		if g.ASN != 0 {
			return strings.TrimSpace(fmt.Sprintf("AS%d %s", g.ASN, g.ASOrg))
		}
	}
	return ""
}

func regionParts(c paint, m marks, s *region.Summary) []gcell {
	parts := []gcell{verdictCell(c, s.Verdict)}
	for _, g := range []struct {
		group probe.Group
		title string
	}{{region.GeoIP, "GeoIP"}, {region.Platform, m.tr("platforms")}} {
		agree, total := 0, 0
		for _, r := range s.Results {
			if r.Group == g.group && r.Status == probe.OK {
				total++
				if slices.Contains(s.Verdict, r.Country) {
					agree++
				}
			}
		}
		if total > 0 {
			style := c.dim
			if agree < total {
				style = c.yellow
			}
			parts = append(parts, gcell{text: fmt.Sprintf("%s %d/%d", g.title, agree, total), style: style})
		}
	}
	for _, r := range s.Attention {
		parts = append(parts, gcell{text: serviceName(r) + " " + m.tr("says") + " " + r.Country, style: c.yellow})
	}
	for _, r := range s.Results {
		if r.Group != region.CDN && r.Status == probe.Unknown && strings.HasPrefix(r.Reason, "service default") {
			parts = append(parts, gcell{text: serviceName(r) + ": " + strings.TrimPrefix(r.Reason, "service "), style: c.dim})
		}
	}
	return parts
}

func cdnParts(c paint, s *region.Summary) []gcell {
	var parts []gcell
	for _, r := range s.Results {
		if r.Group != region.CDN || r.IATA == "" {
			continue
		}
		text := serviceName(r) + " " + r.IATA
		if r.Country != "" {
			text += " " + r.Country
		}
		parts = append(parts, gcell{text: text, style: c.dim})
	}
	return parts
}

func serviceName(r probe.Result) string {
	if r.Extended {
		return r.Service + "*"
	}
	return r.Service
}

func writeLine(w io.Writer, width int, sep, label string, labelWidth int, parts []gcell) {
	var b strings.Builder
	b.WriteString(label)
	col := labelWidth
	for i, p := range parts {
		n := utf8.RuneCountInString(p.text)
		if i > 0 {
			if col+utf8.RuneCountInString(sep)+n > width {
				b.WriteString("\n" + strings.Repeat(" ", labelWidth))
				col = labelWidth
			} else {
				b.WriteString(sep)
				col += utf8.RuneCountInString(sep)
			}
		}
		text := p.text
		if p.style != nil {
			text = p.style(text)
		}
		b.WriteString(text)
		col += n
	}
	b.WriteByte('\n')
	io.WriteString(w, b.String())
}

var groupTitles = map[probe.Group]string{
	censor.DNS:         "DNS",
	censor.DPI:         "DPI",
	censor.Geoblock:    "Geoblock",
	censor.Telegram:    "Telegram",
	services.Streaming: "Streaming",
	services.AI:        "AI",
	services.Web:       "Web",
	risk.Reputation:    "Reputation",
	risk.DNSBL:         "DNSBL",
	risk.Mail:          "Mail",
	risk.Network:       "Network",
	region.GeoIP:       "GeoIP",
	region.Registry:    "Registry",
	region.Platform:    "Platforms",
	region.CDN:         "CDN",
}

func wide(g probe.Group) bool {
	return g == risk.Reputation || g == risk.Mail || g == risk.Network
}

func detailOf(r probe.Result) string {
	if r.Detail != "" && (r.Status != probe.Yes || wide(r.Group)) {
		return r.Detail
	}
	return ""
}

func groupTitle(g probe.Group) string {
	if t, ok := groupTitles[g]; ok {
		return t
	}
	if t := services.Title(g); t != "" {
		return t
	}
	s := string(g)
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func coveredByProfile(h *Host, r probe.Result) bool {
	return h.Profile != nil && r.Group == risk.Reputation && r.Facts != nil && r.Status == probe.Yes
}

func writeServiceGrid(w io.Writer, c paint, m marks, width int, fams []fam, keep func(probe.Result) bool) {
	var cols []column
	var verdicts [][]string
	for _, f := range fams {
		rs := slices.DeleteFunc(slices.Clone(f.host.Services), func(r probe.Result) bool { return !keep(r) })
		if len(rs) > 0 {
			cols = append(cols, newColumn(f.label, rs))
			var v []string
			if f.host.Region != nil {
				v = f.host.Region.Verdict
			}
			verdicts = append(verdicts, v)
		}
	}
	writeGrid2(w, c, m, width, cols, verdicts)
}

func writeGrid2(w io.Writer, c paint, m marks, width int, cols []column, verdicts [][]string) {
	if len(cols) == 0 {
		return
	}
	var groups []probe.Group
	labelWidth := 0
	for _, col := range cols {
		for _, r := range col.results {
			if !slices.Contains(groups, r.Group) {
				groups = append(groups, r.Group)
				labelWidth = max(labelWidth, utf8.RuneCountInString(groupTitle(r.Group)))
			}
		}
	}
	fmt.Fprintln(w)
	if len(cols) > 1 {
		labels := make([]string, len(cols))
		for i, col := range cols {
			labels[i] = col.label
		}
		fmt.Fprintln(w, c.dim(pad("", labelWidth)+"  "+m.tr("marks")+": "+strings.Join(labels, " ")))
	}
	sections := make([][]item, len(groups))
	widths := make([]int, len(groups))
	for gi, g := range groups {
		var items []item
		for _, first := range rowsOf(cols, g) {
			var it item
			country := ""
			for i, col := range cols {
				r, ok := col.byKey[key(first)]
				sym, st := mark(c, m, r, ok)
				it.plain += sym
				it.styled += st(sym)
				if ok && r.Country != "" && !slices.Contains(verdicts[i], r.Country) {
					country = r.Country
				}
			}
			rest := " " + serviceName(first)
			if country != "" {
				rest += " " + country
			}
			it.plain += rest
			it.styled += rest
			if d := detailOf(first); d != "" && len(cols) == 1 {
				d = " " + d
				it.plain += d
				it.styled += c.dim(d)
			}
			widths[gi] = max(widths[gi], utf8.RuneCountInString(it.plain)+3)
			items = append(items, it)
		}
		sections[gi] = items
	}
	cell := 0
	for gi := range groups {
		if !wide(groups[gi]) {
			cell = max(cell, widths[gi])
		}
	}
	for gi, g := range groups {
		cw := cell
		if wide(g) || cw == 0 {
			cw = widths[gi]
		}
		writeColumns(w, c.bold(pad(groupTitle(g), labelWidth))+"  ", labelWidth+2, width, cw, sections[gi])
	}
}

func Legend(r *Report, unicode bool, lang string) string {
	m := asciiMarks
	if unicode {
		m = unicodeMarks
	}
	m.lang = lang
	used := map[probe.Status]bool{}
	for _, f := range r.families() {
		for _, res := range f.host.Services {
			used[res.Status] = true
		}
	}
	for _, res := range r.Censor {
		used[res.Status] = true
	}
	var parts []string
	for _, e := range []struct {
		st   probe.Status
		sym  string
		text string
	}{{probe.No, m.no, "no"}, {probe.Partial, m.partial, "partial"}, {probe.IPBlock, m.block, "blocked"}, {probe.Unknown, m.unknown, "unknown"}, {probe.Failed, m.failed, "error"}} {
		if used[e.st] {
			parts = append(parts, e.sym+" "+m.tr(e.text))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return m.yes + " " + m.tr("yes") + ", " + strings.Join(parts, ", ")
}

type item struct{ plain, styled string }

func mark(c paint, m marks, r probe.Result, ok bool) (string, func(string) string) {
	if !ok {
		return m.none, c.dim
	}
	switch r.Status {
	case probe.Yes, probe.OK:
		return m.yes, c.green
	case probe.No:
		return m.no, c.red
	case probe.Partial:
		return m.partial, c.yellow
	case probe.IPBlock:
		return m.block, c.red
	case probe.Failed:
		return m.failed, c.dim
	case probe.Pending:
		return m.pending, c.dim
	}
	return m.unknown, c.dim
}

func writeColumns(w io.Writer, label string, labelWidth, width, cell int, items []item) {
	if len(items) == 0 {
		return
	}
	perRow := max(1, (width-labelWidth)/cell)
	rows := (len(items) + perRow - 1) / perRow
	var b strings.Builder
	for row := 0; row < rows; row++ {
		if row == 0 {
			b.WriteString(label)
		} else {
			b.WriteString(strings.Repeat(" ", labelWidth))
		}
		for col := 0; col < perRow; col++ {
			i := col*rows + row
			if i >= len(items) {
				break
			}
			it := items[i]
			b.WriteString(it.styled)
			if col < perRow-1 && (col+1)*rows+row < len(items) {
				b.WriteString(strings.Repeat(" ", cell-utf8.RuneCountInString(it.plain)))
			}
		}
		b.WriteByte('\n')
	}
	io.WriteString(w, b.String())
}
