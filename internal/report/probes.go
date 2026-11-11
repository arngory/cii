package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/refdata"
	"github.com/arngory/cii/internal/region"
)

func (h *Host) SetRegion(s region.Summary) {
	h.Region = &s
	h.refreshProfile()
}

func (r *Report) SetCensor(rs []probe.Result) {
	r.Censor = rs
}

func (h *Host) SetServices(rs []probe.Result) {
	h.Services = rs
	h.refreshProfile()
}

type section struct {
	group probe.Group
	title string
}

var regionSections = []section{{region.GeoIP, "GeoIP"}, {region.Registry, "Registry"}, {region.Platform, "Platforms"}, {region.CDN, "CDN"}}

func sectionsOf(cols []column) []section {
	var out []section
	seen := map[probe.Group]bool{}
	for _, col := range cols {
		for _, r := range col.results {
			if !seen[r.Group] {
				seen[r.Group] = true
				out = append(out, section{r.Group, groupTitle(r.Group)})
			}
		}
	}
	return out
}

type column struct {
	label   string
	results []probe.Result
	byKey   map[string]probe.Result
}

func newColumn(label string, rs []probe.Result) column {
	col := column{label: label, results: rs, byKey: map[string]probe.Result{}}
	for _, r := range rs {
		col.byKey[key(r)] = r
	}
	return col
}

func key(r probe.Result) string { return string(r.Group) + "\x00" + r.Service }

type labeled struct {
	label string
	host  *Host
}

func writeProbes(w io.Writer, c paint, hosts []labeled) {
	var regionCols, serviceCols []column
	var summaries []*region.Summary
	for _, h := range hosts {
		if h.host == nil {
			continue
		}
		if h.host.Region != nil {
			regionCols = append(regionCols, newColumn(h.label, h.host.Region.Results))
			summaries = append(summaries, h.host.Region)
		}
		if len(h.host.Services) > 0 {
			serviceCols = append(serviceCols, newColumn(h.label, h.host.Services))
		}
	}
	extended := false
	if len(regionCols) > 0 {
		verdict := []gcell{plain("  verdict")}
		for _, s := range summaries {
			verdict = append(verdict, verdictCell(c, s.Verdict))
		}
		extended = writeTable(w, c, "Region", regionCols, regionSections, verdict) || extended
		var notes []string
		for i, s := range summaries {
			for _, r := range s.Attention {
				notes = append(notes, fmt.Sprintf("  %s (%s) says %s", r.Service, regionCols[i].label, r.Country))
			}
		}
		if len(notes) > 0 {
			fmt.Fprintln(w, c.yellow("Disagrees with the verdict"))
			fmt.Fprintln(w, strings.Join(notes, "\n"))
		}
		fmt.Fprintln(w)
	}
	if len(serviceCols) > 0 {
		extended = writeTable(w, c, "Services", serviceCols, sectionsOf(serviceCols), nil) || extended
		fmt.Fprintln(w)
	}
	for _, h := range hosts {
		if h.host != nil && h.host.Profile != nil {
			writeProfile(w, c, h.label, h.host)
		}
	}
	var fails []string
	for _, cols := range [][]column{regionCols, serviceCols} {
		for _, col := range cols {
			for _, r := range col.results {
				if r.Status == probe.Failed {
					fails = append(fails, fmt.Sprintf("  %s (%s): %s", r.Service, col.label, r.Reason))
				}
			}
		}
	}
	if len(fails) > 0 {
		fmt.Fprintln(w, c.dim("Failed checks"))
		fmt.Fprintln(w, c.dim(strings.Join(fails, "\n")))
		fmt.Fprintln(w)
	}
	if extended {
		fmt.Fprintln(w, c.dim("* extended check (--extended): a vendor's internal API or public lookup page, see docs/REGION_CHECKS.md and docs/RISK_CHECKS.md"))
		fmt.Fprintln(w)
	}
}

func writeTable(w io.Writer, c paint, title string, cols []column, sections []section, firstRow []gcell) bool {
	header := []gcell{{text: title, style: c.bold}}
	for _, col := range cols {
		header = append(header, gcell{text: col.label, style: c.bold})
	}
	rows := [][]gcell{header}
	if firstRow != nil {
		rows = append(rows, firstRow)
	}
	extended := false
	for _, s := range sections {
		services := rowsOf(cols, s.group)
		if len(services) == 0 {
			continue
		}
		rows = append(rows, []gcell{{text: s.title, style: c.dim}})
		for _, first := range services {
			name := "  " + first.Service
			if first.Extended {
				name += "*"
				extended = true
			}
			row := []gcell{plain(name)}
			detail := ""
			for _, col := range cols {
				r, ok := col.byKey[key(first)]
				row = append(row, cell(c, r, ok))
				if ok && detail == "" {
					detail = r.Detail
					if detail == "" && r.Status != probe.Yes && r.Status != probe.OK {
						detail = r.Reason
					}
				}
			}
			if detail != "" {
				row = append(row, gcell{text: probe.Truncate(detail, 80), style: c.dim})
			}
			rows = append(rows, row)
		}
	}
	writeGrid(w, rows)
	return extended
}

func rowsOf(cols []column, g probe.Group) []probe.Result {
	seen := map[string]bool{}
	var out []probe.Result
	for _, col := range cols {
		for _, r := range col.results {
			if r.Group == g && !seen[r.Service] {
				seen[r.Service] = true
				out = append(out, r)
			}
		}
	}
	return out
}

func verdictCell(c paint, verdict []string) gcell {
	if len(verdict) == 0 {
		return gcell{text: "?", style: c.dim}
	}
	s := strings.Join(verdict, "/")
	if len(verdict) == 1 {
		if name := refdata.CountryName(verdict[0]); name != "" {
			s += " " + name
		}
	}
	return gcell{text: s, style: c.green}
}

func cell(c paint, r probe.Result, ok bool) gcell {
	if !ok {
		return gcell{text: "—", style: c.dim}
	}
	withCountry := func(s string) string {
		if r.Country != "" {
			return s + " " + r.Country
		}
		return s
	}
	switch r.Status {
	case probe.OK:
		if r.IATA != "" {
			return plain(r.Country + " " + r.IATA)
		}
		return plain(r.Country)
	case probe.Yes:
		return gcell{text: withCountry("yes"), style: c.green}
	case probe.No:
		return gcell{text: withCountry("no"), style: c.red}
	case probe.Partial:
		label := "partial"
		if r.Reason != "" {
			label = r.Reason
		}
		return gcell{text: withCountry(label), style: c.yellow}
	case probe.IPBlock:
		return gcell{text: "blocked", style: c.red}
	case probe.Failed:
		return gcell{text: "error", style: c.dim}
	}
	return gcell{text: "?", style: c.dim}
}
