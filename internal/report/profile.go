package report

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
)

type Profile struct {
	Registered    string   `json:"registered,omitempty"`
	GeoConsistent *bool    `json:"geo_consistent,omitempty"`
	Usage         []Vote   `json:"usage,omitempty"`
	Company       []Vote   `json:"company,omitempty"`
	Scores        []Score  `json:"scores,omitempty"`
	Factors       []Factor `json:"factors,omitempty"`
}

type Vote struct {
	Value   string   `json:"value"`
	Sources []string `json:"sources"`
}

type Score struct {
	Source string `json:"source"`
	Score  int    `json:"score"`
}

type Factor struct {
	Flag    probe.Flag `json:"flag"`
	Hits    []string   `json:"hits"`
	Checked int        `json:"checked"`
}

func (h *Host) refreshProfile() {
	var rs []probe.Result
	p := &Profile{}
	if h.Region != nil {
		rs = append(rs, h.Region.Results...)
		for _, r := range h.Region.Results {
			if r.Group == region.Registry && r.Status == probe.OK && p.Registered == "" {
				p.Registered = r.Country
			}
		}
		if p.Registered != "" && len(h.Region.Verdict) > 0 {
			ok := slices.Contains(h.Region.Verdict, p.Registered)
			p.GeoConsistent = &ok
		}
	}
	rs = append(rs, h.Services...)
	usage, company := map[string][]string{}, map[string][]string{}
	hits := map[probe.Flag][]string{}
	checked := map[probe.Flag]int{}
	for _, r := range rs {
		f := r.Facts
		if f == nil {
			continue
		}
		if f.Usage != "" {
			usage[f.Usage] = append(usage[f.Usage], r.Service)
		}
		if f.Company != "" {
			company[f.Company] = append(company[f.Company], r.Service)
		}
		if f.Score != nil {
			p.Scores = append(p.Scores, Score{Source: r.Service, Score: *f.Score})
		}
		for flag, on := range f.Flags {
			checked[flag]++
			if on {
				hits[flag] = append(hits[flag], r.Service)
			}
		}
	}
	p.Usage, p.Company = votes(usage), votes(company)
	for _, flag := range probe.Flags {
		if checked[flag] > 0 {
			slices.Sort(hits[flag])
			p.Factors = append(p.Factors, Factor{Flag: flag, Hits: append([]string{}, hits[flag]...), Checked: checked[flag]})
		}
	}
	if p.Registered == "" && len(p.Usage) == 0 && len(p.Company) == 0 && len(p.Scores) == 0 && len(p.Factors) == 0 {
		h.Profile = nil
		return
	}
	h.Profile = p
}

func votes(m map[string][]string) []Vote {
	var out []Vote
	for v, src := range m {
		slices.Sort(src)
		out = append(out, Vote{Value: v, Sources: src})
	}
	slices.SortFunc(out, func(a, b Vote) int {
		return cmp.Or(cmp.Compare(len(b.Sources), len(a.Sources)), cmp.Compare(a.Value, b.Value))
	})
	return out
}

var usageTitles = map[string]string{
	"isp": "ISP", "mobile": "mobile", "hosting": "hosting", "business": "business",
	"education": "education", "government": "government", "cdn": "CDN",
}

var flagTitles = map[probe.Flag]string{
	probe.Proxy: "proxy", probe.VPN: "VPN", probe.Tor: "Tor", probe.Hosting: "hosting", probe.Abuser: "abuser", probe.Bot: "bot",
}

type profileRow struct {
	title string
	parts []gcell
}

func profileRows(c paint, p *Profile) []profileRow {
	if p == nil {
		return nil
	}
	var rows []profileRow
	var typ []gcell
	typ = append(typ, voteCells(c, "", p.Usage)...)
	typ = append(typ, voteCells(c, "company ", p.Company)...)
	if len(typ) > 0 {
		rows = append(rows, profileRow{"Type", typ})
	}
	if len(p.Scores) > 0 {
		var cells []gcell
		for _, s := range p.Scores {
			cells = append(cells, gcell{text: s.Source + " " + strconv.Itoa(s.Score), style: scoreStyle(c, s.Score)})
		}
		rows = append(rows, profileRow{"Score", cells})
	}
	if len(p.Factors) > 0 {
		var cells []gcell
		for _, f := range p.Factors {
			text := fmt.Sprintf("%s %d/%d", flagTitles[f.Flag], len(f.Hits), f.Checked)
			if len(f.Hits) == 0 {
				cells = append(cells, gcell{text: text, style: c.dim})
				continue
			}
			cells = append(cells, gcell{text: text + ": " + strings.Join(f.Hits, ", "), style: c.yellow})
		}
		rows = append(rows, profileRow{"Flags", cells})
	}
	return rows
}

func voteCells(c paint, prefix string, vs []Vote) []gcell {
	total := 0
	for _, v := range vs {
		total += len(v.Sources)
	}
	var cells []gcell
	for i, v := range vs {
		title := cmp.Or(usageTitles[v.Value], v.Value)
		if i == 0 {
			cells = append(cells, plain(fmt.Sprintf("%s%s %d/%d", prefix, title, len(v.Sources), total)))
			continue
		}
		cells = append(cells, gcell{text: prefix + title + ": " + strings.Join(v.Sources, ", "), style: c.yellow})
	}
	return cells
}

func scoreStyle(c paint, score int) func(string) string {
	switch {
	case score >= 75:
		return c.red
	case score >= 25:
		return c.yellow
	}
	return c.dim
}

func writeProfile(w io.Writer, c paint, label string, h *Host) {
	p := h.Profile
	title := "IP profile (" + label + ")"
	if p.Registered != "" {
		state := ""
		if p.GeoConsistent != nil {
			state = map[bool]string{true: ", geo-consistent", false: ", geo-discrepant"}[*p.GeoConsistent]
		}
		title += " · registered " + p.Registered + state
	}
	fmt.Fprintln(w, c.bold(title))
	header := []gcell{{text: "  source", style: c.dim}, {text: "usage", style: c.dim}, {text: "company", style: c.dim}, {text: "score", style: c.dim}}
	for _, f := range probe.Flags {
		header = append(header, gcell{text: flagTitles[f], style: c.dim})
	}
	rows := [][]gcell{header}
	var rs []probe.Result
	if h.Region != nil {
		rs = append(rs, h.Region.Results...)
	}
	for _, r := range append(rs, h.Services...) {
		f := r.Facts
		if f == nil {
			continue
		}
		row := []gcell{plain("  " + r.Service), plain(cmp.Or(usageTitles[f.Usage], "—")), plain(cmp.Or(usageTitles[f.Company], "—"))}
		if f.Score != nil {
			row = append(row, gcell{text: strconv.Itoa(*f.Score), style: scoreStyle(c, *f.Score)})
		} else {
			row = append(row, gcell{text: "—", style: c.dim})
		}
		for _, flag := range probe.Flags {
			on, ok := f.Flags[flag]
			switch {
			case !ok:
				row = append(row, gcell{text: "—", style: c.dim})
			case on:
				row = append(row, gcell{text: "yes", style: c.red})
			default:
				row = append(row, gcell{text: "no", style: c.green})
			}
		}
		rows = append(rows, row)
	}
	writeGrid(w, rows)
	fmt.Fprintln(w)
}
