package report

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strconv"

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

func (h *Host) factResults() []probe.Result {
	var rs []probe.Result
	if h.Region != nil {
		rs = append(rs, h.Region.Results...)
	}
	return append(rs, h.Services...)
}

func (p *Profile) registryText() string {
	if p == nil || p.Registered == "" {
		return ""
	}
	switch {
	case p.GeoConsistent == nil:
		return "registered " + p.Registered
	case *p.GeoConsistent:
		return "registered " + p.Registered + ", geo-consistent"
	}
	return "registered " + p.Registered + ", geo-discrepant"
}

func (h *Host) refreshProfile() {
	p := &Profile{}
	if h.Region != nil {
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
	usage, company := map[string][]string{}, map[string][]string{}
	hits := map[probe.Flag][]string{}
	checked := map[probe.Flag]int{}
	for _, r := range h.factResults() {
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

func scoreStyle(c paint, score int) func(string) string { return levelStyle(c, scoreLevel(score)) }

func writeProfile(w io.Writer, c paint, label string, h *Host) {
	p := h.Profile
	title := "IP profile (" + label + ")"
	if text := p.registryText(); text != "" {
		title += " · " + text
	}
	fmt.Fprintln(w, c.bold(title))
	header := []gcell{{text: "  source", style: c.dim}, {text: "usage", style: c.dim}, {text: "company", style: c.dim}, {text: "score", style: c.dim}}
	for _, f := range probe.Flags {
		header = append(header, gcell{text: flagTitles[f], style: c.dim})
	}
	rows := [][]gcell{header}
	for _, r := range h.factResults() {
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
