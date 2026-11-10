package report

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/refdata"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/risk"
)

const (
	badgeGood    = "30;42"
	badgeNeutral = "30;43"
	badgeBad     = "97;41"
)

var usageBadges = map[string]struct{ label, code string }{
	"isp":        {"ISP", badgeGood},
	"mobile":     {"MOB", badgeGood},
	"business":   {"BIZ", badgeNeutral},
	"education":  {"EDU", badgeNeutral},
	"government": {"GOV", badgeNeutral},
	"hosting":    {"HOST", badgeBad},
	"cdn":        {"CDN", badgeBad},
}

const badgeWidth = 6

func usageBadge(c paint, usage string) string {
	b, ok := usageBadges[usage]
	if !ok {
		return c.dim(pad(" —", badgeWidth))
	}
	return c.badge(b.code, pad(b.label, badgeWidth-2))
}

var scoreLevels = []struct {
	below int
	name  string
}{{10, "very low"}, {25, "low"}, {50, "medium"}, {75, "high"}, {101, "very high"}}

func scoreLevel(score int) int {
	for i, l := range scoreLevels {
		if score < l.below {
			return i
		}
	}
	return len(scoreLevels) - 1
}

func levelOf(f *probe.Facts) int {
	if f.Level != nil {
		return *f.Level
	}
	return scoreLevel(*f.Score)
}

func levelStyle(c paint, level int) func(string) string {
	switch {
	case level <= 1:
		return c.green
	case level == 2:
		return c.yellow
	}
	return c.red
}

var factorHeads = map[probe.Flag]string{
	probe.Proxy: "proxy", probe.VPN: "VPN", probe.Tor: "Tor", probe.Hosting: "host", probe.Abuser: "abuse", probe.Bot: "bot",
}

const factorCell = 6

func sectionRule(c paint, m marks, title string, iw int) string {
	return c.bold(title) + " " + c.dim(strings.Repeat(m.rule, max(0, iw-utf8.RuneCountInString(title)-1)))
}

func qualityLines(c paint, m marks, h *Host, iw int) []string {
	if h.Address == "" {
		return []string{c.dim(unavailableReason(h))}
	}
	field := func(name, value string) string { return c.dim(pad(name, 9)) + value }
	lines := []string{field("Address", c.green(h.Address))}
	if as := bestASN(h.Geo); as != "" {
		lines = append(lines, field("ASN", as))
	}
	if place := bestPlace(h.Geo); place != "" {
		lines = append(lines, field("Place", place))
	}
	if h.Region != nil {
		for _, r := range h.Region.Results {
			if r.Group == region.Registry && r.Detail != "" {
				lines = append(lines, field("Route", r.Detail))
				break
			}
		}
	}
	for _, r := range h.Services {
		if r.Service == risk.PTRService && r.Status != probe.Pending {
			lines = append(lines, field("PTR", cmp.Or(r.Detail, c.dim(r.Reason))))
		}
	}
	p := h.Profile
	if p != nil && p.Registered != "" {
		reg := p.Registered
		switch {
		case p.GeoConsistent == nil:
		case *p.GeoConsistent:
			reg += "  " + c.green(m.yes+" geo-consistent")
		default:
			reg += "  " + c.yellow(m.warn+" geo-discrepant")
		}
		lines = append(lines, field("Registry", reg))
	}

	var sources []probe.Result
	nameW := 0
	for _, r := range h.factResults() {
		if r.Facts != nil {
			sources = append(sources, r)
			nameW = max(nameW, utf8.RuneCountInString(serviceName(r)))
		}
	}
	nameW = min(nameW, max(8, iw-4-factorCell*len(probe.Flags)))
	name := func(r probe.Result) string { return padVisible(serviceName(r), nameW) }

	if t := typeLines(c, sources, name, nameW); len(t) > 0 {
		lines = append(append(lines, "", sectionRule(c, m, "Type", iw)), t...)
	}
	if s := scoreLines(c, m, sources, name); len(s) > 0 {
		lines = append(append(lines, "", sectionRule(c, m, "Score", iw)), s...)
	}
	var verdict []string
	if h.Region != nil {
		verdict = h.Region.Verdict
	}
	if f := factorLines(c, m, sources, name, nameW, verdict); len(f) > 0 {
		lines = append(append(lines, "", sectionRule(c, m, "Factors", iw)), f...)
	}
	return append(lines, reputationNotes(c, m, h)...)
}

func typeLines(c paint, sources []probe.Result, name func(probe.Result) string, nameW int) []string {
	var out []string
	for _, r := range sources {
		f := r.Facts
		if f.Usage == "" && f.Company == "" {
			continue
		}
		if len(out) == 0 {
			out = append(out, c.dim(pad("", nameW)+"  "+pad("usage", badgeWidth)+" company"))
		}
		out = append(out, name(r)+" "+usageBadge(c, f.Usage)+" "+usageBadge(c, f.Company))
	}
	return out
}

func scoreLines(c paint, m marks, sources []probe.Result, name func(probe.Result) string) []string {
	var out []string
	for _, r := range sources {
		if r.Facts.Score == nil {
			continue
		}
		score := *r.Facts.Score
		level := levelOf(r.Facts)
		style := levelStyle(c, level)
		bar := style(strings.Repeat(m.barOn, level+1)) + c.dim(strings.Repeat(m.barOff, len(scoreLevels)-level-1))
		out = append(out, fmt.Sprintf("%s %3d %s %s", name(r), score, bar, style(scoreLevels[level].name)))
	}
	return out
}

func factorLines(c paint, m marks, sources []probe.Result, name func(probe.Result) string, nameW int, verdict []string) []string {
	var rows []probe.Result
	for _, r := range sources {
		if len(r.Facts.Flags) > 0 {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		return nil
	}
	cell := func(text string, style func(string) string) string {
		return strings.Repeat(" ", max(0, factorCell-utf8.RuneCountInString(text))) + style(text)
	}
	head := pad("", nameW) + "  cc"
	for _, f := range probe.Flags {
		head += fmt.Sprintf("%*s", factorCell, factorHeads[f])
	}
	out := []string{c.dim(head)}
	for _, r := range rows {
		cc := cmp.Or(r.Country, "—")
		ccStyle := c.dim
		if r.Country != "" && len(verdict) > 0 && !slices.Contains(verdict, r.Country) {
			ccStyle = c.yellow
		}
		line := name(r) + "  " + ccStyle(pad(cc, 2))
		for _, flag := range probe.Flags {
			on, ok := r.Facts.Flags[flag]
			switch {
			case !ok:
				line += cell(m.none, c.dim)
			case on:
				line += cell(m.no, c.red)
			default:
				line += cell(m.yes, c.green)
			}
		}
		out = append(out, line)
	}
	return append(out, c.dim(m.yes+" clean, "+m.no+" detected, "+m.none+" not reported"))
}

func reputationNotes(c paint, m marks, h *Host) []string {
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
	var out []string
	if len(notes) > 0 {
		out = append(append(out, ""), notes...)
	}
	if len(pending) > 0 {
		out = append(out, c.dim(m.pending+" waiting: "+strings.Join(pending, ", ")))
	}
	return out
}

func lookupLines(c paint, h *Host) []string {
	if h.Address == "" {
		return []string{c.dim(cmp.Or(h.Error, "unavailable"))}
	}
	lines := []string{c.dim(pad("Address", 9)) + c.green(h.Address)}
	if len(h.Geo) == 0 {
		return append(lines, c.dim("no local data for this address; run `cii data update`"))
	}
	srcW := 0
	for _, g := range h.Geo {
		srcW = max(srcW, utf8.RuneCountInString(g.Source))
	}
	for _, g := range h.Geo {
		var parts []string
		if g.Country != "" {
			parts = append(parts, strings.TrimSpace(g.Country+" "+cmp.Or(g.CountryName, refdata.CountryName(g.Country))))
		}
		if g.City != "" {
			parts = append(parts, g.City)
		}
		if g.ASN != 0 {
			parts = append(parts, strings.TrimSpace(fmt.Sprintf("AS%d %s", g.ASN, g.ASOrg)))
		}
		if g.Network.IsValid() {
			parts = append(parts, g.Network.String())
		}
		lines = append(lines, c.dim(pad(g.Source, srcW))+"  "+strings.Join(parts, " · "))
	}
	return lines
}
