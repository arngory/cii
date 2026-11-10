package report

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/arngory/cii/internal/probe"
)

type Change struct {
	Section string `json:"section"`
	Item    string `json:"item"`
	Before  string `json:"before"`
	After   string `json:"after"`
}

func Diff(a, b *Report) []Change {
	var out []Change
	add := func(section, item, before, after string) {
		if before != after {
			out = append(out, Change{section, item, cmpDash(before), cmpDash(after)})
		}
	}
	families := []string{"IPv4", "IPv6"}
	for _, r := range []*Report{a, b} {
		for _, h := range r.Exits {
			if !slices.Contains(families, h.Query) {
				families = append(families, h.Query)
			}
		}
	}
	for _, fam := range families {
		ha, hb := a.host(fam), b.host(fam)
		add(fam, "address", ha.Address, hb.Address)
		add(fam, "verdict", strings.Join(ha.verdict(), "/"), strings.Join(hb.verdict(), "/"))
		add(fam, "registry", ha.profile().Registered, hb.profile().Registered)
		diffResults(add, fam+" region", ha.regionResults(), hb.regionResults())
		diffResults(add, fam+" services", ha.services(), hb.services())
		fa, fb := ha.profile().factorMap(), hb.profile().factorMap()
		for _, f := range probe.Flags {
			add(fam+" factors", flagTitles[f], fa[f], fb[f])
		}
		sa, sb := ha.profile().scoreMap(), hb.profile().scoreMap()
		for _, src := range unionKeys(sa, sb) {
			add(fam+" scores", src, sa[src], sb[src])
		}
	}
	diffResults(add, "Censorship", a.Censor, b.Censor)
	add("Benchmark", "Cloudflare download", a.speed(true), b.speed(true))
	add("Benchmark", "Cloudflare upload", a.speed(false), b.speed(false))
	return out
}

func cmpDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func (r *Report) host(fam string) *Host {
	if fam == "IPv4" && r.IPv4 != nil {
		return r.IPv4
	}
	if fam == "IPv6" && r.IPv6 != nil {
		return r.IPv6
	}
	for _, h := range r.Exits {
		if h.Query == fam {
			return h
		}
	}
	return &Host{}
}

func (h *Host) verdict() []string {
	if h.Region == nil {
		return nil
	}
	return h.Region.Verdict
}

func (h *Host) regionResults() []probe.Result {
	if h.Region == nil {
		return nil
	}
	return h.Region.Results
}

func (h *Host) services() []probe.Result { return h.Services }

func (h *Host) profile() *Profile {
	if h.Profile == nil {
		return &Profile{}
	}
	return h.Profile
}

func (p *Profile) factorMap() map[probe.Flag]string {
	out := map[probe.Flag]string{}
	for _, f := range p.Factors {
		text := fmt.Sprintf("%d/%d", len(f.Hits), f.Checked)
		if len(f.Hits) > 0 {
			text += " " + strings.Join(f.Hits, ", ")
		}
		out[f.Flag] = text
	}
	return out
}

func (p *Profile) scoreMap() map[string]string {
	out := map[string]string{}
	for _, s := range p.Scores {
		out[s.Source] = strconv.Itoa(s.Score)
	}
	return out
}

func (r *Report) speed(down bool) string {
	if r.Bench == nil || r.Bench.Speed == nil {
		return ""
	}
	v := r.Bench.Speed.UpMbps
	if down {
		v = r.Bench.Speed.DownMbps
	}
	return fmt.Sprintf("%.1f Mbit/s", v)
}

func resultText(r probe.Result) string {
	return strings.TrimSpace(string(r.Status) + " " + r.Country + " " + r.IATA)
}

func diffResults(add func(section, item, before, after string), section string, a, b []probe.Result) {
	before, after := map[string]string{}, map[string]string{}
	var order []string
	for _, rs := range []struct {
		list []probe.Result
		into map[string]string
	}{{a, before}, {b, after}} {
		for _, r := range rs.list {
			k := groupTitle(r.Group) + ": " + serviceName(r)
			if _, seen := rs.into[k]; !seen {
				rs.into[k] = resultText(r)
			}
			if !slices.Contains(order, k) {
				order = append(order, k)
			}
		}
	}
	for _, k := range order {
		add(section, k, before[k], after[k])
	}
}

func unionKeys(a, b map[string]string) []string {
	var out []string
	for _, m := range []map[string]string{a, b} {
		for k := range m {
			if !slices.Contains(out, k) {
				out = append(out, k)
			}
		}
	}
	slices.Sort(out)
	return out
}

func WriteDiff(w io.Writer, color bool, nameA, nameB string, changes []Change) {
	c := paint(color)
	fmt.Fprintf(w, "%s %s %s %s\n", c.bold("cii diff"), c.dim(nameA), c.dim("→"), c.dim(nameB))
	if len(changes) == 0 {
		fmt.Fprintln(w, c.green("no changes"))
		return
	}
	section := ""
	rows := [][]gcell{}
	flush := func() {
		if len(rows) > 0 {
			writeGrid(w, rows)
			rows = nil
		}
	}
	for _, ch := range changes {
		if ch.Section != section {
			flush()
			section = ch.Section
			fmt.Fprintln(w)
			fmt.Fprintln(w, c.bold(section))
		}
		rows = append(rows, []gcell{plain("  " + ch.Item), {text: ch.Before, style: c.dim}, plain("→"), {text: ch.After, style: c.yellow}})
	}
	flush()
}
