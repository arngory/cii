package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/arngory/cii/internal/refdata"
	"github.com/arngory/cii/internal/region"
)

func (h *Host) SetRegion(s region.Summary, mask bool) {
	if mask {
		for _, list := range [][]region.Result{s.Results, s.Attention} {
			for i := range list {
				list[i].Reason = MaskText(list[i].Reason)
			}
		}
	}
	h.Region = &s
}

var groupTitles = []struct {
	group region.Group
	title string
}{{region.GeoIP, "GeoIP"}, {region.Platform, "Platforms"}, {region.CDN, "CDN"}}

type regionColumn struct {
	label string
	byKey map[string]region.Result
	sum   *region.Summary
}

func writeRegion(w io.Writer, c paint, hosts []*Host, labels []string) {
	var cols []regionColumn
	for i, h := range hosts {
		if h == nil || h.Region == nil {
			continue
		}
		col := regionColumn{label: labels[i], byKey: map[string]region.Result{}, sum: h.Region}
		for _, r := range h.Region.Results {
			col.byKey[string(r.Group)+"\x00"+r.Service] = r
		}
		cols = append(cols, col)
	}
	if len(cols) == 0 {
		return
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	header := []string{c.bold("Region")}
	verdict := []string{"  verdict"}
	for _, col := range cols {
		header = append(header, c.bold(col.label))
		verdict = append(verdict, verdictCell(c, col.sum.Verdict))
	}
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	fmt.Fprintln(tw, strings.Join(verdict, "\t"))

	for _, g := range groupTitles {
		services := servicesOf(cols, g.group)
		if len(services) == 0 {
			continue
		}
		fmt.Fprintln(tw, c.dim(g.title)+strings.Repeat("\t", len(cols)))
		for _, svc := range services {
			row := []string{"  " + svc}
			for _, col := range cols {
				r, ok := col.byKey[string(g.group)+"\x00"+svc]
				row = append(row, cell(c, r, ok))
			}
			fmt.Fprintln(tw, strings.Join(row, "\t"))
		}
	}
	tw.Flush()

	var notes []string
	for _, col := range cols {
		for _, r := range col.sum.Attention {
			notes = append(notes, fmt.Sprintf("  %s (%s) says %s", r.Service, col.label, r.Country))
		}
	}
	if len(notes) > 0 {
		fmt.Fprintln(w, c.yellow("Disagrees with the verdict"))
		fmt.Fprintln(w, strings.Join(notes, "\n"))
	}
	var fails []string
	for _, col := range cols {
		for _, r := range col.sum.Results {
			if r.Status == region.Failed {
				fails = append(fails, fmt.Sprintf("  %s (%s): %s", r.Service, col.label, r.Reason))
			}
		}
	}
	if len(fails) > 0 {
		fmt.Fprintln(w, c.dim("Failed checks"))
		fmt.Fprintln(w, c.dim(strings.Join(fails, "\n")))
	}
	fmt.Fprintln(w)
}

func servicesOf(cols []regionColumn, g region.Group) []string {
	seen := map[string]bool{}
	var out []string
	for _, col := range cols {
		for _, r := range col.sum.Results {
			if r.Group == g && !seen[r.Service] {
				seen[r.Service] = true
				out = append(out, r.Service)
			}
		}
	}
	return out
}

func verdictCell(c paint, verdict []string) string {
	if len(verdict) == 0 {
		return c.dim("?")
	}
	s := strings.Join(verdict, "/")
	if len(verdict) == 1 {
		if name := refdata.CountryName(verdict[0]); name != "" {
			s += " " + name
		}
	}
	return c.green(s)
}

func cell(c paint, r region.Result, ok bool) string {
	if !ok {
		return c.dim("—")
	}
	switch r.Status {
	case region.OK:
		if r.IATA != "" {
			return r.Country + " " + c.dim(r.IATA)
		}
		return r.Country
	case region.IPBlock:
		return c.red("blocked")
	case region.Failed:
		return c.dim("error")
	}
	return c.dim("?")
}
