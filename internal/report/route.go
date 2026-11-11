package report

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/arngory/cii/internal/route"
)

func routeLines(c paint, m marks, r *route.Report, iw int) []string {
	var lines []string
	head := m.tr("method") + " " + r.Method
	if r.FloorMs > 0 {
		head += fmt.Sprintf(" · %s %.1f ms", m.tr("fastest"), r.FloorMs)
	}
	lines = append(lines, c.dim(head))
	if r.Note != "" {
		lines = append(lines, c.dim(r.Note))
	}
	return append(lines, bufferLines(func(b *bytes.Buffer) {
		writeGrid2(b, c, m, iw, []column{newColumn("", r.Results())}, [][]string{nil})
	})...)
}

func writeRouteDetailed(w io.Writer, c paint, r *route.Report) {
	fmt.Fprintf(w, "%s method %s, fastest %.1f ms\n", c.bold("Routes"), r.Method, r.FloorMs)
	if r.Note != "" {
		fmt.Fprintf(w, "  %s\n", c.dim(r.Note))
	}
	for _, p := range r.Paths {
		rtt := "—"
		if p.RTTms > 0 {
			rtt = fmt.Sprintf("%.1f ms (%s)", p.RTTms, p.Timing)
		}
		dest := p.Addr
		if p.ASN != 0 {
			dest += fmt.Sprintf(" AS%d %s", p.ASN, p.Org)
		}
		fmt.Fprintf(w, "  %-18s %-12s %-16s %s\n", p.Target.Name, p.Verdict, rtt, strings.TrimSpace(dest))
		if p.Reason != "" {
			fmt.Fprintf(w, "  %-18s %s\n", "", c.dim(p.Reason))
		}
		for _, h := range p.Hops {
			if h.Addr == "" {
				fmt.Fprintf(w, "  %-18s %2d  *\n", "", h.TTL)
				continue
			}
			as := ""
			if h.ASN != 0 {
				as = fmt.Sprintf("AS%d %s", h.ASN, h.Org)
			}
			fmt.Fprintf(w, "  %-18s %2d  %-39s %7.1f ms  %s\n", "", h.TTL, h.Addr, h.RTTms, c.dim(as))
		}
	}
	fmt.Fprintln(w)
}
