package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/arngory/cii/internal/bench"
	"github.com/arngory/cii/internal/geodb"
	"github.com/arngory/cii/internal/ipdetect"
	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/version"
)

const Schema = "cii.report/v1"

type Report struct {
	Schema      string         `json:"schema"`
	Tool        Tool           `json:"tool"`
	GeneratedAt time.Time      `json:"generated_at"`
	Mode        string         `json:"mode"`
	IPv4        *Host          `json:"ipv4"`
	IPv6        *Host          `json:"ipv6"`
	Results     []*Host        `json:"results,omitempty"`
	Exits       []*Host        `json:"exits,omitempty"`
	Censor      []probe.Result `json:"censor,omitempty"`
	Bench       *bench.Report  `json:"bench,omitempty"`
	Data        []DataInfo     `json:"data"`
	Attribution []string       `json:"attribution,omitempty"`
	Network     []ledger.Entry `json:"network"`
	Masked      bool           `json:"masked"`
}

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Host struct {
	Query     string          `json:"query,omitempty"`
	Address   string          `json:"address,omitempty"`
	Source    string          `json:"source,omitempty"`
	Via       string          `json:"via,omitempty"`
	Interface []string        `json:"interface,omitempty"`
	Error     string          `json:"error,omitempty"`
	Geo       []geodb.Record  `json:"geo,omitempty"`
	Region    *region.Summary `json:"region,omitempty"`
	Services  []probe.Result  `json:"services,omitempty"`
	Profile   *Profile        `json:"profile,omitempty"`
}

type DataInfo struct {
	ID    string    `json:"id"`
	Type  string    `json:"type"`
	Built time.Time `json:"built"`
}

func New(mode string, mask bool) *Report {
	return &Report{
		Schema:      Schema,
		Tool:        Tool{Name: version.Name, Version: version.Version},
		GeneratedAt: time.Now().UTC().Truncate(time.Second),
		Mode:        mode,
		Masked:      mask,
		Data:        []DataInfo{},
		Network:     []ledger.Entry{},
	}
}

func NewHost(a ipdetect.Address, geo []geodb.Record, mask bool) *Host {
	h := &Host{Source: a.Source, Error: a.Error, Geo: geo}
	if mask {
		h.Error = MaskText(a.Error)
	}
	if a.Address.IsValid() {
		h.Address = MaskAddr(a.Address, mask)
	}
	for _, i := range a.Interface {
		h.Interface = append(h.Interface, MaskAddr(i, mask))
	}
	if mask {
		for i := range h.Geo {
			h.Geo[i].Network = netip.Prefix{}
		}
	}
	return h
}

func (r *Report) SetData(s *geodb.Set) {
	for _, d := range s.DBs {
		r.Data = append(r.Data, DataInfo{ID: d.ID, Type: d.Type, Built: time.Unix(d.Built, 0).UTC()})
	}
	r.Attribution = s.Attribution()
}

func MaskAddr(a netip.Addr, mask bool) string {
	if !mask {
		return a.String()
	}
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.*.*", b[0], b[1])
	}
	b := a.As16()
	return fmt.Sprintf("%x:%x:*:*", uint16(b[0])<<8|uint16(b[1]), uint16(b[2])<<8|uint16(b[3]))
}

var addrLike = regexp.MustCompile(`[0-9A-Fa-f:.]*[.:][0-9A-Fa-f:.]*`)

func MaskText(s string) string {
	return addrLike.ReplaceAllStringFunc(s, func(tok string) string {
		for _, cand := range []string{tok, trimEdge(tok)} {
			if a, err := netip.ParseAddr(cand); err == nil {
				return strings.Replace(tok, cand, MaskAddr(a.Unmap(), true), 1)
			}
			if ap, err := netip.ParseAddrPort(cand); err == nil {
				return strings.Replace(tok, cand, MaskAddr(ap.Addr().Unmap(), true), 1)
			}
		}
		return tok
	})
}

func trimEdge(s string) string {
	s = strings.TrimSuffix(s, ".")
	if strings.HasSuffix(s, ":") && !strings.HasSuffix(s, "::") {
		s = s[:len(s)-1]
	}
	if strings.HasPrefix(s, ":") && !strings.HasPrefix(s, "::") {
		s = s[1:]
	}
	return s
}

func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func (r *Report) WriteDetailed(w io.Writer, color bool) {
	c := paint(color)
	fmt.Fprintf(w, "%s %s — complete information about current IP\n\n", c.bold(r.Tool.Name), r.Tool.Version)

	if r.IPv4 != nil {
		writeHost(w, c, "IPv4", r.IPv4)
	}
	if r.IPv6 != nil {
		writeHost(w, c, "IPv6", r.IPv6)
	}
	for _, h := range r.Results {
		writeHost(w, c, "IP", h)
	}
	writeProbes(w, c, []labeled{{"IPv4", r.IPv4}, {"IPv6", r.IPv6}})
	if len(r.Censor) > 0 {
		cols := []column{newColumn("result", r.Censor)}
		writeTable(w, c, "Censorship", cols, sectionsOf(cols), nil)
		fmt.Fprintln(w)
	}
	if r.Bench != nil {
		writeBenchDetailed(w, c, r.Bench)
	}

	if len(r.Data) > 0 {
		fmt.Fprintln(w, c.bold("Local data"))
		for _, d := range r.Data {
			fmt.Fprintf(w, "  %-20s %s, built %s\n", d.ID, d.Type, d.Built.Format("2006-01-02"))
		}
		for _, a := range r.Attribution {
			fmt.Fprintf(w, "  %s\n", c.dim(a))
		}
		fmt.Fprintln(w)
	} else if r.Mode != "censor" && r.Mode != "bench" {
		fmt.Fprintf(w, "%s no local databases; run `cii data update` to fetch DB-IP Lite\n\n", c.yellow("note:"))
	}

	writeLedger(w, c, r.Network)
}

func writeHost(w io.Writer, c paint, label string, h *Host) {
	if h.Address == "" {
		fmt.Fprintf(w, "%s  %s  %s\n\n", c.bold(label), c.dim("—"), c.dim(h.Error))
		return
	}
	fmt.Fprintf(w, "%s  %s  %s\n", c.bold(label), c.green(h.Address), c.dim("("+h.Source+")"))
	if len(h.Interface) > 0 && (len(h.Interface) > 1 || h.Interface[0] != h.Address) {
		fmt.Fprintf(w, "      on interfaces: %s\n", strings.Join(h.Interface, ", "))
	}
	if len(h.Geo) > 0 {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, g := range h.Geo {
			fmt.Fprintf(tw, "      %s\t%s\t%s\t%s\n", g.Source, place(g), asn(g), netStr(g.Network))
		}
		tw.Flush()
	}
	fmt.Fprintln(w)
}

func WriteContacts(w io.Writer, color bool, entries []ledger.Entry) {
	writeLedger(w, paint(color), entries)
}

func writeLedger(w io.Writer, c paint, entries []ledger.Entry) {
	if len(entries) == 0 {
		fmt.Fprintf(w, "%s none — nothing left this machine\n", c.bold("Network contacts:"))
		return
	}
	fmt.Fprintf(w, "%s %d destination(s)\n", c.bold("Network contacts:"), len(entries))
	var rows [][]gcell
	for _, e := range entries {
		status := gcell{text: fmt.Sprintf("%d req", e.Requests)}
		if e.Errors > 0 {
			status.text += fmt.Sprintf(", %d failed", e.Errors)
		}
		if e.Skipped > 0 {
			status.text += fmt.Sprintf(", %d skipped (proxy)", e.Skipped)
		}
		if e.Blocked > 0 {
			status.text += fmt.Sprintf(", %d BLOCKED", e.Blocked)
			status.style = c.red
		}
		rows = append(rows, []gcell{plain("  " + e.Module), plain(e.Host), plain(e.Proto), status, {text: e.Purpose, style: c.dim}})
	}
	writeGrid(w, rows)
}

func WritePlan(w io.Writer, color bool, rules []netx.Rule) {
	c := paint(color)
	fmt.Fprintf(w, "%s the following destinations may be contacted (nothing has been sent):\n", c.bold("Plan:"))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, r := range rules {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", r.Module, r.Pattern, c.dim(r.Purpose))
	}
	tw.Flush()
	fmt.Fprintln(w, "Any other destination is refused by the network policy.")
}

func place(g geodb.Record) string {
	var parts []string
	if g.Country != "" {
		cc := g.Country
		if g.CountryName != "" {
			cc += " " + g.CountryName
		}
		parts = append(parts, cc)
	}
	if g.Region != "" {
		parts = append(parts, g.Region)
	}
	if g.City != "" {
		parts = append(parts, g.City)
	}
	if g.RegisteredCountry != "" && g.RegisteredCountry != g.Country {
		parts = append(parts, "registered: "+g.RegisteredCountry)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

func asn(g geodb.Record) string {
	if g.ASN == 0 && g.ASOrg == "" {
		return "-"
	}
	return strings.TrimSpace(fmt.Sprintf("AS%d %s", g.ASN, g.ASOrg))
}

func netStr(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	return p.String()
}

func ColorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

type paint bool

func (p paint) wrap(code, s string) string {
	if !p || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
func (p paint) bold(s string) string   { return p.wrap("1", s) }
func (p paint) dim(s string) string    { return p.wrap("2", s) }
func (p paint) green(s string) string  { return p.wrap("32", s) }
func (p paint) yellow(s string) string { return p.wrap("33", s) }
func (p paint) red(s string) string    { return p.wrap("31", s) }

func (p paint) badge(code, s string) string {
	if !p {
		return "[" + s + "]"
	}
	return "\x1b[" + code + "m " + s + " \x1b[0m"
}
