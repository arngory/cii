package report

import (
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/arngory/cii/internal/refdata"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/risk"
	"github.com/arngory/cii/internal/route"
)

const Hidden = "•••"

var (
	addrLike   = regexp.MustCompile(`[0-9A-Fa-f:.]*[.:][0-9A-Fa-f:.]*(?:/\d{1,3})?`)
	asnLike    = regexp.MustCompile(`(?i)\bAS[ -]?\d{1,10}\b`)
	asnPrefix  = regexp.MustCompile(`^AS\d+\s*`)
	legacyMask = regexp.MustCompile(`(?i)\b(?:\d{1,3}\.\d{1,3}\.\*\.\*|[0-9a-f]{1,4}:[0-9a-f]{1,4}:\*:\*)`)
	nibbleLike = regexp.MustCompile(`(?i)\b(?:[0-9a-f]\.){8,}(?:ip6\.arpa\b)?`)
	namedNotes = regexp.MustCompile(`\b(VPN) \([^()]+\)|\b(datacenter) [^;,]+`)
	addrType   = reflect.TypeFor[netip.Addr]()
	prefixType = reflect.TypeFor[netip.Prefix]()
	orgFields  = []string{"ASOrg", "ASDomain", "Org", "Node"}
	asnFields  = []string{"ASN", "OwnASN"}
	freeText   = []string{"Detail", "Reason", "Error", "Notes", "Note", "Transit"}
	addrText   = []string{"Address", "Interface", "Query", "Via", "Disagree", "Addr"}
	genericOrg = map[string]bool{
		"limited": true, "company": true, "corporation": true, "online": true, "internet": true,
		"network": true, "networks": true, "telecom": true, "telecommunications": true,
		"communications": true, "services": true, "service": true, "hosting": true, "cloud": true,
		"data": true, "center": true, "centre": true, "group": true, "holding": true, "holdings": true,
		"global": true, "international": true, "technologies": true, "technology": true,
		"solutions": true, "systems": true, "broadband": true, "mobile": true, "provider": true,
		"gmbh": true, "llc": true, "ltd": true, "inc": true, "corp": true, "s.a.": true,
		"cable": true, "dsl": true, "isp": true, "nsp": true, "content": true, "enterprise": true,
		"educational": true, "research": true, "government": true, "non-profit": true, "route": true, "server": true,
	}
)

func MaskText(s string) string {
	s = nibbleLike.ReplaceAllString(s, Hidden)
	s = legacyMask.ReplaceAllString(s, Hidden)
	s = addrLike.ReplaceAllStringFunc(s, func(tok string) string {
		for _, cand := range []string{tok, trimEdge(tok)} {
			if isAddress(cand) {
				return strings.Replace(tok, cand, Hidden, 1)
			}
		}
		return tok
	})
	return asnLike.ReplaceAllString(s, Hidden)
}

func isAddress(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, err := netip.ParseAddrPort(s); err == nil {
		return true
	}
	_, err := netip.ParsePrefix(s)
	return err == nil
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

func (r *Report) Scrubbed() *Report {
	sc := newScrubber(orgNames(r))
	out := sc.copy(reflect.ValueOf(r), keepText).Interface().(*Report)
	out.Masked = true
	for _, h := range out.hosts() {
		if h.Region != nil {
			for i := range h.Region.Results {
				if h.Region.Results[i].Group == region.Registry {
					h.Region.Results[i].Detail = ""
				}
			}
		}
		for i := range h.Services {
			if h.Services[i].Service == risk.PTRService && h.Services[i].Detail != "" {
				h.Services[i].Detail = Hidden
			}
		}
	}
	if out.Route != nil {
		var own []string
		n := 0
		for i := range out.Route.Paths {
			path := &out.Route.Paths[i]
			t := &path.Target
			if t.Group != route.Custom {
				continue
			}
			n++
			own = append(own, t.Host)
			if t.Name == t.Host {
				t.Name = fmt.Sprintf("target %d", n)
			}
			path.Reason = sc.text(strings.ReplaceAll(r.Route.Paths[i].Reason, t.Host, Hidden), answerText)
			path.Error = sc.text(strings.ReplaceAll(r.Route.Paths[i].Error, t.Host, Hidden), answerText)
			t.Host, t.Expect = Hidden, 0
		}
		slices.SortFunc(own, func(a, b string) int { return len(b) - len(a) })
		for i := range out.Network {
			for _, host := range own {
				if out.Network[i].Host == host {
					out.Network[i].Host = Hidden
				}
				out.Network[i].Purpose = strings.ReplaceAll(out.Network[i].Purpose, host, Hidden)
			}
		}
	}
	return out
}

func (r *Report) hosts() []*Host {
	var hs []*Host
	for _, h := range append(append([]*Host{r.IPv4, r.IPv6}, r.Results...), r.Exits...) {
		if h != nil {
			hs = append(hs, h)
		}
	}
	return hs
}

func orgNames(r *Report) []string {
	seen, geo := map[string]bool{}, map[string]bool{}
	for _, h := range r.hosts() {
		for _, g := range h.Geo {
			for _, place := range []string{g.Country, g.CountryName, refdata.CountryName(g.Country), g.Region, g.City} {
				for _, w := range strings.Fields(strings.ToLower(place)) {
					geo[w] = true
				}
			}
		}
	}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if len([]rune(s)) >= 3 && !genericOrg[strings.ToLower(s)] && !geo[strings.ToLower(s)] {
			seen[s] = true
		}
	}
	addOrg := func(org string) {
		add(org)
		for _, w := range strings.FieldsFunc(org, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' }) {
			if len([]rune(w)) >= 4 {
				add(w)
			}
		}
	}
	for _, h := range r.hosts() {
		for _, g := range h.Geo {
			addOrg(g.ASOrg)
			addOrg(strings.SplitN(g.ASDomain, ".", 2)[0])
		}
	}
	if r.Route != nil {
		for _, p := range r.Route.Paths {
			for _, t := range p.Transit {
				addOrg(asnPrefix.ReplaceAllString(t, ""))
			}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	slices.SortFunc(names, func(a, b string) int { return len(b) - len(a) })
	return names
}

type scrubber struct{ names *regexp.Regexp }

func newScrubber(names []string) scrubber {
	if len(names) == 0 {
		return scrubber{}
	}
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = regexp.QuoteMeta(n)
	}
	return scrubber{names: regexp.MustCompile(`(?i)(^|[^\pL\pN])(?:` + strings.Join(quoted, "|") + `)($|[^\pL\pN])`)}
}

type textKind int

const (
	keepText textKind = iota
	addressText
	answerText
)

func kindOf(field string) textKind {
	switch {
	case slices.Contains(freeText, field):
		return answerText
	case slices.Contains(addrText, field):
		return addressText
	}
	return keepText
}

func (s scrubber) text(v string, kind textKind) string {
	switch kind {
	case keepText:
		return v
	case addressText:
		return MaskText(v)
	}
	v = namedNotes.ReplaceAllString(MaskText(v), "$1$2")
	if s.names == nil {
		return v
	}
	for {
		next := s.names.ReplaceAllString(v, "${1}"+Hidden+"${2}")
		if next == v {
			return v
		}
		v = next
	}
}

func (s scrubber) copy(v reflect.Value, kind textKind) reflect.Value {
	switch {
	case v.Type() == addrType || v.Type() == prefixType:
		return reflect.Zero(v.Type())
	}
	switch v.Kind() {
	case reflect.String:
		out := reflect.New(v.Type()).Elem()
		out.SetString(s.text(v.String(), kind))
		return out
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(s.copy(v.Elem(), kind))
		return out
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := range v.Len() {
			out.Index(i).Set(s.copy(v.Index(i), kind))
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		for it := v.MapRange(); it.Next(); {
			out.SetMapIndex(s.copy(it.Key(), kind), s.copy(it.Value(), kind))
		}
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		for i := range v.NumField() {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			switch {
			case slices.Contains(asnFields, f.Name) && f.Type.Kind() == reflect.Uint:
				out.Field(i).SetUint(0)
			case slices.Contains(orgFields, f.Name) && f.Type.Kind() == reflect.String:
				out.Field(i).SetString("")
			default:
				out.Field(i).Set(s.copy(v.Field(i), kindOf(f.Name)))
			}
		}
		return out
	}
	return v
}
