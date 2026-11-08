package netx

import (
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
)

type Rule struct {
	Module  string `json:"module"`
	Pattern string `json:"host"`
	Purpose string `json:"purpose"`
}

func (r Rule) matches(host string) bool {
	if suffix, ok := strings.CutPrefix(r.Pattern, "*."); ok {
		return strings.HasSuffix(host, "."+suffix)
	}
	return host == r.Pattern
}

type Policy struct {
	rules []Rule
}

func NewPolicy(rules ...Rule) *Policy {
	p := &Policy{}
	p.Add(rules...)
	return p
}

func (p *Policy) Add(rules ...Rule) {
	for _, r := range rules {
		r.Pattern = strings.ToLower(strings.TrimSpace(r.Pattern))
		if r.Pattern == "" {
			continue
		}
		if i := p.index(r); i >= 0 {
			p.rules[i].Purpose = mergePurpose(p.rules[i].Purpose, r.Purpose)
			continue
		}
		p.rules = append(p.rules, r)
	}
}

func mergePurpose(have, add string) string {
	switch {
	case add == "":
		return have
	case have == "":
		return add
	case slices.Contains(strings.Split(have, "; "), add):
		return have
	}
	return have + "; " + add
}

func (p *Policy) index(r Rule) int {
	for i, x := range p.rules {
		if x.Module == r.Module && x.Pattern == r.Pattern {
			return i
		}
	}
	return -1
}

func (p *Policy) Match(module, host string) (Rule, bool) {
	host = normalizeHost(host)
	for _, r := range p.rules {
		if r.Module == module && r.matches(host) {
			return r, true
		}
	}
	return Rule{}, false
}

func (p *Policy) Rules() []Rule {
	out := append([]Rule(nil), p.rules...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].Pattern < out[j].Pattern
	})
	return out
}

func normalizeHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	return strings.Trim(h, "[]")
}

type BlockedError struct {
	Module string
	Host   string
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("network policy: module %q is not allowed to contact %q", e.Module, e.Host)
}
