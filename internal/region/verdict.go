package region

import (
	"slices"
	"sort"

	"github.com/arngory/cii/internal/probe"
)

type Summary struct {
	Verdict   []string       `json:"verdict"`
	Results   []probe.Result `json:"results"`
	Attention []probe.Result `json:"attention,omitempty"`
}

var fallbackCountry = map[string]string{"YouTube": "US"}

func isFallback(r probe.Result) bool {
	return r.Group == Platform && r.Status == probe.OK && fallbackCountry[r.Service] == r.Country
}

func Summarize(results []probe.Result) Summary {
	s := Summary{Verdict: []string{}, Results: results}
	byGroup := map[probe.Group][]string{}
	for _, r := range results {
		if r.Status == probe.OK && (r.Group == GeoIP || r.Group == Platform) && !isFallback(r) {
			byGroup[r.Group] = append(byGroup[r.Group], r.Country)
		}
	}
	if len(byGroup) == 0 {
		markFallbacks(&s)
		return s
	}
	total := 1
	for _, cs := range byGroup {
		total *= len(cs)
	}
	weight := map[string]int{}
	for _, cs := range byGroup {
		for _, c := range cs {
			weight[c] += total / len(cs)
		}
	}
	top := 0
	for _, w := range weight {
		top = max(top, w)
	}
	for c, w := range weight {
		if w == top {
			s.Verdict = append(s.Verdict, c)
		}
	}
	sort.Strings(s.Verdict)
	markFallbacks(&s)
	for _, r := range s.Results {
		if r.Status == probe.OK && r.Group != CDN && !slices.Contains(s.Verdict, r.Country) {
			s.Attention = append(s.Attention, r)
		}
	}
	return s
}

func markFallbacks(s *Summary) {
	for i, r := range s.Results {
		if isFallback(r) && !slices.Contains(s.Verdict, r.Country) {
			s.Results[i].Status = probe.Unknown
			s.Results[i].Reason = "service default " + r.Country + ": country not in its list"
		}
	}
}
