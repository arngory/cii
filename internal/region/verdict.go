package region

import (
	"slices"
	"sort"
)

type Summary struct {
	Verdict   []string `json:"verdict"`
	Results   []Result `json:"results"`
	Attention []Result `json:"attention,omitempty"`
}

func Summarize(results []Result) Summary {
	s := Summary{Verdict: []string{}, Results: results}
	byGroup := map[Group][]string{}
	for _, r := range results {
		if r.Status == OK && (r.Group == GeoIP || r.Group == Platform) {
			byGroup[r.Group] = append(byGroup[r.Group], r.Country)
		}
	}
	if len(byGroup) == 0 {
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
	for _, r := range results {
		if r.Status == OK && r.Group != CDN && !slices.Contains(s.Verdict, r.Country) {
			s.Attention = append(s.Attention, r)
		}
	}
	return s
}
