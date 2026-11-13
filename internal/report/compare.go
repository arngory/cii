package report

import (
	"fmt"
	"slices"
)

func (r *Report) primary() *Host {
	for _, h := range r.hosts() {
		if h.Address != "" {
			return h
		}
	}
	return nil
}

func Compare(reps []*Report, names []string) (*Report, error) {
	out := New("compare")
	for i, r := range reps {
		h := r.primary()
		if h == nil {
			return nil, fmt.Errorf("%s: the report has no address to compare", names[i])
		}
		point := *h
		point.Query = string(rune('A' + i))
		point.Via = names[i] + " · " + r.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC")
		out.Exits = append(out.Exits, &point)
		for _, d := range r.Data {
			if !slices.ContainsFunc(out.Data, func(x DataInfo) bool { return x.ID == d.ID }) {
				out.Data = append(out.Data, d)
			}
		}
		for _, a := range r.Attribution {
			if !slices.Contains(out.Attribution, a) {
				out.Attribution = append(out.Attribution, a)
			}
		}
	}
	return out, nil
}
