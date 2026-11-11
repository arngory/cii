package services

import (
	"slices"
	"testing"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/probe"
)

func TestCatalogs(t *testing.T) {
	if got := CatalogsFor("jp"); !slices.Equal(got, []string{"JP"}) {
		t.Errorf("CatalogsFor(jp) = %v", got)
	}
	if got := CatalogsFor("XX"); len(got) != 0 {
		t.Errorf("CatalogsFor(XX) = %v", got)
	}
	seen := map[string]string{}
	for _, c := range Catalogs {
		for _, cc := range c.Countries {
			if prev, dup := seen[cc]; dup {
				t.Errorf("%s in both %s and %s", cc, prev, c.Code)
			}
			seen[cc] = c.Code
		}
		for _, ch := range c.checks {
			if ch.Group != probe.Group(c.Code) || ch.Eval == nil || len(ch.Requests) == 0 {
				t.Errorf("%s/%s: malformed check", c.Code, ch.Service)
			}
		}
	}
	if Title("JP") != "Japan" || Title("ai") != "" {
		t.Error("Title mismatch")
	}
	if got := SelectRegional([]string{"zz"}, config.Keys{}, true); len(got) != 0 {
		t.Errorf("unknown catalog selected %d checks", len(got))
	}
	for _, c := range Catalogs {
		seen := map[string]bool{}
		for _, ch := range c.checks {
			if seen[ch.Service] {
				t.Errorf("%s: duplicate service %q", c.Code, ch.Service)
			}
			seen[ch.Service] = true
		}
	}
}
