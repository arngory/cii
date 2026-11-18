package main

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestSBOMDoc(t *testing.T) {
	out, err := sbomDoc("v1.2.3", "go1.26.0", []module{{"golang.org/x/net", "v0.62.0", "/x"}, {"gopkg.in/yaml.v3", "v3.0.1", "/y"}})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Format      string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Version     int    `json:"version"`
		Metadata    struct {
			Component struct{ Type, Name, Version, PURL string }
		}
		Components []struct {
			Type, Name, Version, PURL string
			Ref                       string `json:"bom-ref"`
		}
		Dependencies []struct {
			Ref       string
			DependsOn []string
		}
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if doc.Format != "CycloneDX" || doc.SpecVersion != "1.5" || doc.Version != 1 {
		t.Errorf("header = %+v", doc)
	}
	if c := doc.Metadata.Component; c.Type != "application" || c.Name != "cii" || c.Version != "1.2.3" || c.PURL != "pkg:golang/github.com/arngory/cii@v1.2.3" {
		t.Errorf("main component = %+v", c)
	}
	var purls, refs []string
	for _, c := range doc.Components {
		purls = append(purls, c.PURL)
		if c.Ref == "" || slices.Contains(refs, c.Ref) {
			t.Errorf("component %s has an empty or repeated bom-ref %q", c.Name, c.Ref)
		}
		refs = append(refs, c.Ref)
	}
	for _, want := range []string{"pkg:golang/stdlib@1.26.0", "pkg:golang/golang.org/x/net@v0.62.0", "pkg:golang/gopkg.in/yaml.v3@v3.0.1"} {
		if !slices.Contains(purls, want) {
			t.Errorf("%s missing from %v", want, purls)
		}
	}
	if len(doc.Components) != 5 || len(doc.Dependencies) != 1 || !slices.Equal(doc.Dependencies[0].DependsOn, refs) {
		t.Errorf("components = %d, dependencies = %+v", len(doc.Components), doc.Dependencies)
	}
}
