package main

import (
	"encoding/json"
	"os"
	"strings"
)

const mainModule = "github.com/arngory/cii"

type bomLicense struct {
	License struct {
		ID string `json:"id"`
	} `json:"license"`
}

type bomComponent struct {
	Type     string       `json:"type"`
	Ref      string       `json:"bom-ref"`
	Name     string       `json:"name"`
	Version  string       `json:"version,omitempty"`
	PURL     string       `json:"purl,omitempty"`
	Licenses []bomLicense `json:"licenses,omitempty"`
}

type bomDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type bom struct {
	Format      string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Version     int    `json:"version"`
	Metadata    struct {
		Component bomComponent `json:"component"`
	} `json:"metadata"`
	Components   []bomComponent  `json:"components"`
	Dependencies []bomDependency `json:"dependencies"`
}

func licensed(id string) []bomLicense {
	var l bomLicense
	l.License.ID = id
	return []bomLicense{l}
}

func sbomDoc(version, goVersion string, mods []module) ([]byte, error) {
	doc := bom{Format: "CycloneDX", SpecVersion: "1.5", Version: 1}
	root := "pkg:golang/" + mainModule + "@" + version
	doc.Metadata.Component = bomComponent{Type: "application", Ref: root, Name: "cii", Version: strings.TrimPrefix(version, "v"), PURL: root, Licenses: licensed("AGPL-3.0-only")}
	std := "pkg:golang/stdlib@" + strings.TrimPrefix(goVersion, "go")
	doc.Components = append(doc.Components, bomComponent{Type: "library", Ref: std, Name: "stdlib", Version: goVersion, PURL: std, Licenses: licensed("BSD-3-Clause")})
	for _, m := range mods {
		purl := "pkg:golang/" + m.path + "@" + m.version
		doc.Components = append(doc.Components, bomComponent{Type: "library", Ref: purl, Name: m.path, Version: m.version, PURL: purl})
	}
	doc.Components = append(doc.Components,
		bomComponent{Type: "data", Ref: "data:unicode-cldr-territories", Name: "Unicode CLDR territory names", Licenses: licensed("Unicode-3.0")},
		bomComponent{Type: "data", Ref: "data:ourairports-iata", Name: "OurAirports airport codes"})
	deps := bomDependency{Ref: root, DependsOn: []string{}}
	for _, c := range doc.Components {
		deps.DependsOn = append(deps.DependsOn, c.Ref)
	}
	doc.Dependencies = []bomDependency{deps}
	out, err := json.MarshalIndent(doc, "", "  ")
	return append(out, '\n'), err
}

func sbom(version, out string) error {
	goVersion, err := goOut(nil, "env", "GOVERSION")
	if err != nil {
		return err
	}
	mods, err := modules()
	if err != nil {
		return err
	}
	doc, err := sbomDoc(version, goVersion, mods)
	if err != nil {
		return err
	}
	return os.WriteFile(out, doc, 0o644)
}
