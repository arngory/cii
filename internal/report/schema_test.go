package report

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestSchemaFileIsCurrent(t *testing.T) {
	want, err := JSONSchema()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../../schema/report.schema.json")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("schema/report.schema.json is out of date: run `make schema` (%v)", err)
	}
	var doc struct {
		Defs map[string]struct {
			Properties map[string]any `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(want, &doc); err != nil {
		t.Fatal(err)
	}
	for def, field := range map[string]string{"Report": "exits", "Host": "profile", "ProbeResult": "facts", "ProbeFacts": "level", "Profile": "geo_consistent", "LedgerEntry": "requests", "BenchReport": "speed"} {
		if _, ok := doc.Defs[def].Properties[field]; !ok {
			t.Errorf("%s.%s missing from the schema", def, field)
		}
	}
}
