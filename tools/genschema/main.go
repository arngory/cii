package main

import (
	"fmt"
	"os"

	"github.com/arngory/cii/internal/report"
)

func main() {
	out, err := report.JSONSchema()
	if err == nil {
		err = os.WriteFile("schema/report.schema.json", out, 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "genschema:", err)
		os.Exit(1)
	}
}
