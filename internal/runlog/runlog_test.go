package runlog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteAndPrune(t *testing.T) {
	dir := t.TempDir()
	foreign := filepath.Join(dir, "other.log")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	var first string
	for i := 0; i < Keep+3; i++ {
		p, err := Write(dir, base.Add(time.Duration(i)*time.Second), []byte("a"), []byte("b"))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = p
		}
	}
	same, err := Write(dir, base.Add(time.Duration(Keep+2)*time.Second), []byte("x"))
	if err != nil || filepath.Base(same) != "20261109-120022-01.log" {
		t.Fatalf("collision name = %q, %v", same, err)
	}
	if _, err := Write(same, base, []byte("x")); err == nil {
		t.Fatal("writing under a file path succeeded")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != Keep+1 {
		t.Fatalf("kept %d entries", len(entries))
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("foreign .log file was pruned")
	}
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatal("oldest log not pruned")
	}
	info, _ := os.Stat(same)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
	if b, _ := os.ReadFile(same); string(b) != "x" {
		t.Fatalf("content = %q", b)
	}
}

func TestListAndReportJSON(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"20260102-000000-00.log", "20260101-000000-00.log", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	logs, err := List(dir)
	if err != nil || len(logs) != 2 || filepath.Base(logs[0]) != "20260101-000000-00.log" {
		t.Fatalf("List = %v, %v", logs, err)
	}
	if got := string(ReportJSON([]byte("frame\nreport" + JSONMarker + `{"a":1}`))); got != `{"a":1}` {
		t.Errorf("from log = %q", got)
	}
	if got := string(ReportJSON([]byte(`{"a":1}`))); got != `{"a":1}` {
		t.Errorf("plain JSON = %q", got)
	}
}
