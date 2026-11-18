package main

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/arngory/cii/internal/report"
)

func TestMetricsServer(t *testing.T) {
	for _, bad := range []string{"", "9433", "127.0.0.1", "127.0.0.1:", "256.0.0.1:9433", "127.0.0.1:http-ish-port", ":9433", "localhost:9433", "metrics.example:9433"} {
		if m, err := listenMetrics(bad); err == nil {
			m.close()
			t.Errorf("--listen %q was accepted", bad)
		}
	}
	m, err := listenMetrics("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer m.close()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	get := func(method, path string) (int, string, string) {
		req, _ := http.NewRequest(method, "http://"+m.addr+path, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("Content-Type"), string(body)
	}
	if code, _, _ := get(http.MethodGet, "/metrics"); code != http.StatusServiceUnavailable {
		t.Errorf("before the first run: HTTP %d", code)
	}
	if err := m.set(report.Demo("online").Scrubbed()); err != nil {
		t.Fatal(err)
	}
	code, kind, body := get(http.MethodGet, "/metrics")
	if code != http.StatusOK || !strings.HasPrefix(kind, "text/plain; version=0.0.4") || !strings.Contains(body, "cii_check_available") {
		t.Errorf("metrics: HTTP %d, %q\n%.300s", code, kind, body)
	}
	if strings.Contains(body, "203.0.113.7") {
		t.Errorf("a masked report exposed the address in the metrics")
	}
	if code, _, body := get(http.MethodHead, "/metrics"); code != http.StatusOK || body != "" {
		t.Errorf("HEAD: HTTP %d, body %q", code, body)
	}
	for path, want := range map[string]int{"/": http.StatusNotFound, "/metrics/": http.StatusNotFound, "/report.json": http.StatusNotFound} {
		if code, _, _ := get(http.MethodGet, path); code != want {
			t.Errorf("GET %s: HTTP %d, want %d", path, code, want)
		}
	}
	if code, _, _ := get(http.MethodPost, "/metrics"); code != http.StatusMethodNotAllowed {
		t.Errorf("POST: HTTP %d", code)
	}
	if err := m.close(); err != nil {
		t.Errorf("close: %v", err)
	}
	if _, err := client.Get("http://" + m.addr + "/metrics"); err == nil {
		t.Error("the server still answers after close")
	}
}
