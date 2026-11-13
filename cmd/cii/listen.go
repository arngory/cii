package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/arngory/cii/internal/report"
)

type metricsServer struct {
	mu   sync.RWMutex
	body []byte
	srv  *http.Server
	addr string
}

func listenMetrics(addr string) (*metricsServer, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return nil, fmt.Errorf("--listen %q: expected host:port, e.g. 127.0.0.1:9433", addr)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("--listen: %w", err)
	}
	m := &metricsServer{addr: ln.Addr().String()}
	m.srv = &http.Server{Handler: m, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go m.srv.Serve(ln)
	return m, nil
}

func (m *metricsServer) set(r *report.Report) error {
	var b bytes.Buffer
	if err := r.WritePrometheus(&b); err != nil {
		return err
	}
	m.mu.Lock()
	m.body = b.Bytes()
	m.mu.Unlock()
	return nil
}

func (m *metricsServer) close() error {
	if err := m.srv.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (m *metricsServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch {
	case req.URL.Path != "/metrics":
		http.NotFound(w, req)
		return
	case req.Method != http.MethodGet && req.Method != http.MethodHead:
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m.mu.RLock()
	body := m.body
	m.mu.RUnlock()
	if body == nil {
		http.Error(w, "the first run has not finished yet", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write(body)
}
