package ledger

import (
	"sort"
	"sync"
)

type Entry struct {
	Module   string `json:"module"`
	Purpose  string `json:"purpose"`
	Host     string `json:"host"`
	Proto    string `json:"proto"`
	Requests int    `json:"requests"`
	Blocked  int    `json:"blocked,omitempty"`
	Skipped  int    `json:"skipped,omitempty"`
	Errors   int    `json:"errors,omitempty"`
}

type key struct{ module, purpose, host, proto string }

type Ledger struct {
	mu      sync.Mutex
	entries map[key]*Entry
}

func New() *Ledger { return &Ledger{entries: map[key]*Entry{}} }

func (l *Ledger) get(module, purpose, host, proto string) *Entry {
	k := key{module, purpose, host, proto}
	e, ok := l.entries[k]
	if !ok {
		e = &Entry{Module: module, Purpose: purpose, Host: host, Proto: proto}
		l.entries[k] = e
	}
	return e
}

func (l *Ledger) Request(module, purpose, host, proto string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.get(module, purpose, host, proto).Requests++
}

func (l *Ledger) Blocked(module, purpose, host, proto string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.get(module, purpose, host, proto).Blocked++
}

func (l *Ledger) Skipped(module, purpose, host, proto string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.get(module, purpose, host, proto).Skipped++
}

func (l *Ledger) Error(module, purpose, host, proto string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.get(module, purpose, host, proto).Errors++
}

func (l *Ledger) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, 0, len(l.entries))
	for _, e := range l.entries {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Purpose < out[j].Purpose
	})
	return out
}
