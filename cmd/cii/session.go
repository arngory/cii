package main

import (
	"slices"
	"sync"

	"github.com/arngory/cii/internal/geodb"
	"github.com/arngory/cii/internal/ipdetect"
	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/report"
)

type hostRun struct {
	family   netx.Family
	addr     ipdetect.Address
	geo      []geodb.Record
	local    []probe.Result
	checks   [][]probe.Result
	regional [][]probe.Result
	risk     []probe.Result
	offline  []probe.Result
}

type session struct {
	mu    sync.Mutex
	mode  string
	mask  bool
	dbs   *geodb.Set
	led   *ledger.Ledger
	hosts []*hostRun
}

func (s *session) update(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

func slots(rs []probe.Result) [][]probe.Result {
	out := make([][]probe.Result, len(rs))
	for i, r := range rs {
		out[i] = []probe.Result{r}
	}
	return out
}

func (h *hostRun) split() (regionResults, services []probe.Result) {
	regionResults = slices.Clone(h.local)
	for _, rs := range h.checks {
		for _, r := range rs {
			if region.Owns(r.Group) {
				regionResults = append(regionResults, r)
			} else {
				services = append(services, r)
			}
		}
	}
	for _, rs := range h.regional {
		services = append(services, rs...)
	}
	services = append(services, h.risk...)
	return regionResults, append(services, h.offline...)
}

func (s *session) verdict(h *hostRun) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	results, _ := h.split()
	return region.Summarize(results).Verdict
}

func (s *session) report() *report.Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	rep := report.New(s.mode, s.mask)
	rep.SetData(s.dbs)
	for _, h := range s.hosts {
		host := report.NewHost(h.addr, slices.Clone(h.geo), s.mask)
		if h.addr.Address.IsValid() {
			results, svc := h.split()
			if len(svc) > 0 {
				host.SetServices(svc, s.mask)
			}
			if len(results) > 0 {
				host.SetRegion(region.Summarize(results), s.mask)
			}
		}
		setHost(rep, h.family, host)
	}
	rep.Network = s.led.Entries()
	return rep
}
