package main

import (
	"slices"
	"sync"

	"github.com/arngory/cii/internal/bench"
	"github.com/arngory/cii/internal/geodb"
	"github.com/arngory/cii/internal/ipdetect"
	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/report"
	"github.com/arngory/cii/internal/route"
)

type hostRun struct {
	family   netx.Family
	label    string
	via      string
	order    int
	nets     map[netx.Family]*netx.Net
	addr     ipdetect.Address
	geo      []geodb.Record
	local    []probe.Result
	checks   [][]probe.Result
	regional [][]probe.Result
	risk     []probe.Result
	offline  []probe.Result
}

type session struct {
	mu        sync.Mutex
	mode      string
	mask      bool
	dbs       *geodb.Set
	led       *ledger.Ledger
	hosts     []*hostRun
	censor    []probe.Result
	bench     *bench.Report
	benchStep string
	route     *route.Report
}

func (s *session) step() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.benchStep
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
	rep := report.New(s.mode)
	if s.dbs != nil {
		rep.SetData(s.dbs)
	}
	if s.censor != nil {
		rep.SetCensor(slices.Clone(s.censor))
	}
	if s.bench != nil {
		b := *s.bench
		b.Notes, b.Iperf = slices.Clone(b.Notes), slices.Clone(b.Iperf)
		rep.SetBench(&b)
	}
	hosts := slices.SortedFunc(slices.Values(s.hosts), func(a, b *hostRun) int { return a.order - b.order })
	for _, h := range hosts {
		host := report.NewHost(h.addr, slices.Clone(h.geo))
		if h.addr.Address.IsValid() {
			results, svc := h.split()
			if len(svc) > 0 {
				host.SetServices(svc)
			}
			if len(results) > 0 {
				host.SetRegion(region.Summarize(results))
			}
		}
		if h.label != "" {
			host.Query, host.Via = h.label, h.via
			rep.Exits = append(rep.Exits, host)
			continue
		}
		setHost(rep, h.family, host)
	}
	if s.route != nil {
		rt := *s.route
		rep.Route = &rt
	}
	rep.Network = s.led.Entries()
	if s.mask {
		return rep.Scrubbed()
	}
	return rep
}

func (s *session) ownASN() uint {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.hosts {
		if h.label != "" {
			continue
		}
		for _, g := range h.geo {
			if g.ASN != 0 {
				return g.ASN
			}
		}
	}
	return 0
}
