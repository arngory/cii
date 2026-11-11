package route

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/arngory/cii/internal/netx"
)

type Hop struct {
	TTL   int     `json:"ttl"`
	Addr  string  `json:"addr,omitempty"`
	RTTms float64 `json:"rtt_ms,omitempty"`
	ASN   uint    `json:"asn,omitempty"`
	Org   string  `json:"org,omitempty"`
}

type Path struct {
	Target  Target   `json:"target"`
	Addr    string   `json:"addr,omitempty"`
	ASN     uint     `json:"asn,omitempty"`
	Org     string   `json:"org,omitempty"`
	RTTms   float64  `json:"rtt_ms,omitempty"`
	Samples int      `json:"samples"`
	Hops    []Hop    `json:"hops,omitempty"`
	Transit []string `json:"transit,omitempty"`
	JumpMs  float64  `json:"jump_ms,omitempty"`
	Verdict string   `json:"verdict"`
	Reason  string   `json:"reason,omitempty"`
	Error   string   `json:"error,omitempty"`
	Timing  string   `json:"timing,omitempty"`
	addr    netip.Addr
}

type Report struct {
	Method  string  `json:"method"`
	FloorMs float64 `json:"floor_ms,omitempty"`
	OwnASN  uint    `json:"own_asn,omitempty"`
	Note    string  `json:"note,omitempty"`
	Paths   []Path  `json:"paths"`
}

type Options struct {
	Targets []Target
	ASN     func(netip.Addr) (uint, string)
	OwnASN  uint
	Rounds  int
	MaxTTL  int
	Wait    time.Duration
	TCPOnly bool
}

func Defaults() Options {
	return Options{Targets: Targets, Rounds: 3, MaxTTL: 24, Wait: 2 * time.Second}
}

func Run(ctx context.Context, n *netx.Net, o Options) *Report {
	rep := &Report{OwnASN: o.OwnASN}
	paths := make([]*Path, len(o.Targets))
	var wg sync.WaitGroup
	for i, t := range o.Targets {
		paths[i] = &Path{Target: t}
		wg.Go(func() { resolve(ctx, n, paths[i]) })
	}
	wg.Wait()
	rep.Method = "tcp"
	switch {
	case o.TCPOnly:
		rep.Note = "TCP connect timing only (--tcp)"
	case n.Options().Family == netx.IPv6:
		rep.Note = "IPv6: TCP connect timing only"
	default:
		if err := traceICMP(ctx, n, o, paths); err != nil {
			rep.Note = "no hop data: " + err.Error() + "; TCP connect timing only"
		} else {
			rep.Method = "icmp"
		}
	}
	timeTCP(ctx, n, paths)
	for _, p := range paths {
		annotate(p, o.ASN)
	}
	if rep.OwnASN == 0 {
		rep.OwnASN = firstHopASN(paths)
	}
	if !attributed(paths) {
		rep.Note = strings.TrimPrefix(rep.Note+"; no local ASN database (cii data update): hops and destinations are not attributed", "; ")
	}
	rep.FloorMs = floor(paths)
	local := answeredLocally(paths)
	if local {
		rep.Note = strings.TrimPrefix(rep.Note+"; every destination answered in under 2 ms, which no real path allows: connections end at a local proxy, tunnel or sandbox", "; ")
	}
	for _, p := range paths {
		judge(p, rep.FloorMs, rep.OwnASN)
		if local && p.RTTms > 0 {
			p.Verdict, p.Reason = Intercepted, "answered locally"
		}
		rep.Paths = append(rep.Paths, *p)
	}
	return rep
}

func attributed(paths []*Path) bool {
	reached := false
	for _, p := range paths {
		if p.ASN != 0 {
			return true
		}
		for _, h := range p.Hops {
			if h.ASN != 0 {
				return true
			}
		}
		reached = reached || p.addr.IsValid()
	}
	return !reached
}

func answeredLocally(paths []*Path) bool {
	expects := map[uint]bool{}
	answered := 0
	for _, p := range paths {
		if p.RTTms <= 0 {
			continue
		}
		if p.RTTms >= localLimitMs {
			return false
		}
		answered++
		expects[p.Target.Expect] = true
	}
	return answered >= 6 && len(expects) >= 4
}

func resolve(ctx context.Context, n *netx.Net, p *Path) {
	want4 := n.Options().Family != netx.IPv6
	if a, err := netip.ParseAddr(p.Target.Host); err == nil {
		if a.Unmap().Is4() == want4 {
			p.addr = a.Unmap()
		} else {
			p.Error = "no " + n.Options().Family.String() + " address"
		}
		return
	}
	addrs, err := n.LookupHost(ctx, Module, p.Target.Host)
	if err != nil {
		p.Error = describe(err)
		return
	}
	for _, s := range addrs {
		if a, err := netip.ParseAddr(s); err == nil && a.Unmap().Is4() == want4 {
			p.addr = a.Unmap()
			return
		}
	}
	p.Error = "no " + n.Options().Family.String() + " address"
}

func firstHopASN(paths []*Path) uint {
	votes := map[uint]int{}
	best, bestN := uint(0), 0
	for _, p := range paths {
		for _, h := range p.Hops {
			if h.ASN != 0 {
				votes[h.ASN]++
				if votes[h.ASN] > bestN {
					best, bestN = h.ASN, votes[h.ASN]
				}
				break
			}
		}
	}
	return best
}

func annotate(p *Path, lookup func(netip.Addr) (uint, string)) {
	if p.addr.IsValid() {
		p.Addr = p.addr.String()
	}
	if lookup == nil {
		return
	}
	if p.addr.IsValid() {
		p.ASN, p.Org = lookup(p.addr)
	}
	for i := range p.Hops {
		if a, err := netip.ParseAddr(p.Hops[i].Addr); err == nil && netx.IsPublic(a) {
			p.Hops[i].ASN, p.Hops[i].Org = lookup(a)
		}
	}
}
