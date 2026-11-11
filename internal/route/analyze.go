package route

import (
	"fmt"
	"slices"
	"strings"

	"github.com/arngory/cii/internal/probe"
)

const (
	Direct      = "direct"
	Near        = "near"
	Regional    = "regional"
	Transit     = "transit"
	Detour      = "detour"
	Intercepted = "intercepted"
	Unreachable = "unreachable"
)

const (
	jumpLimit    = 40.0
	localLimitMs = 2.0
)

func judge(p *Path, floor float64, own uint) {
	if p.RTTms <= 0 {
		p.Verdict = Unreachable
		if p.Reason = p.Error; p.Reason == "" {
			p.Reason = "no answer"
		}
		return
	}
	p.Error = ""
	responding := 0
	prev := 0.0
	seenDest := false
	for _, h := range p.Hops {
		if h.Addr == "" {
			continue
		}
		responding++
		if prev > 0 && h.RTTms-prev > p.JumpMs {
			p.JumpMs = h.RTTms - prev
		}
		prev = h.RTTms
		if h.ASN != 0 && h.ASN == p.ASN {
			seenDest = true
		}
		if name, ok := transitASNs[h.ASN]; ok && !seenDest && h.ASN != own && h.ASN != p.Target.Expect && h.ASN != p.ASN {
			label := fmt.Sprintf("AS%d %s", h.ASN, name)
			if !slices.Contains(p.Transit, label) {
				p.Transit = append(p.Transit, label)
			}
		}
	}
	excess := p.RTTms - floor
	var parts []string
	switch {
	case len(p.Hops) > 0 && p.RTTms < 1 && responding <= 1:
		p.Verdict = Intercepted
		parts = append(parts, "answered in under 1 ms with no hops: a local proxy or tunnel replied")
	case excess > 60:
		p.Verdict = Detour
		parts = append(parts, fmt.Sprintf("+%.0f ms over the fastest path", excess))
	case p.JumpMs > jumpLimit:
		p.Verdict = Detour
		parts = append(parts, fmt.Sprintf("one hop adds %.0f ms", p.JumpMs))
	case len(p.Transit) > 0:
		p.Verdict = Transit
		parts = append(parts, "via "+strings.Join(p.Transit, ", "))
	case excess <= 5:
		p.Verdict = Direct
	case excess <= 25:
		p.Verdict = Near
	default:
		p.Verdict = Regional
		parts = append(parts, fmt.Sprintf("+%.0f ms over the fastest path", excess))
	}
	switch {
	case p.ASN == 0 || p.Target.Expect == 0:
	case own != 0 && p.ASN == own && p.ASN != p.Target.Expect:
		parts = append(parts, "served from a cache inside your network")
	case p.ASN != p.Target.Expect:
		parts = append(parts, fmt.Sprintf("served from AS%d %s, not AS%d", p.ASN, p.Org, p.Target.Expect))
	}
	p.Reason = strings.Join(parts, "; ")
}

func (r *Report) Results() []probe.Result {
	out := make([]probe.Result, 0, len(r.Paths))
	for _, p := range r.Paths {
		res := probe.Result{Group: p.Target.Group, Service: p.Target.Name, Reason: p.Reason}
		switch p.Verdict {
		case Direct, Near:
			res.Status = probe.Yes
		case Regional, Transit:
			res.Status = probe.Partial
		case Detour, Intercepted:
			res.Status = probe.No
		default:
			res.Status = probe.Failed
		}
		if p.RTTms > 0 {
			res.Detail = fmt.Sprintf("%.1f ms %s", p.RTTms, p.Verdict)
			if p.Reason != "" {
				res.Detail += ": " + p.Reason
			}
		}
		out = append(out, res)
	}
	return out
}
