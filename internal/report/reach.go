package report

import (
	"strings"

	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/risk"
)

const (
	unreachableMin   = 5
	unreachableShare = 4
)

type reach struct{ unreachable, tried int }

func (h *Host) reach() reach {
	var r reach
	for _, res := range h.factResults() {
		if res.Status == probe.Pending || res.Group == risk.Network || strings.HasPrefix(res.Service, "local:") {
			continue
		}
		r.tried++
		if res.Status == probe.Failed && res.Reason == netx.ReasonUnreachable {
			r.unreachable++
		}
	}
	return r
}

func (r reach) broken() bool {
	return r.unreachable >= unreachableMin && r.unreachable*unreachableShare >= r.tried
}

func (r reach) none() bool { return r.unreachable == r.tried }
