package region

import (
	"context"
	"net/netip"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

const Module = "region"

const (
	GeoIP    probe.Group = "geoip"
	Platform probe.Group = "platform"
	CDN      probe.Group = "cdn"
)

func Select(k config.Keys, extended bool) []probe.Check {
	return probe.Select(append(append([]probe.Check(nil), Checks...), ExtendedChecks...), k, extended)
}

func Rules(checks []probe.Check) []netx.Rule {
	return probe.Rules(Module, checks)
}

func Run(ctx context.Context, nets map[netx.Family]*netx.Net, keys config.Keys, f netx.Family, ip netip.Addr, checks []probe.Check) []probe.Result {
	return probe.Run(ctx, probe.Env{Module: Module, Nets: nets, Keys: keys}, f, ip, checks)
}
