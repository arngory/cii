package region

import (
	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/probe"
)

const Module = "region"

const (
	GeoIP    probe.Group = "geoip"
	Platform probe.Group = "platform"
	CDN      probe.Group = "cdn"
	Registry probe.Group = "registry"
)

func Select(k config.Keys, extended bool) []probe.Check {
	return probe.Select(Module, append(append([]probe.Check(nil), Checks...), ExtendedChecks...), k, extended)
}

func Owns(g probe.Group) bool {
	return g == GeoIP || g == Platform || g == CDN || g == Registry
}
