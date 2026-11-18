package censor

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

const Local probe.Group = "local"

const notOpenDNS = "not an opendns resolver"

var (
	openDNSServer = map[netx.Family]string{netx.IPv4: "208.67.222.222", netx.IPv6: "2620:119:35::35"}
	googleServer  = map[netx.Family]string{netx.IPv4: "8.8.8.8", netx.IPv6: "2001:4860:4860::8888"}
	fakeIPRange   = netip.MustParsePrefix("198.18.0.0/15")
	resolvConf    = "/etc/resolv.conf"
)

func (r *runner) interception(ctx context.Context) []probe.Result {
	fam := r.n.Options().Family
	if fam != netx.IPv6 {
		fam = netx.IPv4
	}
	out := make([]probe.Result, 2)
	var wg sync.WaitGroup
	wg.Go(func() {
		defer r.acquire()()
		var a answer
		err := r.attempt(func() error {
			var err error
			a, err = r.queryUDP(ctx, net.JoinHostPort(openDNSServer[fam], "53"), "which.opendns.com", dnsmessage.TypeTXT)
			return err
		})
		out[0] = openDNSResult(a.TXT, a.RCode, err)
	})
	wg.Go(func() {
		defer r.acquire()()
		var a answer
		err := r.attempt(func() error {
			var err error
			a, err = r.queryUDP(ctx, net.JoinHostPort(googleServer[fam], "53"), "id.server", dnsmessage.TypeTXT, dnsmessage.ClassCHAOS)
			return err
		})
		out[1] = googleChaosResult(a.TXT, a.RCode, err)
	})
	wg.Wait()
	return out
}

func openDNSResult(txt []string, rcode dnsmessage.RCode, err error) probe.Result {
	res := probe.Result{Group: DNS, Service: "Port 53 interception (OpenDNS)"}
	switch {
	case err != nil:
		res.Status, res.Reason = errStatus(err), describe(err)
		if res.Status == probe.No {
			res.Status = probe.Unknown
		}
	case len(txt) == 0:
		res.Status, res.Reason = probe.Unknown, "no TXT answer ("+rcodeName(rcode)+")"
	case strings.Contains(strings.ToLower(strings.Join(txt, " ")), notOpenDNS):
		res.Status, res.Reason = probe.No, "intercepted: answered by another resolver"
		res.Detail = probe.Truncate(strings.Join(txt, " "), 80)
	default:
		res.Status, res.Reason = probe.Yes, "answered by OpenDNS"
		res.Detail = probe.Truncate(strings.Join(txt, " "), 80)
	}
	return res
}

func googleChaosResult(txt []string, rcode dnsmessage.RCode, err error) probe.Result {
	res := probe.Result{Group: DNS, Service: "Port 53 interception (Google)"}
	switch {
	case err != nil:
		res.Status, res.Reason = errStatus(err), describe(err)
		if res.Status == probe.No {
			res.Status = probe.Unknown
		}
	case len(txt) > 0:
		res.Status, res.Reason = probe.No, "intercepted: CHAOS id.server answered"
		res.Detail = probe.Truncate(strings.Join(txt, " "), 80)
	default:
		res.Status, res.Reason = probe.Yes, "no CHAOS answer ("+rcodeName(rcode)+"), as expected from Google"
	}
	return res
}

func localChecks(n *netx.Net) []probe.Result {
	var out []probe.Result
	out = append(out, routeCheck(n))
	if ns := netx.SystemNameservers(resolvConf); len(ns) > 0 {
		res := probe.Result{Group: Local, Service: "System resolver", Status: probe.Yes, Reason: "no fake-IP resolver"}
		for _, a := range ns {
			if fakeIPRange.Contains(a) {
				res.Status, res.Reason = probe.Partial, "fake-IP resolver (Clash/sing-box style): DNS is answered locally"
				res.Detail = a.String()
				break
			}
		}
		out = append(out, res)
	}
	if !n.Proxied() && !n.Options().Source.IsValid() {
		if ifc, _, ok := netx.RouteInterface(n.Options().Family); ok && ifc.MTU > 0 {
			out = append(out, probe.Result{Group: Local, Service: "Interface MTU", Status: probe.Yes, Reason: strconv.Itoa(ifc.MTU) + " on " + ifc.Name})
		}
	}
	return out
}

func routeCheck(n *netx.Net) probe.Result {
	route := probe.Result{Group: Local, Service: "Default route"}
	if n.Proxied() {
		route.Status, route.Reason = probe.Unknown, "a proxy is in effect: the path starts at the proxy"
		return route
	}
	var ifc net.Interface
	var src netip.Addr
	var ok bool
	if s := n.Options().Source; s.IsValid() {
		route.Service, src = "Source interface", s
		ifc, ok = netx.InterfaceOf(s)
	} else {
		ifc, src, ok = netx.RouteInterface(n.Options().Family)
	}
	switch {
	case !ok:
		route.Status, route.Reason = probe.Unknown, "no interface for "+n.Options().Family.String()
	case netx.IsTunnel(ifc):
		route.Status, route.Reason = probe.Partial, "through tunnel "+ifc.Name+": results describe the tunnel exit"
		route.Detail = src.String()
	default:
		route.Status, route.Reason = probe.Yes, "no tunnel on "+ifc.Name
	}
	return route
}
