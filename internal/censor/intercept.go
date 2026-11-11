package censor

import (
	"context"
	"errors"
	"net"
	"net/netip"
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

func (r *runner) queryTXT(ctx context.Context, addr, name string, class dnsmessage.Class) ([]string, dnsmessage.RCode, error) {
	ctx, cancel := r.timeoutCtx(ctx)
	defer cancel()
	id := randomID()
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	qn, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, 0, err
	}
	q, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: qn, Type: dnsmessage.TypeTXT, Class: class}},
	}).Pack()
	if err != nil {
		return nil, 0, err
	}
	c, err := r.n.Dial(ctx, Module, "udp", addr)
	if err != nil {
		return nil, 0, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write(q); err != nil {
		return nil, 0, err
	}
	buf := make([]byte, 4096)
	for {
		k, err := c.Read(buf)
		if err != nil {
			return nil, 0, err
		}
		txt, rcode, err := parseTXT(buf[:k], id)
		if errors.Is(err, errMismatch) {
			continue
		}
		return txt, rcode, err
	}
}

func parseTXT(msg []byte, id uint16) ([]string, dnsmessage.RCode, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil, 0, err
	}
	if !h.Response || h.ID != id {
		return nil, 0, errMismatch
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, h.RCode, err
	}
	var out []string
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return out, h.RCode, nil
		}
		if err != nil {
			return out, h.RCode, err
		}
		if rh.Type != dnsmessage.TypeTXT {
			if err := p.SkipAnswer(); err != nil {
				return out, h.RCode, err
			}
			continue
		}
		t, err := p.TXTResource()
		if err != nil {
			return out, h.RCode, err
		}
		out = append(out, strings.Join(t.TXT, ""))
	}
}

func (r *runner) interception(ctx context.Context) []probe.Result {
	fam := r.n.Options().Family
	if fam != netx.IPv6 {
		fam = netx.IPv4
	}
	out := make([]probe.Result, 2)
	var wg sync.WaitGroup
	wg.Go(func() {
		defer r.acquire()()
		var txt []string
		var rcode dnsmessage.RCode
		err := r.attempt(func() error {
			var err error
			txt, rcode, err = r.queryTXT(ctx, net.JoinHostPort(openDNSServer[fam], "53"), "which.opendns.com", dnsmessage.ClassINET)
			return err
		})
		out[0] = openDNSResult(txt, rcode, err)
	})
	wg.Go(func() {
		defer r.acquire()()
		var txt []string
		var rcode dnsmessage.RCode
		err := r.attempt(func() error {
			var err error
			txt, rcode, err = r.queryTXT(ctx, net.JoinHostPort(googleServer[fam], "53"), "id.server", dnsmessage.ClassCHAOS)
			return err
		})
		out[1] = googleChaosResult(txt, rcode, err)
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
	route := probe.Result{Group: Local, Service: "Default route"}
	ifc, src, ok := netx.RouteInterface(n.Options().Family)
	if s := n.Options().Source; s.IsValid() {
		route.Service, src = "Source interface", s
		ifc, ok = netx.InterfaceOf(s)
	}
	switch {
	case n.Proxied():
		route.Status, route.Reason = probe.Unknown, "a proxy is in effect: the path starts at the proxy"
	case !ok:
		route.Status, route.Reason = probe.Unknown, "no interface for "+n.Options().Family.String()
	case netx.IsTunnel(ifc):
		route.Status, route.Reason = probe.Partial, "through tunnel "+ifc.Name+": results describe the tunnel exit"
		route.Detail = src.String()
	default:
		route.Status, route.Reason = probe.Yes, "no tunnel on "+ifc.Name
	}
	out = append(out, route)
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
	return out
}
