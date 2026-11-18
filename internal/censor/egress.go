package censor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/arngory/cii/internal/probe"
)

const (
	EgressPrefix = "Resolver exit"
	akamaiWhoami = "whoami.akamai.net"
	googleWhoami = "o-o.myaddr.l.google.com"
	ecsPrefix    = "edns0-client-subnet "
)

var egressServices = []string{EgressPrefix + " (Akamai)", EgressPrefix + " (Google)"}

func (r *runner) egress(ctx context.Context) []probe.Result {
	out := make([]probe.Result, len(egressServices))
	if r.n.Proxied() {
		for i, s := range egressServices {
			out[i] = probe.Result{Group: DNS, Service: s, Status: probe.Unknown, Reason: "a proxy is in effect: names are resolved at the proxy"}
		}
		return out
	}
	lookups := []func(context.Context) ([]string, error){
		func(ctx context.Context) ([]string, error) { return r.n.LookupHost(ctx, Module, akamaiWhoami) },
		func(ctx context.Context) ([]string, error) { return r.n.LookupTXT(ctx, Module, googleWhoami) },
	}
	var wg sync.WaitGroup
	for i, lookup := range lookups {
		wg.Go(func() {
			defer r.acquire()()
			var raw []string
			err := r.attempt(func() error {
				ctx, cancel := r.timeoutCtx(ctx)
				defer cancel()
				var err error
				raw, err = lookup(ctx)
				return err
			})
			out[i] = egressResult(egressServices[i], raw, err, r.opts.Locate)
		})
	}
	wg.Wait()
	return out
}

func egressResult(service string, raw []string, err error, locate func(netip.Addr) (country, network string)) probe.Result {
	res := probe.Result{Group: DNS, Service: service, Status: probe.Unknown}
	var addrs []netip.Addr
	subnet := ""
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if rest, ok := strings.CutPrefix(s, ecsPrefix); ok {
			if p, err := netip.ParsePrefix(strings.TrimSpace(rest)); err == nil {
				subnet = p.String()
			}
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil && !slices.Contains(addrs, a.Unmap()) {
			addrs = append(addrs, a.Unmap())
		}
	}
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		res.Reason = "no such name: the resolver does not pass the query on"
		return res
	case err != nil:
		res.Reason = describe(err)
		if errStatus(err) == probe.Failed {
			res.Status = probe.Failed
		}
		return res
	case len(addrs) == 0:
		res.Reason = "no address in the answer"
		return res
	}
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
		if fakeIPRange.Contains(a) {
			res.Reason, res.Detail = "answered locally by a fake-IP resolver", a.String()
			return res
		}
		if locate == nil {
			continue
		}
		country, network := locate(a)
		if res.Country == "" {
			res.Country = country
		}
		if network != "" {
			parts[i] += " " + network
		}
	}
	res.Status, res.Reason, res.Detail = probe.Yes, "the resolver that asks on your behalf", strings.Join(parts, ", ")
	if subnet != "" {
		res.Reason += "; it passes the client subnet on (ECS)"
		res.Detail += "; client subnet " + subnet
	}
	return res
}
