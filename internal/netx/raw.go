package netx

import (
	"context"
	"errors"
	"fmt"
	"net"
)

var ErrProxyRaw = errors.New("raw connections and DNS lookups are disabled while a proxy is in effect")

func (n *Net) Options() Options { return n.opts }

func (n *Net) allow(module, host, proto string) (Rule, error) {
	rule, ok := n.policy.Match(module, host)
	if !ok {
		n.ledger.Blocked(module, "not declared", normalizeHost(host), proto)
		return rule, &BlockedError{Module: module, Host: host}
	}
	if n.proxied {
		n.ledger.Skipped(module, rule.Purpose, normalizeHost(host), proto)
		return rule, ErrProxyRaw
	}
	n.ledger.Request(module, rule.Purpose, normalizeHost(host), proto)
	return rule, nil
}

func (n *Net) Dial(ctx context.Context, module, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	var base string
	switch network {
	case "tcp", "tcp4", "tcp6":
		base = "tcp"
	case "udp", "udp4", "udp6":
		base = "udp"
	default:
		return nil, fmt.Errorf("dial: unsupported network %q", network)
	}
	rule, err := n.allow(module, host, network)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: n.opts.Timeout}
	if n.opts.Source.IsValid() {
		if base == "tcp" {
			d.LocalAddr = &net.TCPAddr{IP: n.opts.Source.AsSlice()}
		} else {
			d.LocalAddr = &net.UDPAddr{IP: n.opts.Source.AsSlice()}
		}
	}
	dialNet := network
	if n.opts.Family != Any {
		dialNet = n.opts.Family.network(base)
	}
	c, err := d.DialContext(ctx, dialNet, addr)
	if err != nil {
		n.ledger.Error(module, rule.Purpose, normalizeHost(host), network)
	}
	return c, err
}

func (n *Net) LookupHost(ctx context.Context, module, name string) ([]string, error) {
	rule, err := n.allow(module, name, "dns")
	if err != nil {
		return nil, err
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, name)
	var dnsErr *net.DNSError
	if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
		n.ledger.Error(module, rule.Purpose, normalizeHost(name), "dns")
	}
	return addrs, err
}
