package netx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

var ErrProxyRaw = errors.New("raw connections and DNS lookups are disabled while a proxy is in effect")

func (n *Net) Options() Options { return n.opts }

func ledgerHost(rule Rule, host string) string {
	if strings.HasPrefix(rule.Pattern, "*.") {
		return rule.Pattern
	}
	return normalizeHost(host)
}

func (n *Net) allow(module, host, proto string) (Rule, error) {
	rule, ok := n.policy.Match(module, host)
	if !ok {
		n.ledger.Blocked(module, "not declared", normalizeHost(host), proto)
		return rule, &BlockedError{Module: module, Host: host}
	}
	if n.proxied {
		n.ledger.Skipped(module, rule.Purpose, ledgerHost(rule, host), proto)
		return rule, ErrProxyRaw
	}
	n.ledger.Request(module, rule.Purpose, ledgerHost(rule, host), proto)
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
		n.ledger.Error(module, rule.Purpose, ledgerHost(rule, host), network)
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
		n.ledger.Error(module, rule.Purpose, ledgerHost(rule, name), "dns")
	}
	return addrs, err
}

func ReverseName(ip netip.Addr) string {
	ip = ip.Unmap()
	b := ip.AsSlice()
	var parts []string
	if ip.Is4() {
		for i := len(b) - 1; i >= 0; i-- {
			parts = append(parts, strconv.Itoa(int(b[i])))
		}
		return strings.Join(parts, ".")
	}
	const hex = "0123456789abcdef"
	for i := len(b) - 1; i >= 0; i-- {
		parts = append(parts, string(hex[b[i]&0xf]), string(hex[b[i]>>4]))
	}
	return strings.Join(parts, ".")
}

func ReverseZone(ip netip.Addr) string {
	if ip.Unmap().Is4() {
		return "in-addr.arpa"
	}
	return "ip6.arpa"
}

func (n *Net) LookupAddr(ctx context.Context, module string, ip netip.Addr) ([]string, error) {
	name := ReverseName(ip) + "." + ReverseZone(ip)
	rule, err := n.allow(module, name, "dns")
	if err != nil {
		return nil, err
	}
	names, err := net.DefaultResolver.LookupAddr(ctx, ip.Unmap().String())
	var dnsErr *net.DNSError
	if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
		n.ledger.Error(module, rule.Purpose, ledgerHost(rule, name), "dns")
	}
	return names, err
}
