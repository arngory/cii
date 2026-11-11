package netx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
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
	return n.check(module, host, netip.Addr{}, false, proto)
}

func (n *Net) allowAddr(module, host string, ip netip.Addr, proto string) (Rule, error) {
	return n.check(module, host, ip, true, proto)
}

func (n *Net) check(module, host string, ip netip.Addr, verify bool, proto string) (Rule, error) {
	rule, ok := n.policy.Match(module, host)
	if !ok {
		n.ledger.Blocked(module, "not declared", normalizeHost(host), proto)
		return rule, &BlockedError{Module: module, Host: host}
	}
	if verify {
		if err := n.addrOf(module, host, ip); err != nil {
			n.ledger.Blocked(module, "address not resolved for host", ledgerHost(rule, host), proto)
			return rule, err
		}
	}
	if n.proxied {
		n.ledger.Skipped(module, rule.Purpose, ledgerHost(rule, host), proto)
		return rule, ErrProxyRaw
	}
	n.ledger.Request(module, rule.Purpose, ledgerHost(rule, host), proto)
	return rule, nil
}

func baseNetwork(network string) (string, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return "tcp", nil
	case "udp", "udp4", "udp6":
		return "udp", nil
	}
	return "", fmt.Errorf("dial: unsupported network %q", network)
}

func (n *Net) Dial(ctx context.Context, module, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	base, err := baseNetwork(network)
	if err != nil {
		return nil, err
	}
	rule, err := n.allow(module, host, network)
	if err != nil {
		return nil, err
	}
	return n.dial(ctx, module, rule, host, base, network, addr)
}

func (n *Net) DialAddr(ctx context.Context, module, network, host string, ip netip.Addr, port string) (net.Conn, error) {
	base, err := baseNetwork(network)
	if err != nil {
		return nil, err
	}
	rule, err := n.allowAddr(module, host, ip, network)
	if err != nil {
		return nil, err
	}
	return n.dial(ctx, module, rule, host, base, network, net.JoinHostPort(ip.Unmap().String(), port))
}

func (n *Net) dial(ctx context.Context, module string, rule Rule, host, base, network, addr string) (net.Conn, error) {
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
	out, err := n.resolve(ctx, module, name, func(ctx context.Context) ([]string, error) { return net.DefaultResolver.LookupHost(ctx, name) })
	if err == nil {
		var addrs []netip.Addr
		for _, s := range out {
			if a, err := netip.ParseAddr(s); err == nil {
				addrs = append(addrs, a.Unmap())
			}
		}
		n.resolved.Store(resolvedKey(module, name), addrs)
	}
	return out, err
}

func resolvedKey(module, host string) string { return module + "\x00" + normalizeHost(host) }

var ErrAddrNotOfHost = errors.New("address was not resolved for this host")

func (n *Net) addrOf(module, host string, ip netip.Addr) error {
	if !ip.IsValid() {
		return ErrAddrNotOfHost
	}
	ip = ip.Unmap()
	if lit, err := netip.ParseAddr(host); err == nil {
		if lit.Unmap() == ip {
			return nil
		}
		return ErrAddrNotOfHost
	}
	if v, ok := n.resolved.Load(resolvedKey(module, host)); ok && slices.Contains(v.([]netip.Addr), ip) {
		return nil
	}
	return ErrAddrNotOfHost
}

func (n *Net) resolve(ctx context.Context, module, name string, do func(context.Context) ([]string, error)) ([]string, error) {
	rule, err := n.allow(module, name, "dns")
	if err != nil {
		return nil, err
	}
	out, err := do(ctx)
	var dnsErr *net.DNSError
	if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
		n.ledger.Error(module, rule.Purpose, ledgerHost(rule, name), "dns")
	}
	return out, err
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
	return n.resolve(ctx, module, name, func(ctx context.Context) ([]string, error) {
		return net.DefaultResolver.LookupAddr(ctx, ip.Unmap().String())
	})
}
