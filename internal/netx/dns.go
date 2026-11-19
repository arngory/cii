package netx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	DNSModule  = "dns"
	DNSPurpose = "dns: name lookups via "
)

var dnsRoots *x509.CertPool

type DNSServer struct {
	Name    string
	Addrs   []netip.Addr
	Port    string
	TLSName string
}

func preset(name, tlsName string, addrs ...string) DNSServer {
	s := DNSServer{Name: name, Port: "853", TLSName: tlsName}
	for _, a := range addrs {
		s.Addrs = append(s.Addrs, netip.MustParseAddr(a))
	}
	return s
}

var DNSPresets = map[string]DNSServer{
	"quad9":      preset("Quad9", "dns.quad9.net", "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"),
	"cznic":      preset("CZ.NIC ODVR", "odvr.nic.cz", "193.17.47.1", "185.43.135.1", "2001:148f:ffff::1", "2001:148f:fffe::1"),
	"cloudflare": preset("Cloudflare", "cloudflare-dns.com", "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"),
	"google":     preset("Google", "dns.google", "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"),
	"adguard":    preset("AdGuard", "dns.adguard-dns.com", "94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"),
}

func DNSPresetNames() []string {
	names := make([]string, 0, len(DNSPresets))
	for n := range DNSPresets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func ParseDNS(spec string) (*DNSServer, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.EqualFold(spec, "system") {
		return nil, nil
	}
	if p, ok := DNSPresets[strings.ToLower(spec)]; ok {
		return &p, nil
	}
	s := DNSServer{Port: "53"}
	addr := spec
	if rest, ok := strings.CutPrefix(spec, "tls://"); ok {
		var name string
		addr, name, ok = strings.Cut(rest, "#")
		if !ok || name == "" {
			return nil, fmt.Errorf("--dns %q: DNS-over-TLS needs the certificate name: tls://ADDRESS#NAME", spec)
		}
		s.Port, s.TLSName = "853", name
	}
	bare := addr
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") && strings.Contains(addr, ":") {
		bare = addr[1 : len(addr)-1]
	}
	ap, err := netip.ParseAddrPort(addr)
	if err == nil && ap.Port() == 0 {
		return nil, fmt.Errorf("--dns %q: port 0 is not a port", spec)
	}
	if err == nil {
		s.Port = fmt.Sprint(ap.Port())
	} else if a, perr := netip.ParseAddr(bare); perr == nil && (bare == addr || a.Is6()) {
		ap = netip.AddrPortFrom(a, 0)
	} else {
		return nil, fmt.Errorf("--dns %q: expected system, one of %s, an address such as 192.0.2.53 or [2001:db8::53]:53, or tls://ADDRESS#NAME", spec, strings.Join(DNSPresetNames(), ", "))
	}
	if ap.Addr().Zone() != "" {
		return nil, fmt.Errorf("--dns %q: an address with a zone is not supported", spec)
	}
	s.Addrs = []netip.Addr{ap.Addr().Unmap()}
	s.Name = ap.Addr().Unmap().String()
	return &s, nil
}

func (s *DNSServer) proto() string {
	if s.TLSName != "" {
		return "dot"
	}
	return "dns"
}

func (s *DNSServer) Label() string {
	if s.TLSName != "" {
		return s.Name + " over TLS"
	}
	return s.Name
}

func (s *DNSServer) Public() bool {
	return slices.ContainsFunc(s.Addrs, IsPublic)
}

func (s *DNSServer) Rules() []Rule {
	var out []Rule
	for _, a := range s.Addrs {
		out = append(out, Rule{Module: DNSModule, Pattern: a.String(), Purpose: DNSPurpose + s.Label()})
	}
	return out
}

func (s *DNSServer) ordered() []netip.Addr {
	out := slices.Clone(s.Addrs)
	slices.SortStableFunc(out, func(a, b netip.Addr) int {
		switch {
		case a.Is4() == b.Is4():
			return 0
		case a.Is4():
			return -1
		}
		return 1
	})
	return out
}

func (n *Net) allowResolver(host, proto string) (Rule, error) {
	rule, ok := n.policy.Match(DNSModule, host)
	if !ok {
		n.ledger.Blocked(DNSModule, "not declared", normalizeHost(host), proto)
		return rule, &BlockedError{Module: DNSModule, Host: host}
	}
	n.ledger.Request(DNSModule, rule.Purpose, ledgerHost(rule, host), proto)
	return rule, nil
}

func (n *Net) dnsCandidates() []netip.Addr {
	s, src := n.opts.DNS, n.opts.Source
	var out []netip.Addr
	for _, a := range s.ordered() {
		if !src.IsValid() || src.Is4() == a.Is4() {
			out = append(out, a)
		}
	}
	if last, ok := n.dnsLast.Load().(netip.Addr); ok {
		if k := slices.Index(out, last); k > 0 {
			out = append(append([]netip.Addr{last}, out[:k]...), out[k+1:]...)
		}
	}
	return out
}

func (n *Net) dnsDial(ctx context.Context, network, _ string) (net.Conn, error) {
	s := n.opts.DNS
	base := "udp"
	if strings.HasPrefix(network, "tcp") || s.TLSName != "" {
		base = "tcp"
	}
	candidates := n.dnsCandidates()
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%s has no address of the source address family", s.Label())
	}
	var errs []error
	src := n.opts.Source
	for i, a := range candidates {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		rule, err := n.allowResolver(a.String(), s.proto())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		try, cancel := ctx, context.CancelFunc(func() {})
		if deadline, ok := ctx.Deadline(); ok && i < len(candidates)-1 {
			try, cancel = context.WithTimeout(ctx, time.Until(deadline)/2)
		}
		d := net.Dialer{Timeout: n.opts.Timeout}
		if src.IsValid() {
			if base == "tcp" {
				d.LocalAddr = &net.TCPAddr{IP: src.AsSlice()}
			} else {
				d.LocalAddr = &net.UDPAddr{IP: src.AsSlice()}
			}
		}
		c, err := d.DialContext(try, base, net.JoinHostPort(a.String(), s.Port))
		if err == nil && s.TLSName != "" {
			tc := tls.Client(c, &tls.Config{ServerName: s.TLSName, MinVersion: tls.VersionTLS12, RootCAs: dnsRoots})
			if err = tc.HandshakeContext(try); err != nil {
				c.Close()
			} else {
				c = tc
			}
		}
		cancel()
		if err != nil {
			n.ledger.Error(DNSModule, rule.Purpose, a.String(), s.proto())
			errs = append(errs, err)
			continue
		}
		n.dnsLast.Store(a)
		return c, nil
	}
	return nil, errors.Join(errs...)
}
