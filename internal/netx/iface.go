package netx

import (
	"fmt"
	"net"
	"net/netip"
)

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func IsPublic(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	if a.Is4() && cgnat.Contains(a) {
		return false
	}
	for _, p := range docPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var docPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("198.18.0.0/15"),
}

func InterfaceAddrs(name string) ([]netip.Addr, error) {
	var ifs []net.Interface
	if name != "" {
		ifc, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", name, err)
		}
		ifs = []net.Interface{*ifc}
	} else {
		all, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		ifs = all
	}
	var out []netip.Addr
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if pn, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(pn.IP); ok {
					out = append(out, ip.Unmap())
				}
			}
		}
	}
	return out, nil
}

func SourceForInterface(name string, f Family) (netip.Addr, error) {
	addrs, err := InterfaceAddrs(name)
	if err != nil {
		return netip.Addr{}, err
	}
	families := []Family{f}
	if f == Any {
		families = []Family{IPv4, IPv6}
	}
	for _, fam := range families {
		if a, ok := pickSource(addrs, fam); ok {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("interface %q has no usable %s address", name, f)
}

func pickSource(addrs []netip.Addr, f Family) (netip.Addr, bool) {
	var fallback netip.Addr
	for _, a := range addrs {
		if a.IsLoopback() || a.IsLinkLocalUnicast() || a.Is4() != (f == IPv4) {
			continue
		}
		if IsPublic(a) {
			return a, true
		}
		if !fallback.IsValid() {
			fallback = a
		}
	}
	return fallback, fallback.IsValid()
}
