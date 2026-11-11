package netx

import (
	"net"
	"net/netip"
	"os"
	"strings"
)

var routeProbe = map[Family]string{IPv4: "192.0.2.1:9", IPv6: "[2001:db8::1]:9"}

func RouteInterface(f Family) (net.Interface, netip.Addr, bool) {
	target, ok := routeProbe[f]
	if !ok {
		target = routeProbe[IPv4]
	}
	c, err := net.Dial("udp", target)
	if err != nil {
		return net.Interface{}, netip.Addr{}, false
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return net.Interface{}, netip.Addr{}, false
	}
	src, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return net.Interface{}, netip.Addr{}, false
	}
	src = src.Unmap()
	ifc, ok := InterfaceOf(src)
	return ifc, src, ok
}

func InterfaceOf(src netip.Addr) (net.Interface, bool) {
	ifs, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, false
	}
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if pn, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(pn.IP); ok && ip.Unmap() == src.Unmap() {
					return ifc, true
				}
			}
		}
	}
	return net.Interface{}, false
}

var tunnelPrefixes = []string{"tun", "utun", "tap", "ppp", "wg", "ipsec", "gpd", "nordlynx", "tailscale", "zt"}

func IsTunnel(ifc net.Interface) bool {
	if ifc.Flags&net.FlagPointToPoint != 0 {
		return true
	}
	name := strings.ToLower(ifc.Name)
	for _, p := range tunnelPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func SystemNameservers(path string) []netip.Addr {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(strings.SplitN(f[1], "%", 2)[0]); err == nil {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
}
