package netx

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/icmp"
)

type ICMPConn struct {
	n       *Net
	module  string
	conn    *icmp.PacketConn
	v6      bool
	mu      sync.Mutex
	allowed map[netip.Addr]bool
}

func (n *Net) ListenICMP(module string, v6 bool) (*ICMPConn, error) {
	if n.proxied {
		return nil, ErrProxyRaw
	}
	network, src := "ip4:icmp", "0.0.0.0"
	if v6 {
		network, src = "ip6:ipv6-icmp", "::"
	}
	if s := n.opts.Source; s.IsValid() && s.Is4() != v6 {
		src = s.String()
	}
	c, err := icmp.ListenPacket(network, src)
	if err != nil {
		return nil, err
	}
	return &ICMPConn{n: n, module: module, conn: c, v6: v6, allowed: map[netip.Addr]bool{}}, nil
}

func (c *ICMPConn) Allow(host string, ip netip.Addr) error {
	if _, err := c.n.allowAddr(c.module, host, ip, "icmp"); err != nil {
		return err
	}
	c.mu.Lock()
	c.allowed[ip.Unmap()] = true
	c.mu.Unlock()
	return nil
}

func (c *ICMPConn) WriteTo(b []byte, ip netip.Addr, ttl int) error {
	c.mu.Lock()
	ok := c.allowed[ip.Unmap()]
	c.mu.Unlock()
	if !ok {
		return ErrAddrNotOfHost
	}
	var err error
	if c.v6 {
		err = c.conn.IPv6PacketConn().SetHopLimit(ttl)
	} else {
		err = c.conn.IPv4PacketConn().SetTTL(ttl)
	}
	if err != nil {
		return err
	}
	_, err = c.conn.WriteTo(b, &net.IPAddr{IP: ip.AsSlice()})
	return err
}

func (c *ICMPConn) ReadFrom(b []byte) (int, net.Addr, error) { return c.conn.ReadFrom(b) }

func (c *ICMPConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

func (c *ICMPConn) Close() error { return c.conn.Close() }
