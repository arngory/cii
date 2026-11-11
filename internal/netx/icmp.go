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
	mu      sync.Mutex
	allowed map[netip.Addr]bool
}

func (n *Net) ListenICMP4(module string) (*ICMPConn, error) {
	if n.proxied {
		return nil, ErrProxyRaw
	}
	src := "0.0.0.0"
	if n.opts.Source.IsValid() && n.opts.Source.Is4() {
		src = n.opts.Source.String()
	}
	c, err := icmp.ListenPacket("ip4:icmp", src)
	if err != nil {
		return nil, err
	}
	return &ICMPConn{n: n, module: module, conn: c, allowed: map[netip.Addr]bool{}}, nil
}

func (c *ICMPConn) Allow(host string, ip netip.Addr) error {
	if err := c.n.addrOf(c.module, host, ip); err != nil {
		return err
	}
	if _, err := c.n.allow(c.module, host, "icmp"); err != nil {
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
	if err := c.conn.IPv4PacketConn().SetTTL(ttl); err != nil {
		return err
	}
	_, err := c.conn.WriteTo(b, &net.IPAddr{IP: ip.AsSlice()})
	return err
}

func (c *ICMPConn) ReadFrom(b []byte) (int, net.Addr, error) { return c.conn.ReadFrom(b) }

func (c *ICMPConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

func (c *ICMPConn) Close() error { return c.conn.Close() }
