package netx

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

type UDPConn struct {
	n       *Net
	module  string
	conn    *net.UDPConn
	mu      sync.Mutex
	allowed map[netip.Addr]bool
}

func (n *Net) ListenUDP(module string) (*UDPConn, error) {
	if n.proxied {
		return nil, ErrProxyRaw
	}
	network := n.opts.Family.network("udp")
	var local *net.UDPAddr
	if s := n.opts.Source; s.IsValid() {
		local = &net.UDPAddr{IP: s.AsSlice()}
	}
	c, err := net.ListenUDP(network, local)
	if err != nil {
		return nil, err
	}
	return &UDPConn{n: n, module: module, conn: c, allowed: map[netip.Addr]bool{}}, nil
}

func (c *UDPConn) Allow(host string, ip netip.Addr) error {
	if _, err := c.n.allowAddr(c.module, host, ip, "udp"); err != nil {
		return err
	}
	c.mu.Lock()
	c.allowed[ip.Unmap()] = true
	c.mu.Unlock()
	return nil
}

func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	u, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, ErrAddrNotOfHost
	}
	ip, _ := netip.AddrFromSlice(u.IP)
	c.mu.Lock()
	ok = c.allowed[ip.Unmap()]
	c.mu.Unlock()
	if !ok {
		return 0, ErrAddrNotOfHost
	}
	return c.conn.WriteTo(b, u)
}

func (c *UDPConn) ReadFrom(b []byte) (int, net.Addr, error) { return c.conn.ReadFrom(b) }
func (c *UDPConn) LocalAddr() net.Addr                      { return c.conn.LocalAddr() }
func (c *UDPConn) SetDeadline(t time.Time) error            { return c.conn.SetDeadline(t) }
func (c *UDPConn) SetReadDeadline(t time.Time) error        { return c.conn.SetReadDeadline(t) }
func (c *UDPConn) SetWriteDeadline(t time.Time) error       { return c.conn.SetWriteDeadline(t) }
func (c *UDPConn) Close() error                             { return c.conn.Close() }
