package netx

import (
	"golang.org/x/net/icmp"
)

func (n *Net) AllowICMP(module, host string) error {
	_, err := n.allow(module, host, "icmp")
	return err
}

func (n *Net) ListenICMP4() (*icmp.PacketConn, error) {
	if n.proxied {
		return nil, ErrProxyRaw
	}
	src := "0.0.0.0"
	if n.opts.Source.IsValid() && n.opts.Source.Is4() {
		src = n.opts.Source.String()
	}
	return icmp.ListenPacket("ip4:icmp", src)
}
