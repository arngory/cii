package censor

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/quic"

	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

const Transport probe.Group = "transport"

type stunServer struct{ Host, Port string }

var (
	stunServers = []stunServer{{"stun.cloudflare.com", "3478"}, {"stun.l.google.com", "19302"}}
	quicTargets = []string{"www.google.com", "www.cloudflare.com"}
	quicPort    = "443"
	quicRoots   *x509.CertPool
	cgnatRange  = netip.MustParsePrefix("100.64.0.0/10")
)

const (
	stunMagic       = 0x2112A442
	stunRequest     = 0x0001
	stunSuccess     = 0x0101
	stunMapped      = 0x0001
	stunXORMapped   = 0x0020
	stunAttempts    = 2
	stunWaitCeiling = 3 * time.Second
)

func (r *runner) transport(ctx context.Context) []probe.Result {
	out := make([]probe.Result, 1+len(quicTargets))
	var wg sync.WaitGroup
	wg.Go(func() {
		defer r.acquire()()
		out[0] = r.nat(ctx)
	})
	for i, host := range quicTargets {
		wg.Go(func() {
			defer r.acquire()()
			out[1+i] = r.quic(ctx, host)
		})
	}
	wg.Wait()
	return out
}

func (r *runner) resolveFamily(ctx context.Context, host string) (netip.Addr, error) {
	ctx, cancel := r.timeoutCtx(ctx)
	defer cancel()
	addrs, err := r.n.LookupHost(ctx, Module, host)
	if err != nil {
		return netip.Addr{}, err
	}
	want6 := r.n.Options().Family == netx.IPv6
	for _, s := range addrs {
		if ip, err := netip.ParseAddr(s); err == nil && ip.Unmap().Is6() == want6 {
			return ip.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no %s address", r.n.Options().Family)
}

func stunBinding() (msg, id []byte) {
	msg = make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:], stunRequest)
	binary.BigEndian.PutUint32(msg[4:], stunMagic)
	rand.Read(msg[8:])
	return msg, msg[8:20]
}

func parseSTUN(msg, id []byte) (netip.AddrPort, bool) {
	if len(msg) < 20 || binary.BigEndian.Uint16(msg[0:]) != stunSuccess || binary.BigEndian.Uint32(msg[4:]) != stunMagic || string(msg[8:20]) != string(id) {
		return netip.AddrPort{}, false
	}
	body := msg[20:]
	if n := int(binary.BigEndian.Uint16(msg[2:])); n <= len(body) {
		body = body[:n]
	}
	var plain netip.AddrPort
	for len(body) >= 4 {
		typ, size := binary.BigEndian.Uint16(body[0:]), int(binary.BigEndian.Uint16(body[2:]))
		if size > len(body)-4 {
			break
		}
		val := body[4 : 4+size]
		body = body[4+min(len(body)-4, (size+3)&^3):]
		if (typ != stunXORMapped && typ != stunMapped) || len(val) < 8 || (val[1] != 1 && val[1] != 2) || (val[1] == 2 && len(val) < 20) {
			continue
		}
		port := binary.BigEndian.Uint16(val[2:])
		raw := append([]byte(nil), val[4:8]...)
		if val[1] == 2 {
			raw = append([]byte(nil), val[4:20]...)
		}
		if typ == stunXORMapped {
			port ^= stunMagic >> 16
			for i := range raw {
				raw[i] ^= msg[4+i]
			}
		}
		ip, _ := netip.AddrFromSlice(raw)
		if typ == stunXORMapped {
			return netip.AddrPortFrom(ip.Unmap(), port), true
		}
		plain = netip.AddrPortFrom(ip.Unmap(), port)
	}
	return plain, plain.IsValid()
}

func stunQuery(conn net.PacketConn, server netip.AddrPort, wait time.Duration) (netip.AddrPort, error) {
	msg, id := stunBinding()
	buf := make([]byte, 1500)
	for range stunAttempts {
		if _, err := conn.WriteTo(msg, net.UDPAddrFromAddrPort(server)); err != nil {
			return netip.AddrPort{}, err
		}
		conn.SetReadDeadline(time.Now().Add(wait))
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				break
			}
			if u, ok := from.(*net.UDPAddr); !ok || u.AddrPort().Port() != server.Port() || u.AddrPort().Addr().Unmap() != server.Addr() {
				continue
			}
			if mapped, ok := parseSTUN(buf[:n], id); ok {
				return mapped, nil
			}
		}
	}
	return netip.AddrPort{}, context.DeadlineExceeded
}

func (r *runner) nat(ctx context.Context) probe.Result {
	res := probe.Result{Group: Transport, Service: "NAT (STUN)", Status: probe.Unknown}
	conn, err := r.n.ListenUDP(Module)
	if err != nil {
		res.Reason = describe(err)
		return res
	}
	defer conn.Close()
	wait := min(r.n.Options().Timeout, stunWaitCeiling)
	var mapped []netip.AddrPort
	var failure error
	for _, s := range stunServers {
		if ctx.Err() != nil {
			break
		}
		port, _ := strconv.Atoi(s.Port)
		ip, err := r.resolveFamily(ctx, s.Host)
		if err == nil {
			err = conn.Allow(s.Host, ip)
		}
		if err != nil {
			failure = err
			continue
		}
		if m, err := stunQuery(conn, netip.AddrPortFrom(ip, uint16(port)), wait); err == nil {
			mapped = append(mapped, m)
		}
	}
	if len(mapped) == 0 && failure != nil && (netx.AsBlocked(failure) != nil || errors.Is(failure, netx.ErrProxyRaw)) {
		res.Status, res.Reason = errStatus(failure), describe(failure)
		return res
	}
	var local netip.AddrPort
	if u, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		addr := r.n.Options().Source
		if !addr.IsValid() {
			_, addr, _ = netx.RouteInterface(r.n.Options().Family)
		}
		local = netip.AddrPortFrom(addr, uint16(u.Port))
	}
	return natResult(local, mapped)
}

func natResult(local netip.AddrPort, mapped []netip.AddrPort) probe.Result {
	res := probe.Result{Group: Transport, Service: "NAT (STUN)"}
	if len(mapped) == 0 {
		res.Status, res.Reason = probe.No, "no answer from STUN servers: UDP is blocked or filtered"
		return res
	}
	res.Status, res.Detail = probe.Yes, mapped[0].String()
	if local.Addr().IsValid() {
		res.Detail = local.String() + " → " + mapped[0].String()
	}
	switch {
	case local.Addr().IsValid() && local.Addr() == mapped[0].Addr():
		res.Reason = "no NAT: the local address is the public one"
	case len(mapped) > 1 && mapped[0] != mapped[1]:
		res.Status, res.Reason = probe.Partial, "symmetric NAT: each destination gets its own mapping, peer-to-peer needs a relay"
		res.Detail += ", " + mapped[1].String()
	case len(mapped) > 1:
		res.Reason = "NAT with one mapping for every destination: peer-to-peer can work"
	default:
		res.Reason = "NAT; the mapping type is unknown: one STUN server answered"
	}
	if cgnatRange.Contains(local.Addr()) {
		res.Reason += "; carrier-grade NAT (local address from 100.64.0.0/10)"
	}
	return res
}

func (r *runner) quic(ctx context.Context, host string) probe.Result {
	res := probe.Result{Group: Transport, Service: "QUIC " + host, Status: probe.Unknown}
	ip, err := r.resolveFamily(ctx, host)
	if err != nil {
		res.Reason = "DNS lookup failed: " + describe(err)
		if s := errStatus(err); s != probe.No {
			res.Status, res.Reason = s, describe(err)
		}
		return res
	}
	conn, err := r.n.ListenUDP(Module)
	if err != nil {
		res.Reason = describe(err)
		return res
	}
	defer conn.Close()
	if err := conn.Allow(host, ip); err != nil {
		res.Status, res.Reason = errStatus(err), describe(err)
		return res
	}
	ep, err := quic.NewEndpoint(conn, nil)
	if err != nil {
		res.Reason = describe(err)
		return res
	}
	defer func() {
		closing, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		ep.Close(closing)
	}()
	port, _ := strconv.Atoi(quicPort)
	dialCtx, cancel := r.timeoutCtx(ctx)
	defer cancel()
	qc, err := ep.Dial(dialCtx, "udp", netip.AddrPortFrom(ip, uint16(port)).String(), &quic.Config{
		TLSConfig: &tls.Config{ServerName: host, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13, RootCAs: quicRoots},
	})
	res.Detail = ip.String()
	switch {
	case err == nil:
		qc.Abort(nil)
		res.Status, res.Reason = probe.Yes, "QUIC handshake completed: HTTP/3 is reachable"
	case isX509(err):
		res.Status, res.Reason = probe.No, "invalid certificate in the QUIC handshake"
	case errors.Is(err, context.DeadlineExceeded) || netx.IsTimeout(err):
		res.Status, res.Reason = probe.No, "no QUIC answer on UDP "+quicPort+": blocked, filtered or not offered"
	default:
		res.Status, res.Reason = probe.No, "QUIC handshake failed: "+describe(err)
	}
	return res
}
