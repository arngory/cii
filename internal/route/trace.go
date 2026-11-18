package route

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/arngory/cii/internal/netx"
)

func describe(err error) string {
	switch {
	case errors.Is(err, netx.ErrProxyRaw):
		return "disabled while a proxy is in effect"
	case netx.AsBlocked(err) != nil:
		return "blocked by policy"
	case netx.IsTimeout(err):
		return "timeout"
	case netx.IsRefused(err):
		return "connection refused"
	case netx.IsUnreachable(err):
		return "network unreachable"
	case errors.Is(err, os.ErrPermission):
		return "raw ICMP needs root or CAP_NET_RAW"
	}
	return netx.Redact(err).Error()
}

const sendGap = 500 * time.Microsecond

func seqOf(round, target, ttl int) int { return round<<11 | target<<5 | ttl }

func unseq(seq int) (round, target, ttl int) { return seq >> 11, seq >> 5 & 0x3f, seq & 0x1f }

func traceICMP(ctx context.Context, n *netx.Net, o Options, paths []*Path) error {
	if len(paths) > 64 || o.MaxTTL > 31 || o.Rounds > 15 {
		return errors.New("too many targets or hops")
	}
	var candidates []int
	for i, p := range paths {
		if p.addr.IsValid() {
			candidates = append(candidates, i)
		}
	}
	if len(candidates) == 0 {
		return errors.New("no target resolved")
	}
	v6 := n.Options().Family == netx.IPv6
	proto, echoType, replyType := 1, icmp.Type(ipv4.ICMPTypeEcho), icmp.Type(ipv4.ICMPTypeEchoReply)
	if v6 {
		proto, echoType, replyType = 58, ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	conn, err := n.ListenICMP(Module, v6)
	if err != nil {
		return errors.New(describe(err))
	}
	defer conn.Close()
	id := os.Getpid() & 0xffff
	var mu sync.Mutex
	sent := map[int]time.Time{}
	got := make([]map[int]Hop, len(paths))
	reached := make([]int, len(paths))
	for i := range got {
		got[i] = map[int]Hop{}
	}
	record := func(seq int, from net.Addr, at time.Time, echo bool) {
		mu.Lock()
		defer mu.Unlock()
		t0, ok := sent[seq]
		if !ok {
			return
		}
		_, ti, ttl := unseq(seq)
		if ti >= len(paths) {
			return
		}
		rtt := float64(at.Sub(t0).Microseconds()) / 1000
		addr := ""
		if ip, ok := from.(*net.IPAddr); ok {
			if a, ok := netip.AddrFromSlice(ip.IP); ok {
				addr = a.Unmap().String()
				echo = echo && a.Unmap() == paths[ti].addr
			}
		}
		if addr == "" {
			echo = false
		}
		h := got[ti][ttl]
		if h.Addr == "" || rtt < h.RTTms {
			got[ti][ttl] = Hop{TTL: ttl, Addr: addr, RTTms: rtt}
		}
		if echo && (reached[ti] == 0 || ttl < reached[ti]) {
			reached[ti] = ttl
		}
	}
	var active []int
	for _, i := range candidates {
		if err := conn.Allow(paths[i].host, paths[i].addr); err != nil {
			paths[i].Error = describe(err)
			continue
		}
		active = append(active, i)
	}
	if len(active) == 0 {
		return errors.New("no target may be traced")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			k, from, err := conn.ReadFrom(buf)
			now := time.Now()
			if err != nil {
				return
			}
			msg, err := icmp.ParseMessage(proto, buf[:k])
			if err != nil {
				continue
			}
			switch body := msg.Body.(type) {
			case *icmp.Echo:
				if msg.Type == replyType && body.ID == id {
					record(body.Seq, from, now, true)
				}
			case *icmp.TimeExceeded:
				if eid, seq, ok := inner(body.Data, v6); ok && eid == id {
					record(seq, from, now, false)
				}
			case *icmp.DstUnreach:
				if eid, seq, ok := inner(body.Data, v6); ok && eid == id {
					record(seq, from, now, true)
				}
			}
		}
	}()
	sentOK := 0
	var sendErr error
	for round := 1; round <= o.Rounds && ctx.Err() == nil; round++ {
		for k := range active {
			i := active[(k+round)%len(active)]
			for ttl := 1; ttl <= o.MaxTTL; ttl++ {
				mu.Lock()
				limit := reached[i]
				mu.Unlock()
				if limit > 0 && ttl > limit {
					break
				}
				seq := seqOf(round, i, ttl)
				b, _ := (&icmp.Message{Type: echoType, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("cii route")}}).Marshal(nil)
				mu.Lock()
				sent[seq] = time.Now()
				mu.Unlock()
				if err := conn.WriteTo(b, paths[i].addr, ttl); err != nil {
					if sendErr == nil {
						sendErr = err
					}
				} else {
					sentOK++
				}
				time.Sleep(sendGap)
			}
		}
		if sentOK == 0 && sendErr != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(o.Wait / time.Duration(max(o.Rounds, 1))):
		}
	}
	if sentOK == 0 && sendErr != nil {
		conn.SetReadDeadline(time.Now())
		<-done
		return fmt.Errorf("send: %s", describe(sendErr))
	}
	select {
	case <-ctx.Done():
	case <-time.After(o.Wait):
	}
	conn.SetReadDeadline(time.Now())
	<-done
	mu.Lock()
	defer mu.Unlock()
	for _, i := range active {
		p := paths[i]
		limit := reached[i]
		if limit == 0 {
			limit = o.MaxTTL
		}
		for ttl := 1; ttl <= limit; ttl++ {
			h, ok := got[i][ttl]
			if !ok {
				h = Hop{TTL: ttl}
			}
			p.Hops = append(p.Hops, h)
		}
		for len(p.Hops) > 0 && p.Hops[len(p.Hops)-1].Addr == "" {
			p.Hops = p.Hops[:len(p.Hops)-1]
		}
		if reached[i] > 0 {
			p.RTTms, p.Samples, p.Timing = got[i][reached[i]].RTTms, 1, "icmp"
		}
	}
	return nil
}

func inner(data []byte, v6 bool) (id, seq int, ok bool) {
	ihl, echo := 40, byte(128)
	if v6 {
		if len(data) < 48 || data[6] != 58 {
			return 0, 0, false
		}
	} else {
		if len(data) < 20 {
			return 0, 0, false
		}
		ihl, echo = int(data[0]&0x0f)*4, 8
		if len(data) < ihl+8 || data[9] != 1 {
			return 0, 0, false
		}
	}
	icmpHdr := data[ihl:]
	if icmpHdr[0] != echo {
		return 0, 0, false
	}
	return int(icmpHdr[4])<<8 | int(icmpHdr[5]), int(icmpHdr[6])<<8 | int(icmpHdr[7]), true
}

func timeTCP(ctx context.Context, n *netx.Net, paths []*Path) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, p := range paths {
		if !p.addr.IsValid() || p.RTTms > 0 {
			continue
		}
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			var rtts []float64
			var lastErr error
			for range 4 {
				start := time.Now()
				c, err := n.DialAddr(ctx, Module, "tcp", p.host, p.addr, "443")
				if err != nil {
					lastErr = err
					if errors.Is(err, netx.ErrProxyRaw) || errors.Is(err, netx.ErrAddrNotOfHost) || netx.AsBlocked(err) != nil {
						break
					}
					continue
				}
				rtts = append(rtts, float64(time.Since(start).Microseconds())/1000)
				c.Close()
				time.Sleep(50 * time.Millisecond)
			}
			if len(rtts) == 0 {
				p.Error = describe(lastErr)
				return
			}
			sort.Float64s(rtts)
			p.RTTms, p.Samples, p.Timing = rtts[0], len(rtts), "tcp"
		})
	}
	wg.Wait()
}

func floor(paths []*Path) float64 {
	var rtts []float64
	for _, p := range paths {
		if p.RTTms > 0 {
			rtts = append(rtts, p.RTTms)
		}
	}
	if len(rtts) == 0 {
		return 0
	}
	slices.Sort(rtts)
	if len(rtts) >= 4 {
		return rtts[1]
	}
	return rtts[0]
}
