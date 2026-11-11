package route

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

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

func seqOf(round, target, ttl int) int { return round<<11 | target<<5 | ttl }

func unseq(seq int) (round, target, ttl int) { return seq >> 11, seq >> 5 & 0x3f, seq & 0x1f }

func traceICMP(ctx context.Context, n *netx.Net, o Options, paths []*Path) error {
	if len(paths) > 64 || o.MaxTTL > 31 || o.Rounds > 15 {
		return errors.New("too many targets or hops")
	}
	conn, err := n.ListenICMP4()
	if err != nil {
		var se *net.OpError
		if errors.As(err, &se) && errors.Is(se.Err, os.ErrPermission) || errors.Is(err, os.ErrPermission) {
			return errors.New("raw ICMP needs root or CAP_NET_RAW")
		}
		if errors.Is(err, netx.ErrProxyRaw) {
			return err
		}
		return errors.New(describe(err))
	}
	defer conn.Close()
	pc := conn.IPv4PacketConn()
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
			addr = ip.IP.String()
		}
		h := got[ti][ttl]
		if h.Addr == "" || rtt < h.RTTms {
			got[ti][ttl] = Hop{TTL: ttl, Addr: addr, RTTms: rtt}
		}
		if echo && (reached[ti] == 0 || ttl < reached[ti]) {
			reached[ti] = ttl
		}
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
			msg, err := icmp.ParseMessage(1, buf[:k])
			if err != nil {
				continue
			}
			switch body := msg.Body.(type) {
			case *icmp.Echo:
				if msg.Type == ipv4.ICMPTypeEchoReply && body.ID == id {
					record(body.Seq, from, now, true)
				}
			case *icmp.TimeExceeded:
				if eid, seq, ok := inner(body.Data); ok && eid == id {
					record(seq, from, now, false)
				}
			case *icmp.DstUnreach:
				if eid, seq, ok := inner(body.Data); ok && eid == id {
					record(seq, from, now, true)
				}
			}
		}
	}()
	var active []int
	for i, p := range paths {
		if !p.addr.IsValid() {
			continue
		}
		if err := n.AllowICMP(Module, p.Target.Host); err != nil {
			p.Error = describe(err)
			continue
		}
		active = append(active, i)
	}
	for round := 1; round <= o.Rounds && ctx.Err() == nil; round++ {
		for ttl := 1; ttl <= o.MaxTTL; ttl++ {
			if err := pc.SetTTL(ttl); err != nil {
				return err
			}
			for _, i := range active {
				mu.Lock()
				limit := reached[i]
				mu.Unlock()
				if limit > 0 && ttl > limit {
					continue
				}
				seq := seqOf(round, i, ttl)
				b, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("cii route")}}).Marshal(nil)
				mu.Lock()
				sent[seq] = time.Now()
				mu.Unlock()
				conn.WriteTo(b, &net.IPAddr{IP: paths[i].addr.AsSlice()})
			}
			time.Sleep(2 * time.Millisecond)
		}
		select {
		case <-ctx.Done():
		case <-time.After(o.Wait / time.Duration(max(o.Rounds, 1))):
		}
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

func inner(data []byte) (id, seq int, ok bool) {
	if len(data) < 20 {
		return 0, 0, false
	}
	ihl := int(data[0]&0x0f) * 4
	if len(data) < ihl+8 || data[9] != 1 {
		return 0, 0, false
	}
	icmpHdr := data[ihl:]
	if icmpHdr[0] != 8 {
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
				c, err := n.Dial(ctx, Module, "tcp", net.JoinHostPort(p.Target.Host, "443"))
				if err != nil {
					lastErr = err
					if errors.Is(err, netx.ErrProxyRaw) || netx.AsBlocked(err) != nil {
						break
					}
					continue
				}
				rtts = append(rtts, float64(time.Since(start).Microseconds())/1000)
				if ra, ok := c.RemoteAddr().(*net.TCPAddr); ok {
					if a, ok := netip.AddrFromSlice(ra.IP); ok {
						p.addr = a.Unmap()
					}
				}
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
