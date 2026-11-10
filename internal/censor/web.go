package censor

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

type target struct {
	Entry string
	Host  string
}

func parseTargets(entries []string) []target {
	var out []target
	for _, e := range entries {
		if t, ok := parseTarget(e); ok {
			out = append(out, t)
		}
	}
	return out
}

func parseTarget(entry string) (target, bool) {
	e := strings.TrimSpace(entry)
	lower := strings.ToLower(e)
	for _, p := range []string{"http://", "https://"} {
		if strings.HasPrefix(lower, p) {
			e = e[len(p):]
			break
		}
	}
	host := e
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(strings.TrimSuffix(strings.ToLower(host), "."), "[]")
	if host == "" || strings.ContainsAny(host, " \t@") {
		return target{}, false
	}
	return target{Entry: e, Host: host}, true
}

type phase int

const (
	phaseNone phase = iota
	phaseDNS
	phaseConnect
	phaseTLS
	phaseRequest
	phaseResponse
)

type outcome struct {
	Status   int
	Location string
	Err      error
	Phase    phase
}

func sameOrSub(host, base string) bool {
	return host == base || strings.HasSuffix(host, "."+base)
}

func sameSite(a, b string) bool {
	if sameOrSub(a, b) || sameOrSub(b, a) {
		return true
	}
	la, lb := strings.Split(a, "."), strings.Split(b, ".")
	if len(la) < 2 || len(lb) < 2 || net.ParseIP(a) != nil || net.ParseIP(b) != nil {
		return false
	}
	return strings.Join(la[len(la)-2:], ".") == strings.Join(lb[len(lb)-2:], ".")
}

func isBlockPage(loc string) bool {
	u, err := url.Parse(loc)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range blockPageHosts {
		if sameOrSub(host, h) {
			return true
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if bogus([]string{ip.String()}) {
			return true
		}
	} else {
		for _, label := range strings.Split(host, ".") {
			for _, m := range blockPageMarkers {
				if strings.Contains(label, m) {
					return true
				}
			}
		}
	}
	path := strings.ToLower(u.Path)
	return strings.Contains(path, "/blocked") || strings.Contains(path, "/zapret")
}

func (r *runner) fetch(ctx context.Context, scheme string, t target, follow bool) outcome {
	var o outcome
	_ = r.attempt(func() error {
		o = r.fetchOnce(ctx, scheme, t, follow)
		return o.Err
	})
	return o
}

func (r *runner) fetchOnce(ctx context.Context, scheme string, t target, follow bool) outcome {
	ctx, cancel := r.timeoutCtx(ctx)
	defer cancel()
	var mu sync.Mutex
	ph := phaseNone
	set := func(p phase, reset bool) {
		mu.Lock()
		if reset || p > ph {
			ph = p
		}
		mu.Unlock()
	}
	trace := &httptrace.ClientTrace{
		GetConn:  func(string) { set(phaseConnect, true) },
		DNSStart: func(httptrace.DNSStartInfo) { set(phaseDNS, true) },
		DNSDone: func(i httptrace.DNSDoneInfo) {
			if i.Err == nil {
				set(phaseConnect, false)
			}
		},
		ConnectDone: func(_, _ string, err error) {
			if err == nil {
				set(phaseRequest, false)
			}
		},
		TLSHandshakeStart: func() { set(phaseTLS, true) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				set(phaseRequest, false)
			}
		},
		GotConn:      func(httptrace.GotConnInfo) { set(phaseRequest, false) },
		WroteRequest: func(httptrace.WroteRequestInfo) { set(phaseResponse, false) },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, scheme+"://"+t.Entry, nil)
	if err != nil {
		return outcome{Err: err}
	}
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Sec-Fetch-Site", "none")
	c := r.n.HTTPClient(Module)
	c.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if !follow || len(via) >= 10 || !sameOrSub(strings.ToLower(next.URL.Hostname()), t.Host) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, err := c.Do(req)
	mu.Lock()
	o := outcome{Phase: ph}
	mu.Unlock()
	if err != nil {
		o.Err = err
		return o
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	o.Status = resp.StatusCode
	if loc, err := resp.Location(); err == nil {
		o.Location = loc.String()
	} else if l := resp.Header.Get("Location"); l != "" {
		o.Location = l
	}
	return o
}

func connectFailed(o outcome) bool {
	return o.Err != nil && o.Phase == phaseConnect && netx.AsBlocked(o.Err) == nil && !errors.Is(o.Err, netx.ErrProxyRaw)
}

func classifyHTTP(host string, o outcome) probe.Result {
	var res probe.Result
	if o.Err != nil {
		why := describe(o.Err)
		res.Status = errStatus(o.Err)
		switch {
		case res.Status != probe.No:
			res.Reason = why
		case o.Phase == phaseDNS:
			res.Status, res.Reason = probe.Unknown, "DNS lookup failed: "+why
		case o.Phase <= phaseConnect:
			res.Reason = "blocked by port: " + why
		case o.Phase == phaseTLS && isX509(o.Err):
			res.Reason = "invalid certificate (possible MITM or block page)"
			res.Detail = probe.Truncate(o.Err.Error(), 160)
		case o.Phase == phaseTLS:
			res.Reason = "TLS handshake " + why + " (likely DPI)"
		default:
			res.Reason = "blocked / " + why + " after request (likely DPI)"
		}
		return res
	}
	code := o.Status
	switch {
	case code >= 200 && code < 300:
		res.Status, res.Reason = probe.Yes, fmt.Sprintf("available (%d)", code)
	case code >= 300 && code < 400:
		loc := o.Location
		if loc == "" {
			loc = "<empty>"
		}
		res.Reason = fmt.Sprintf("redirected (%d) → %s", code, loc)
		u, err := url.Parse(o.Location)
		switch {
		case o.Location != "" && isBlockPage(o.Location):
			res.Status, res.Reason = probe.No, fmt.Sprintf("redirected to block page (%d) → %s", code, loc)
		case err == nil && o.Location != "" && sameSite(strings.ToLower(u.Hostname()), host):
			res.Status = probe.Yes
		default:
			res.Status = probe.Unknown
		}
	case code == http.StatusForbidden:
		res.Status, res.Reason = probe.No, "denied (403)"
	case code == http.StatusUnavailableForLegalReasons:
		res.Status, res.Reason = probe.No, "unavailable for legal reasons (451)"
	default:
		res.Status, res.Reason = probe.Unknown, fmt.Sprintf("responded with status code %d", code)
	}
	return res
}

func ValidProtocol(p string) bool {
	switch strings.ToLower(p) {
	case "", "both", "http", "https":
		return true
	}
	return false
}

func (r *runner) protocols() (http, https bool) {
	switch strings.ToLower(r.opts.Protocol) {
	case "http":
		return true, false
	case "https":
		return false, true
	}
	return true, true
}

func (r *runner) web(ctx context.Context, lists []webList) []probe.Result {
	var out []probe.Result
	for _, l := range lists {
		rows := make([][]probe.Result, len(l.Targets))
		var wg sync.WaitGroup
		for i, t := range l.Targets {
			wg.Go(func() { rows[i] = r.checkDomain(ctx, l.Group, t) })
		}
		wg.Wait()
		for _, rs := range rows {
			out = append(out, rs...)
		}
	}
	return out
}

func (r *runner) resolveTarget(ctx context.Context, host string) (string, *probe.Result) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.String(), nil
	}
	defer r.acquire()()
	pa, err := r.systemAnswer(ctx, host)
	switch {
	case errors.Is(err, netx.ErrProxyRaw):
		return "", nil
	case err != nil:
		return "", &probe.Result{Status: errStatus(err), Reason: "DNS lookup failed: " + describe(err)}
	case pa.NXDomain:
		return "", &probe.Result{Status: probe.Unknown, Reason: "domain does not exist"}
	case len(pa.IPs) == 0:
		rt := "A"
		if r.n.Options().Family == netx.IPv6 {
			rt = "AAAA"
		}
		return "", &probe.Result{Status: probe.Unknown, Reason: "no " + rt + " record"}
	}
	return pa.IPs[0], nil
}

func (r *runner) checkDomain(ctx context.Context, group probe.Group, t target) []probe.Result {
	ip, fail := r.resolveTarget(ctx, t.Host)
	if fail != nil {
		fail.Group, fail.Service = group, t.Host
		return []probe.Result{*fail}
	}
	doHTTP, doHTTPS := r.protocols()
	var httpO, httpsO outcome
	var wg sync.WaitGroup
	if doHTTP {
		wg.Go(func() {
			defer r.acquire()()
			httpO = r.fetch(ctx, "http", t, false)
		})
	}
	if doHTTPS {
		wg.Go(func() {
			defer r.acquire()()
			httpsO = r.fetch(ctx, "https", t, true)
		})
	}
	wg.Wait()
	viaProxy := r.n.Proxied()
	if doHTTP && doHTTPS && !viaProxy && connectFailed(httpO) && connectFailed(httpsO) {
		return []probe.Result{{Group: group, Service: t.Host, Status: probe.IPBlock,
			Reason: "blocked by IP: TCP 80 and 443 unreachable", Detail: ip}}
	}
	var out []probe.Result
	add := func(proto string, o outcome) {
		res := classifyHTTP(t.Host, o)
		res.Group, res.Service = group, t.Host+" "+proto
		res.Detail = joinDetail(ip, res.Detail)
		out = append(out, res)
	}
	if doHTTP {
		add("HTTP", httpO)
	}
	if doHTTPS {
		add("HTTPS", httpsO)
	}
	return out
}
