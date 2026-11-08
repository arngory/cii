package netx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/version"
)

type Family int

const (
	Any Family = iota
	IPv4
	IPv6
)

func (f Family) String() string {
	switch f {
	case IPv4:
		return "ipv4"
	case IPv6:
		return "ipv6"
	}
	return "any"
}

func (f Family) network(base string) string {
	switch f {
	case IPv4:
		return base + "4"
	case IPv6:
		return base + "6"
	}
	return base
}

type Options struct {
	Family    Family
	Source    netip.Addr
	Proxy     *url.URL
	Timeout   time.Duration
	UserAgent string
}

func DefaultUserAgent() string {
	return version.Name + "/" + version.Version + " (+https://github.com/arngory/cii)"
}

type Net struct {
	opts   Options
	policy *Policy
	ledger *ledger.Ledger
	dialer *net.Dialer
	tr     *http.Transport
}

func New(opts Options, policy *Policy, led *ledger.Ledger) *Net {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.UserAgent == "" {
		opts.UserAgent = DefaultUserAgent()
	}
	d := &net.Dialer{Timeout: opts.Timeout, KeepAlive: 30 * time.Second}
	if opts.Source.IsValid() {
		d.LocalAddr = &net.TCPAddr{IP: opts.Source.AsSlice()}
	}
	n := &Net{opts: opts, policy: policy, ledger: led, dialer: d}

	proxy := http.ProxyFromEnvironment
	if opts.Proxy != nil {
		proxy = http.ProxyURL(opts.Proxy)
	}
	n.tr = &http.Transport{
		Proxy: proxy,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, opts.Family.network("tcp"), addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   opts.Timeout,
		ResponseHeaderTimeout: opts.Timeout,
	}
	return n
}

func (n *Net) Options() Options { return n.opts }

func (n *Net) Policy() *Policy { return n.policy }

func (n *Net) HTTPClient(module string) *http.Client {
	return &http.Client{
		Timeout:   n.opts.Timeout,
		Transport: &guard{n: n, module: module},
	}
}

type guard struct {
	n      *Net
	module string
}

func (g *guard) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	rule, ok := g.n.policy.Match(g.module, host)
	if !ok {
		g.n.ledger.Blocked(g.module, "not declared", normalizeHost(host), req.URL.Scheme)
		return nil, &BlockedError{Module: g.module, Host: host}
	}
	g.n.ledger.Request(g.module, rule.Purpose, normalizeHost(host), req.URL.Scheme)
	if req.Header.Get("User-Agent") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", g.n.opts.UserAgent)
	}
	resp, err := g.n.tr.RoundTrip(req)
	if err != nil {
		g.n.ledger.Error(g.module, rule.Purpose, normalizeHost(host), req.URL.Scheme)
	}
	return resp, err
}

var ErrProxyRaw = errors.New("raw connections are disabled while a proxy is configured")

func (n *Net) Dial(ctx context.Context, module, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	rule, ok := n.policy.Match(module, host)
	if !ok {
		n.ledger.Blocked(module, "not declared", normalizeHost(host), network)
		return nil, &BlockedError{Module: module, Host: host}
	}
	if n.opts.Proxy != nil {
		n.ledger.Blocked(module, rule.Purpose, normalizeHost(host), network)
		return nil, ErrProxyRaw
	}
	n.ledger.Request(module, rule.Purpose, normalizeHost(host), network)
	d := *n.dialer
	if n.opts.Source.IsValid() && (network == "udp" || network == "udp4" || network == "udp6") {
		d.LocalAddr = &net.UDPAddr{IP: n.opts.Source.AsSlice()}
	}
	if n.opts.Family != Any {
		network = n.opts.Family.network(trimFamily(network))
	}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		n.ledger.Error(module, rule.Purpose, normalizeHost(host), network)
	}
	return c, err
}

func trimFamily(network string) string {
	switch network {
	case "tcp4", "tcp6":
		return "tcp"
	case "udp4", "udp6":
		return "udp"
	}
	return network
}
