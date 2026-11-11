package netx

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/net/http/httpproxy"

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
	opts    Options
	policy  *Policy
	ledger  *ledger.Ledger
	tr      *http.Transport
	proxy   sync.Map
	proxied bool
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func envProxyConfig() *httpproxy.Config {
	all := firstEnv("ALL_PROXY", "all_proxy")
	c := &httpproxy.Config{
		HTTPProxy:  firstEnv("HTTP_PROXY", "http_proxy"),
		HTTPSProxy: firstEnv("HTTPS_PROXY", "https_proxy"),
		NoProxy:    firstEnv("NO_PROXY", "no_proxy"),
	}
	if c.HTTPProxy == "" {
		c.HTTPProxy = all
	}
	if c.HTTPSProxy == "" {
		c.HTTPSProxy = all
	}
	return c
}

func envProxy() bool {
	c := envProxyConfig()
	return c.HTTPProxy != "" || c.HTTPSProxy != ""
}

func (n *Net) Proxied() bool { return n.proxied }

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
	n := &Net{opts: opts, policy: policy, ledger: led, proxied: opts.Proxy != nil || envProxy()}

	proxy := http.ProxyURL(opts.Proxy)
	if opts.Proxy == nil {
		pf := envProxyConfig().ProxyFunc()
		proxy = func(r *http.Request) (*url.URL, error) { return pf(r.URL) }
	}
	n.tr = &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			u, err := proxy(r)
			if u != nil {
				n.proxy.Store(proxyAddr(u), struct{}{})
			}
			return u, err
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if _, viaProxy := n.proxy.Load(addr); viaProxy {
				return d.DialContext(ctx, "tcp", addr)
			}
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
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, &BlockedError{Module: g.module, Host: host}
	}
	g.n.ledger.Request(g.module, rule.Purpose, normalizeHost(host), req.URL.Scheme)
	if req.Header.Get("User-Agent") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", g.n.opts.UserAgent)
	}
	resp, err := g.n.tr.RoundTrip(req)
	if err != nil && !errors.Is(req.Context().Err(), context.Canceled) {
		g.n.ledger.Error(g.module, rule.Purpose, normalizeHost(host), req.URL.Scheme)
	}
	return resp, err
}

func proxyAddr(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	port := map[string]string{"http": "80", "https": "443", "socks5": "1080", "socks5h": "1080"}[u.Scheme]
	return net.JoinHostPort(u.Hostname(), port)
}
