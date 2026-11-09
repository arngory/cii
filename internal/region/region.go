package region

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/refdata"
)

const Module = "region"

type Group string

const (
	GeoIP    Group = "geoip"
	Platform Group = "platform"
	CDN      Group = "cdn"
)

type Status string

const (
	OK      Status = "ok"
	Unknown Status = "unknown"
	IPBlock Status = "ipblock"
	Failed  Status = "error"
)

type Result struct {
	Group   Group  `json:"group"`
	Service string `json:"service"`
	Status  Status `json:"status"`
	Country string `json:"country,omitempty"`
	IATA    string `json:"iata,omitempty"`
	Node    string `json:"node,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type response struct {
	Status int
	Header http.Header
	Body   []byte
}

type Check struct {
	Service     string
	Group       Group
	Method      string
	URL         string
	ExtraHosts  []string
	Transport   netx.Family
	NoRedirect  bool
	BlockStatus int
	KeyOK       func(k config.Keys) bool
	Authorize   func(req *http.Request, k config.Keys)
	Extract     func(r *response) string
	Custom      func(r *response) []Result
}

func Select(k config.Keys) []Check {
	var out []Check
	for _, c := range Checks {
		if c.KeyOK == nil || c.KeyOK(k) {
			out = append(out, c)
		}
	}
	return out
}

func Rules(checks []Check) []netx.Rule {
	var rules []netx.Rule
	for _, c := range checks {
		u, err := url.Parse(c.URL)
		if err != nil {
			continue
		}
		for _, h := range append([]string{u.Hostname()}, c.ExtraHosts...) {
			rules = append(rules, netx.Rule{Module: Module, Pattern: h, Purpose: "region: " + c.Service})
		}
	}
	return rules
}

type Env struct {
	Nets map[netx.Family]*netx.Net
	Keys config.Keys
}

const maxBody = 4 << 20

func Run(ctx context.Context, env Env, f netx.Family, ip netip.Addr, checks []Check) []Result {
	results := make([][]Result, len(checks))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = runOne(ctx, env, f, ip, c)
		}()
	}
	wg.Wait()
	var out []Result
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}

func runOne(ctx context.Context, env Env, f netx.Family, ip netip.Addr, c Check) []Result {
	fail := func(reason string) []Result {
		return []Result{{Group: c.Group, Service: c.Service, Status: Failed, Reason: reason}}
	}
	transport := f
	if c.Transport != netx.Any {
		transport = c.Transport
	}
	n := env.Nets[transport]
	if n == nil {
		return fail("no " + transport.String() + " connectivity")
	}
	client := n.HTTPClient(Module)
	if c.NoRedirect {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	method := c.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.ReplaceAll(c.URL, "{ip}", ip.String()), nil)
	if err != nil {
		return fail(err.Error())
	}
	if c.Authorize != nil {
		c.Authorize(req, env.Keys)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fail(reason(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fail(reason(err))
	}
	r := &response{Status: resp.StatusCode, Header: resp.Header, Body: body}

	if c.Custom != nil {
		return c.Custom(r)
	}
	if c.BlockStatus != 0 && r.Status == c.BlockStatus {
		return []Result{{Group: c.Group, Service: c.Service, Status: IPBlock, Reason: fmt.Sprintf("HTTP %d", r.Status)}}
	}
	return []Result{countryResult(c.Group, c.Service, c.Extract(r), r.Status)}
}

func countryResult(g Group, service, raw string, status int) Result {
	res := Result{Group: g, Service: service}
	cc := strings.ToUpper(strings.TrimSpace(raw))
	switch {
	case refdata.IsCountry(cc):
		res.Status, res.Country = OK, cc
	case status == http.StatusTooManyRequests:
		res.Status, res.Reason = Failed, "rate limited"
	case status >= 400:
		res.Status, res.Reason = Failed, fmt.Sprintf("HTTP %d", status)
	default:
		res.Status = Unknown
		if cc != "" {
			res.Reason = "answered " + truncate(cc, 16)
		}
	}
	return res
}

func reason(err error) string {
	var be *netx.BlockedError
	switch {
	case errors.As(err, &be):
		return "blocked by policy: " + be.Host
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	err = netx.Redact(err)
	var ue *url.Error
	if errors.As(err, &ue) {
		if ue.Timeout() {
			return "timeout"
		}
		return truncate(ue.Err.Error(), 120)
	}
	return truncate(err.Error(), 120)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
