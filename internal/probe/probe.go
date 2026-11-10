package probe

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

type Tier int

const (
	TierA Tier = iota
	TierB
)

type Group string

type Status string

const (
	OK      Status = "ok"
	Yes     Status = "yes"
	No      Status = "no"
	Partial Status = "partial"
	Unknown Status = "unknown"
	IPBlock Status = "ipblock"
	Failed  Status = "error"
)

type Result struct {
	Group    Group  `json:"group"`
	Service  string `json:"service"`
	Status   Status `json:"status"`
	Country  string `json:"country,omitempty"`
	IATA     string `json:"iata,omitempty"`
	Node     string `json:"node,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Extended bool   `json:"extended,omitempty"`
	Facts    *Facts `json:"facts,omitempty"`
}

type Request struct {
	Method     string
	URL        string
	Body       string
	BodyFrom   func(ip netip.Addr, prev []*Response) (string, error)
	Header     map[string]string
	NoRedirect bool
}

type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

type Check struct {
	Module     string
	Service    string
	Group      Group
	Tier       Tier
	Requests   []Request
	ExtraHosts []string
	Transport  netx.Family
	KeyOK      func(k config.Keys) bool
	Authorize  func(req *http.Request, k config.Keys)
	Eval       func(rs []*Response) []Result
}

func Get(rawURL string) []Request { return []Request{{URL: rawURL}} }

func Select(module string, checks []Check, k config.Keys, extended bool) []Check {
	var out []Check
	for _, c := range checks {
		if (c.Tier == TierA || extended) && (c.KeyOK == nil || c.KeyOK(k)) {
			c.Module = module
			out = append(out, c)
		}
	}
	return out
}

func Rules(checks []Check) []netx.Rule {
	var rules []netx.Rule
	for _, c := range checks {
		hosts := append([]string(nil), c.ExtraHosts...)
		for _, r := range c.Requests {
			if u, err := url.Parse(r.URL); err == nil {
				hosts = append(hosts, u.Hostname())
			}
		}
		for _, h := range hosts {
			rules = append(rules, netx.Rule{Module: c.Module, Pattern: h, Purpose: c.Module + ": " + c.Service})
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
			results[i] = complete(c, runOne(ctx, env, f, ip, c))
		}()
	}
	wg.Wait()
	var out []Result
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}

func complete(c Check, rs []Result) []Result {
	for i := range rs {
		if rs[i].Group == "" {
			rs[i].Group = c.Group
		}
		if rs[i].Service == "" {
			rs[i].Service = c.Service
		}
		rs[i].Extended = c.Tier == TierB
	}
	return rs
}

func runOne(ctx context.Context, env Env, f netx.Family, ip netip.Addr, c Check) []Result {
	transport := f
	if c.Transport != netx.Any {
		transport = c.Transport
	}
	n := env.Nets[transport]
	if n == nil {
		return Fail("no " + transport.String() + " connectivity")
	}
	var responses []*Response
	for _, r := range c.Requests {
		if r.BodyFrom != nil {
			if len(responses) > 0 {
				if res, failed := HTTPFailure(responses[len(responses)-1].Status); failed {
					return []Result{res}
				}
			}
			body, err := r.BodyFrom(ip, responses)
			if err != nil {
				return []Result{{Status: Unknown, Reason: Truncate(err.Error(), 120)}}
			}
			r.Body = body
		}
		resp, err := do(ctx, n.HTTPClient(c.Module), env.Keys, ip, c, r)
		if err != nil {
			return Fail(reason(err))
		}
		responses = append(responses, resp)
	}
	return c.Eval(responses)
}

func do(ctx context.Context, client *http.Client, keys config.Keys, ip netip.Addr, c Check, r Request) (*Response, error) {
	if r.NoRedirect {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if r.Body != "" {
		body = strings.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.ReplaceAll(r.URL, "{ip}", ip.String()), body)
	if err != nil {
		return nil, err
	}
	for k, v := range r.Header {
		req.Header.Set(k, v)
	}
	if c.Authorize != nil {
		c.Authorize(req, keys)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: data}, nil
}

func Fail(reason string) []Result {
	return []Result{{Status: Failed, Reason: reason}}
}

func HTTPFailure(status int) (Result, bool) {
	switch {
	case status == http.StatusTooManyRequests:
		return Result{Status: Failed, Reason: "rate limited"}, true
	case status >= 400:
		return Result{Status: Failed, Reason: fmt.Sprintf("HTTP %d", status)}, true
	}
	return Result{}, false
}

func CountryResult(raw string, status int) Result {
	cc := strings.ToUpper(strings.TrimSpace(raw))
	if refdata.IsCountry(cc) {
		return Result{Status: OK, Country: cc}
	}
	if r, failed := HTTPFailure(status); failed {
		return r
	}
	r := Result{Status: Unknown}
	if cc != "" {
		r.Reason = "answered " + Truncate(cc, 16)
	}
	return r
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
		return Truncate(ue.Err.Error(), 120)
	}
	return Truncate(err.Error(), 120)
}

func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
