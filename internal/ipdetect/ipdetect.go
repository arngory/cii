package ipdetect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/arngory/cii/internal/netx"
)

const Module = "ipdetect"

type Format string

type Provider struct {
	Name   string `yaml:"name" json:"name"`
	URL4   string `yaml:"url4" json:"url4,omitempty"`
	URL6   string `yaml:"url6" json:"url6,omitempty"`
	Format Format `yaml:"format" json:"format"`
}

var DefaultProviders = []Provider{
	{Name: "cloudflare", URL4: "https://www.cloudflare.com/cdn-cgi/trace", URL6: "https://www.cloudflare.com/cdn-cgi/trace", Format: "trace"},
	{Name: "ipify", URL4: "https://api.ipify.org", URL6: "https://api6.ipify.org", Format: "plain"},
	{Name: "icanhazip", URL4: "https://ipv4.icanhazip.com", URL6: "https://ipv6.icanhazip.com", Format: "plain"},
}

func Rules(providers []Provider) []netx.Rule {
	var rules []netx.Rule
	for _, p := range providers {
		for _, raw := range []string{p.URL4, p.URL6} {
			if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
				rules = append(rules, netx.Rule{Module: Module, Pattern: u.Hostname(), Purpose: "public IP echo (" + p.Name + ")"})
			}
		}
	}
	return rules
}

type Address struct {
	Address   netip.Addr   `json:"address"`
	Source    string       `json:"source"`
	Interface []netip.Addr `json:"interface,omitempty"`
	Error     string       `json:"error,omitempty"`
}

type Options struct {
	Providers []Provider
	Offline   bool
	Iface     string
	Source    netip.Addr
}

func Detect(ctx context.Context, n *netx.Net, f netx.Family, o Options) Address {
	var res Address
	var candidates []netip.Addr
	switch {
	case n.Proxied():
	case o.Iface != "" || !o.Source.IsValid():
		candidates, _ = netx.InterfaceAddrs(o.Iface)
	default:
		candidates = []netip.Addr{o.Source}
	}
	for _, a := range candidates {
		if a.IsValid() && a.Is4() == (f == netx.IPv4) && netx.IsPublic(a) {
			res.Interface = append(res.Interface, a)
		}
	}
	if o.Offline {
		if len(res.Interface) > 0 {
			res.Address, res.Source = res.Interface[0], "interface"
		} else {
			res.Error = "offline: no public address on local interfaces"
		}
		return res
	}
	client := n.HTTPClient(Module)
	var errs []string
	for _, p := range o.Providers {
		raw := p.URL4
		if f == netx.IPv6 {
			raw = p.URL6
		}
		if raw == "" {
			continue
		}
		a, err := query(ctx, client, raw, p.Format)
		if err == nil && a.Is4() != (f == netx.IPv4) {
			err = fmt.Errorf("returned an %s address", familyOf(a))
		}
		if err != nil {
			errs = append(errs, p.Name+": "+err.Error())
			continue
		}
		res.Address, res.Source = a, "echo:"+p.Name
		return res
	}
	if len(res.Interface) > 0 {
		res.Address, res.Source = res.Interface[0], "interface"
		return res
	}
	if len(errs) == 0 {
		res.Error = "no providers configured for " + f.String()
	} else {
		res.Error = strings.Join(errs, "; ")
	}
	return res
}

func familyOf(a netip.Addr) string {
	if a.Is4() {
		return "IPv4"
	}
	return "IPv6"
}

func query(ctx context.Context, c *http.Client, raw string, f Format) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return netip.Addr{}, netx.Redact(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return netip.Addr{}, netx.Redact(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return netip.Addr{}, err
	}
	return Parse(body, f)
}

func Parse(body []byte, f Format) (netip.Addr, error) {
	var s string
	switch {
	case f == "" || f == "plain":
		s = string(body)
	case f == "trace":
		for _, line := range strings.Split(string(body), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
				s = v
				break
			}
		}
	case strings.HasPrefix(string(f), "json:"):
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			return netip.Addr{}, fmt.Errorf("bad JSON: %w", err)
		}
		v, _ := m[strings.TrimPrefix(string(f), "json:")].(string)
		s = v
	default:
		return netip.Addr{}, fmt.Errorf("unknown format %q", f)
	}
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("no address in response")
	}
	return a.Unmap(), nil
}
