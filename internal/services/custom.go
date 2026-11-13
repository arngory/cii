package services

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/probe"
)

const (
	Custom       probe.Group = "custom"
	customPrefix             = "custom:"
	MaxCustom                = 32
	maxLabel                 = 40
)

var builtinGroups = map[string]probe.Group{"streaming": Streaming, "ai": AI, "web": Web}

func customGroup(title string) probe.Group {
	switch g, ok := builtinGroups[strings.ToLower(title)]; {
	case title == "" || strings.EqualFold(title, string(Custom)):
		return Custom
	case ok:
		return g
	}
	return probe.Group(customPrefix + title)
}

func customTitle(g probe.Group) string {
	if g == Custom {
		return "Custom"
	}
	if t, ok := strings.CutPrefix(string(g), customPrefix); ok {
		return t
	}
	return ""
}

func label(kind, s string) error {
	switch {
	case utf8.RuneCountInString(s) > maxLabel:
		return fmt.Errorf("%s %q is longer than %d characters", kind, s, maxLabel)
	case strings.ContainsFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }):
		return fmt.Errorf("%s %q has unprintable characters", kind, s)
	case strings.Contains(s, ";"):
		return fmt.Errorf("%s %q must not contain a semicolon", kind, s)
	}
	return nil
}

func builtin(name string) bool {
	same := func(c probe.Check) bool { return strings.EqualFold(c.Service, name) }
	return slices.ContainsFunc(Checks, same) || slices.ContainsFunc(Catalogs, func(c *Catalog) bool { return slices.ContainsFunc(c.checks, same) })
}

func CustomChecks(defs []config.ServiceCheck) ([]probe.Check, error) {
	if len(defs) > MaxCustom {
		return nil, fmt.Errorf("services: %d checks in the config, at most %d are supported", len(defs), MaxCustom)
	}
	var out []probe.Check
	seen := map[string]bool{}
	for i, d := range defs {
		u, err := url.Parse(strings.TrimSpace(d.URL))
		switch {
		case err != nil:
			return nil, fmt.Errorf("services[%d]: bad url", i)
		case u.Scheme != "https" && u.Scheme != "http":
			return nil, fmt.Errorf("services[%d]: url must start with https:// or http://", i)
		case u.Hostname() == "":
			return nil, fmt.Errorf("services[%d]: url has no host", i)
		case u.User != nil:
			return nil, fmt.Errorf("services[%d]: url must not carry credentials", i)
		}
		host := strings.ToLower(u.Hostname())
		if _, err := netip.ParseAddr(host); err != nil {
			if host, err = idna.Lookup.ToASCII(host); err != nil {
				return nil, fmt.Errorf("services[%d]: url has a host name that cannot be used", i)
			}
			if port := u.Port(); port != "" {
				u.Host = net.JoinHostPort(host, port)
			} else {
				u.Host = host
			}
		}
		name, group := strings.TrimSpace(d.Name), strings.TrimSpace(d.Group)
		if name == "" {
			name = host
		}
		if err := label("name", name); err != nil {
			return nil, fmt.Errorf("services[%d]: %w", i, err)
		}
		if err := label("group", group); err != nil {
			return nil, fmt.Errorf("services[%d]: %w", i, err)
		}
		if seen[name] {
			return nil, fmt.Errorf("services[%d]: name %q is used twice", i, name)
		}
		if builtin(name) {
			return nil, fmt.Errorf("services[%d]: %q is the name of a built-in check", i, name)
		}
		seen[name] = true
		for _, code := range d.Expect {
			if code < 100 || code > 599 {
				return nil, fmt.Errorf("services[%d]: expect %d is not an HTTP status", i, code)
			}
		}
		out = append(out, probe.Check{
			Module: Module, Service: name, Group: customGroup(group), Custom: true, Host: host,
			Requests: []probe.Request{{URL: strings.ReplaceAll(u.String(), "{ip}", "%7Bip%7D"), NoRedirect: true}},
			Eval:     customEval(d),
		})
	}
	return out, nil
}

func customEval(d config.ServiceCheck) func([]*probe.Response) []probe.Result {
	return func(rs []*probe.Response) []probe.Result {
		r := rs[0]
		expected := r.Status < 400
		if len(d.Expect) > 0 {
			expected = slices.Contains([]int(d.Expect), r.Status)
		}
		switch {
		case d.Blocked != "" && bytes.Contains(r.Body, []byte(d.Blocked)):
			return no("blocked marker found")
		case !expected && (r.Status == http.StatusTooManyRequests || r.Status >= 500):
			return unknown(r)
		case !expected:
			return no(fmt.Sprintf("HTTP %d", r.Status))
		case d.Contains != "" && !bytes.Contains(r.Body, []byte(d.Contains)):
			return no("marker not found")
		}
		return yes("")
	}
}
