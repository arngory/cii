package censor

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

const Module = "censor"

const (
	DNS      probe.Group = "dns"
	DPI      probe.Group = "dpi"
	Geoblock probe.Group = "geoblock"
	Telegram probe.Group = "telegram"
)

var Modes = []string{"dns", "telegram", "dpi", "geoblock"}

type Options struct {
	Modes       []string
	DomainsFile string
	Domain      string
	Protocol    string
	Retries     int
}

func ValidMode(m string) bool {
	_, ok := canonicalMode(m)
	return ok
}

func canonicalMode(m string) ([]string, bool) {
	switch m = strings.ToLower(strings.TrimSpace(m)); m {
	case "all", "both":
		return Modes, true
	case "tg":
		return []string{"telegram"}, true
	case "dns", "telegram", "dpi", "geoblock":
		return []string{m}, true
	}
	return nil, false
}

func selectedModes(opts Options) (map[string]bool, []string) {
	set := map[string]bool{}
	var bad []string
	if len(opts.Modes) == 0 {
		for _, m := range Modes {
			set[m] = true
		}
		return set, nil
	}
	for _, m := range opts.Modes {
		ms, ok := canonicalMode(m)
		if !ok {
			bad = append(bad, m)
			continue
		}
		for _, x := range ms {
			set[x] = true
		}
	}
	return set, bad
}

type webList struct {
	Group   probe.Group
	Targets []target
}

func webLists(opts Options, modes map[string]bool) ([]webList, error) {
	if opts.Domain != "" || opts.DomainsFile != "" {
		if !modes["dpi"] && !modes["geoblock"] {
			return nil, nil
		}
		group := DPI
		if !modes["dpi"] {
			group = Geoblock
		}
		var entries []string
		if opts.Domain != "" {
			entries = []string{opts.Domain}
		} else {
			var err error
			if entries, err = readDomainsFile(opts.DomainsFile); err != nil {
				return nil, err
			}
		}
		return []webList{{group, parseTargets(entries)}}, nil
	}
	var out []webList
	if modes["dpi"] {
		out = append(out, webList{DPI, parseTargets(dpiDomains)})
	}
	if modes["geoblock"] {
		out = append(out, webList{Geoblock, parseTargets(geoblockDomains)})
	}
	return out, nil
}

func readDomainsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseDomainList(f)
}

func parseDomainList(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func Rules(opts Options) []netx.Rule {
	modes, _ := selectedModes(opts)
	var rules []netx.Rule
	add := func(host, purpose string) {
		rules = append(rules, netx.Rule{Module: Module, Pattern: host, Purpose: Module + ": " + purpose})
	}
	if modes["dns"] {
		for _, fam := range []netx.Family{netx.IPv4, netx.IPv6} {
			for _, r := range resolversFor(fam) {
				add(r.IP, "DNS resolver "+r.Name+" (UDP/53, DoT/853)")
				if u, err := url.Parse(r.DoH); err == nil {
					add(u.Hostname(), "DNS resolver "+r.Name+" (DoH)")
				}
			}
		}
		for _, d := range hijackDomains {
			add(d, "DNS hijack check via system resolver")
		}
	}
	if modes["telegram"] {
		for _, dc := range telegramDCs {
			add(dc.IP, "Telegram DC MTProto handshake")
			add(dc.IP6, "Telegram DC MTProto handshake")
		}
	}
	lists, _ := webLists(opts, modes)
	for _, l := range lists {
		for _, t := range l.Targets {
			add(t.Host, string(l.Group)+" check")
			if net.ParseIP(t.Host) == nil {
				add("*."+t.Host, string(l.Group)+" check (same-site redirects)")
			}
		}
	}

	return rules
}

type runner struct {
	n         *netx.Net
	opts      Options
	sem       chan struct{}
	retries   int
	resolvers []resolver
	dcs       []telegramDC
}

func newRunner(n *netx.Net, opts Options) *runner {
	fam := n.Options().Family
	return &runner{n: n, opts: opts, sem: make(chan struct{}, 8), retries: max(opts.Retries, 0), resolvers: resolversFor(fam), dcs: telegramDCsFor(fam)}
}

func (r *runner) acquire() func() {
	r.sem <- struct{}{}
	return func() { <-r.sem }
}

func (r *runner) attempt(fn func() error) error {
	var err error
	for i := 0; i <= r.retries; i++ {
		if err = fn(); err == nil || errors.Is(err, netx.ErrProxyRaw) || isPolicy(err) {
			return err
		}
	}
	return err
}

func (r *runner) timeoutCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, r.n.Options().Timeout)
}

func Run(ctx context.Context, n *netx.Net, opts Options) []probe.Result {
	modes, bad := selectedModes(opts)
	r := newRunner(n, opts)
	var out []probe.Result
	for _, m := range bad {
		out = append(out, probe.Result{Service: "mode " + m, Status: probe.Failed, Reason: "unknown mode"})
	}
	parts := make([][]probe.Result, 3)
	var wg sync.WaitGroup
	if modes["dns"] {
		wg.Go(func() { parts[0] = r.dns(ctx) })
	}
	if modes["telegram"] {
		wg.Go(func() { parts[1] = r.telegram(ctx) })
	}
	lists, err := webLists(opts, modes)
	if err != nil {
		group := DPI
		if !modes["dpi"] {
			group = Geoblock
		}
		out = append(out, probe.Result{Group: group, Service: opts.DomainsFile, Status: probe.Failed, Reason: probe.Truncate(err.Error(), 120)})
	}
	if len(lists) > 0 {
		wg.Go(func() { parts[2] = r.web(ctx, lists) })
	}
	wg.Wait()
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func isPolicy(err error) bool {
	var be *netx.BlockedError
	return errors.As(err, &be)
}

func isX509(err error) bool {
	var unk x509.UnknownAuthorityError
	var host x509.HostnameError
	var inv x509.CertificateInvalidError
	var ve *tls.CertificateVerificationError
	return errors.As(err, &unk) || errors.As(err, &host) || errors.As(err, &inv) || errors.As(err, &ve)
}

func describe(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, netx.ErrProxyRaw):
		return "disabled while a proxy is in effect"
	case isPolicy(err):
		var be *netx.BlockedError
		errors.As(err, &be)
		return "blocked by policy: " + be.Host
	case netx.IsTimeout(err):
		return "timeout"
	case netx.IsRefused(err):
		return "connection refused"
	case netx.IsReset(err):
		return "connection reset"
	case netx.IsUnreachable(err):
		return "network unreachable"
	case isX509(err):
		return "invalid certificate"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "connection closed"
	}
	err = netx.Redact(err)
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return probe.Truncate(err.Error(), 120)
}

func errStatus(err error) probe.Status {
	switch {
	case errors.Is(err, netx.ErrProxyRaw):
		return probe.Unknown
	case isPolicy(err):
		return probe.Failed
	}
	return probe.No
}
