package risk

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

type Zone struct {
	Name     string
	Zone     string
	IPv6     bool
	Private  bool
	Homepage string
	codes    func(last byte) (listed bool, meaning string)
}

var Zones = []Zone{
	{Name: "Spamhaus ZEN", Zone: "zen.spamhaus.org", IPv6: true, Private: true, Homepage: "https://www.spamhaus.org/blocklists/zen-blocklist/", codes: spamhausCodes},
	{Name: "SpamCop", Zone: "bl.spamcop.net", Homepage: "https://www.spamcop.net/bl.shtml"},
	{Name: "PSBL", Zone: "psbl.surriel.com", Homepage: "https://psbl.org/"},
	{Name: "Mailspike", Zone: "bl.mailspike.net", Homepage: "https://mailspike.org/", codes: mailspikeCodes},
	{Name: "DroneBL", Zone: "dnsbl.dronebl.org", IPv6: true, Homepage: "https://dronebl.org/", codes: droneblCodes},
	{Name: "UCEPROTECT L1", Zone: "dnsbl-1.uceprotect.net", Homepage: "https://www.uceprotect.net/"},
	{Name: "s5h.net", Zone: "all.s5h.net", Homepage: "https://www.s5h.net/"},
}

func spamhausCodes(b byte) (bool, string) {
	switch b {
	case 2:
		return true, "SBL"
	case 3:
		return true, "SBL CSS"
	case 4, 5, 6, 7:
		return true, "XBL"
	case 9:
		return true, "SBL DROP"
	case 10, 11:
		return true, "PBL end-user range"
	}
	return true, ""
}

func mailspikeCodes(b byte) (bool, string) {
	switch {
	case b == 2:
		return true, "listed"
	case b >= 10 && b <= 14:
		return true, "reputation L" + strconv.Itoa(15-int(b))
	}
	return false, "reputation code"
}

var droneblTypes = map[byte]string{
	3: "IRC drone", 5: "bottler", 6: "spambot or drone", 7: "DDoS drone", 8: "SOCKS proxy",
	9: "HTTP proxy", 10: "proxychain", 11: "web page proxy", 12: "open DNS resolver", 13: "brute force attacker",
	14: "open Wingate proxy", 15: "compromised router", 16: "autorooting worm", 17: "botnet", 18: "DNS/MX on IRC",
	19: "abused VPN service", 255: "uncategorized",
}

func droneblCodes(b byte) (bool, string) { return true, droneblTypes[b] }

var spamhausErrors = map[string]string{
	"127.255.255.252": "malformed query",
	"127.255.255.254": "refused: query via public/open resolver",
	"127.255.255.255": "refused: query limit exceeded",
}

type MailOptions struct {
	Host string
	Port int
}

const DefaultMailHost = "gmail-smtp-in.l.google.com"

func (m MailOptions) host() string {
	if m.Host == "" {
		return DefaultMailHost
	}
	return m.Host
}

func (m MailOptions) port() int {
	if m.Port <= 0 {
		return 25
	}
	return m.Port
}

type Options struct {
	NoDNSBL    bool
	NoMail     bool
	Mail       MailOptions
	ResolvConf string
}

func Rules(opts Options) []netx.Rule {
	var rules []netx.Rule
	if !opts.NoDNSBL {
		for _, z := range Zones {
			rules = append(rules, netx.Rule{Module: Module, Pattern: "*." + z.Zone, Purpose: Module + ": DNSBL " + z.Name})
		}
	}
	if !opts.NoMail {
		rules = append(rules, netx.Rule{Module: Module, Pattern: opts.Mail.host(), Purpose: Module + ": outbound SMTP port 25"})
	}
	for _, zone := range []string{"in-addr.arpa", "ip6.arpa"} {
		rules = append(rules, netx.Rule{Module: Module, Pattern: "*." + zone, Purpose: Module + ": reverse DNS (PTR) of the checked address"})
	}
	return rules
}

const PTRService = "Reverse DNS"

func checkPTR(ctx context.Context, r resolver, ip netip.Addr) probe.Result {
	res := probe.Result{Group: Network, Service: PTRService}
	names, err := r.LookupAddr(ctx, Module, ip)
	var dnsErr *net.DNSError
	switch {
	case err == nil && len(names) > 0:
		res.Status, res.Detail = probe.Yes, strings.TrimSuffix(names[0], ".")
	case err == nil || errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		res.Status, res.Reason = probe.Unknown, "no PTR record"
	case netx.AsBlocked(err) != nil:
		res.Status, res.Reason = probe.Failed, "blocked by policy: *."+netx.ReverseZone(ip)
	case errors.As(err, &dnsErr):
		res.Status, res.Reason = probe.Failed, probe.Truncate("resolve: "+dnsErr.Err, 120)
	default:
		res.Status, res.Reason = probe.Failed, "lookup failed"
	}
	return res
}

type resolver interface {
	LookupHost(ctx context.Context, module, name string) ([]string, error)
	LookupAddr(ctx context.Context, module string, ip netip.Addr) ([]string, error)
}

type dialer interface {
	Dial(ctx context.Context, module, network, addr string) (net.Conn, error)
}

const proxyReason = "disabled while a proxy is in effect"

func Run(ctx context.Context, n *netx.Net, ip netip.Addr, opts Options) []probe.Result {
	if n.Proxied() {
		return proxied(ip, opts)
	}
	return run(ctx, n, n, n.Options().Timeout, ip, opts)
}

func proxied(ip netip.Addr, opts Options) []probe.Result {
	return slots(ip, opts, probe.Unknown, proxyReason)
}

func Placeholders(ip netip.Addr, opts Options) []probe.Result {
	return slots(ip, opts, probe.Pending, "")
}

func slots(ip netip.Addr, opts Options, status probe.Status, reason string) []probe.Result {
	var out []probe.Result
	if !opts.NoDNSBL {
		for _, z := range zonesFor(ip) {
			out = append(out, probe.Result{Group: DNSBL, Service: z.Zone, Status: status, Reason: reason})
		}
	}
	out = append(out, probe.Result{Group: Network, Service: PTRService, Status: status, Reason: reason})
	if !opts.NoMail {
		out = append(out, probe.Result{Group: Mail, Service: smtpService, Status: status, Reason: reason})
	}
	return out
}

func run(ctx context.Context, r resolver, d dialer, timeout time.Duration, ip netip.Addr, opts Options) []probe.Result {
	var out []probe.Result
	if !opts.NoDNSBL {
		out = append(out, checkDNSBL(ctx, r, ip, opts.ResolvConf)...)
	}
	out = append(out, checkPTR(ctx, r, ip))
	if !opts.NoMail {
		out = append(out, checkSMTP(ctx, d, opts.Mail, timeout))
	}
	return out
}

func zonesFor(ip netip.Addr) []Zone {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return nil
	}
	var out []Zone
	for _, z := range Zones {
		if ip.Is4() || z.IPv6 {
			out = append(out, z)
		}
	}
	return out
}

func checkDNSBL(ctx context.Context, r resolver, ip netip.Addr, resolvConf string) []probe.Result {
	zones := zonesFor(ip)
	if len(zones) == 0 {
		return nil
	}
	public := publicResolvers(resolvConf)
	rev := netx.ReverseName(ip)
	out := make([]probe.Result, len(zones))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, z := range zones {
		out[i] = probe.Result{Group: DNSBL, Service: z.Zone}
		if z.Private && public != "" {
			out[i].Status = probe.Unknown
			out[i].Reason = "skipped: system resolver " + public + " is public; " + z.Name + " requires your own resolver"
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			addrs, err := r.LookupHost(ctx, Module, rev+"."+z.Zone)
			out[i].Status, out[i].Detail, out[i].Reason = interpret(z, addrs, err)
		}()
	}
	wg.Wait()
	return out
}

func interpret(z Zone, addrs []string, err error) (probe.Status, string, string) {
	if err != nil {
		var dnsErr *net.DNSError
		switch {
		case errors.Is(err, netx.ErrProxyRaw):
			return probe.Unknown, "", proxyReason
		case netx.AsBlocked(err) != nil:
			return probe.Failed, "", "blocked by policy: *." + z.Zone
		case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
			return probe.Yes, "", ""
		case errors.As(err, &dnsErr) && dnsErr.IsTimeout, errors.Is(err, context.DeadlineExceeded):
			return probe.Failed, "", "timeout"
		case errors.As(err, &dnsErr):
			return probe.Failed, "", probe.Truncate("resolve: "+dnsErr.Err, 120)
		}
		return probe.Failed, "", probe.Truncate(err.Error(), 120)
	}
	var listed, other []string
	for _, a := range addrs {
		ip, perr := netip.ParseAddr(a)
		switch {
		case perr != nil || !ip.Is4():
			continue
		case strings.HasPrefix(a, "127.255.255."):
			meaning := spamhausErrors[a]
			if meaning == "" {
				meaning = "refused by list operator"
			}
			return probe.Unknown, a + " " + meaning, meaning
		case strings.HasPrefix(a, "127.0.0.") && ip.As4()[3] >= 2:
			last := ip.As4()[3]
			isListed, meaning := true, ""
			if z.codes != nil {
				isListed, meaning = z.codes(last)
			}
			code := a
			if meaning != "" {
				code += " " + meaning
			}
			if isListed {
				listed = append(listed, code)
			} else {
				other = append(other, code)
			}
		default:
			return probe.Unknown, a, "unexpected answer"
		}
	}
	switch {
	case len(listed) > 0:
		return probe.No, strings.Join(listed, ", "), ""
	case len(other) > 0:
		return probe.Yes, strings.Join(other, ", "), ""
	}
	return probe.Unknown, "", fmt.Sprintf("no IPv4 answer (%d records)", len(addrs))
}

var knownPublic = map[string]bool{
	"8.8.8.8": true, "8.8.4.4": true, "1.1.1.1": true, "1.0.0.1": true, "9.9.9.9": true, "149.112.112.112": true,
	"208.67.222.222": true, "208.67.220.220": true, "94.140.14.14": true, "94.140.15.15": true, "77.88.8.8": true,
	"77.88.8.1": true, "185.228.168.9": true, "76.76.2.0": true, "76.76.10.0": true,
	"2001:4860:4860::8888": true, "2001:4860:4860::8844": true, "2606:4700:4700::1111": true,
	"2606:4700:4700::1001": true, "2620:fe::fe": true, "2620:fe::9": true, "2620:119:35::35": true,
}

func publicResolvers(path string) string {
	if path == "" {
		path = "/etc/resolv.conf"
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var servers []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			servers = append(servers, fields[1])
		}
	}
	if len(servers) == 0 {
		return ""
	}
	for _, s := range servers {
		if !knownPublic[strings.SplitN(s, "%", 2)[0]] {
			return ""
		}
	}
	return servers[0]
}
