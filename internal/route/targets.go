package route

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

const Module = "route"

const (
	Search    probe.Group = "route-search"
	Social    probe.Group = "route-social"
	CDN       probe.Group = "route-cdn"
	AI        probe.Group = "route-ai"
	Dev       probe.Group = "route-dev"
	Messaging probe.Group = "route-messaging"
	Resolver  probe.Group = "route-dns"
)

var Groups = map[probe.Group]string{
	Search: "Google", Social: "Social", CDN: "CDN", AI: "AI", Dev: "Dev", Messaging: "Messaging", Resolver: "DNS", Custom: "Custom",
}

type Target struct {
	Name    string      `json:"name"`
	Host    string      `json:"host"`
	Expect  uint        `json:"expect_asn,omitempty"`
	Group   probe.Group `json:"group"`
	Unicast bool        `json:"unicast,omitempty"`
	Host6   string      `json:"host6,omitempty"`
}

func (t Target) hostFor(f netx.Family) string {
	if f == netx.IPv6 && t.Host6 != "" {
		return t.Host6
	}
	return t.Host
}

var Targets = []Target{
	{Name: "Google", Host: "www.google.com", Expect: 15169, Group: Search},
	{Name: "YouTube", Host: "www.youtube.com", Expect: 15169, Group: Search},
	{Name: "Facebook", Host: "www.facebook.com", Expect: 32934, Group: Social},
	{Name: "Instagram", Host: "www.instagram.com", Expect: 32934, Group: Social},
	{Name: "WhatsApp", Host: "web.whatsapp.com", Expect: 32934, Group: Social},
	{Name: "X", Host: "x.com", Expect: 13335, Group: Social},
	{Name: "Telegram DC2", Host: "149.154.167.51", Host6: "2001:67c:4e8:f002::a", Expect: 62041, Group: Messaging, Unicast: true},
	{Name: "Telegram DC4", Host: "149.154.167.91", Host6: "2001:67c:4e8:f004::a", Expect: 62041, Group: Messaging, Unicast: true},
	{Name: "Discord", Host: "discord.com", Expect: 13335, Group: Messaging},
	{Name: "Cloudflare", Host: "www.cloudflare.com", Expect: 13335, Group: CDN},
	{Name: "Fastly", Host: "www.fastly.com", Expect: 54113, Group: CDN},
	{Name: "Akamai", Host: "www.akamai.com", Expect: 0, Group: CDN},
	{Name: "Amazon CloudFront", Host: "d1.awsstatic.com", Expect: 16509, Group: CDN},
	{Name: "OpenAI API", Host: "api.openai.com", Expect: 13335, Group: AI},
	{Name: "Claude", Host: "claude.ai", Expect: 0, Group: AI},
	{Name: "GitHub", Host: "github.com", Expect: 36459, Group: Dev, Unicast: true},
	{Name: "Cloudflare DNS", Host: "1.1.1.1", Host6: "2606:4700:4700::1111", Expect: 13335, Group: Resolver},
	{Name: "Google DNS", Host: "8.8.8.8", Host6: "2001:4860:4860::8888", Expect: 15169, Group: Resolver},
	{Name: "Quad9", Host: "9.9.9.9", Host6: "2620:fe::fe", Expect: 19281, Group: Resolver},
}

func Rules(targets []Target) []netx.Rule {
	rules := make([]netx.Rule, 0, len(targets))
	for _, t := range targets {
		rules = append(rules, netx.Rule{Module: Module, Pattern: t.Host, Purpose: "route: path to " + t.Name})
		if t.Host6 != "" {
			rules = append(rules, netx.Rule{Module: Module, Pattern: t.Host6, Purpose: "route: path to " + t.Name})
		}
	}
	return rules
}

var transitASNs = map[uint]string{
	174: "Cogent", 209: "Lumen", 701: "Verizon", 1239: "Sprint", 1273: "Vodafone", 1299: "Arelion",
	2828: "Verizon", 2914: "NTT", 3257: "GTT", 3320: "DTAG", 3356: "Lumen", 3491: "PCCW", 3549: "Lumen",
	4637: "Telstra", 5511: "Orange", 6453: "Tata", 6461: "Zayo", 6762: "Sparkle", 6830: "Liberty Global",
	6939: "Hurricane Electric", 7018: "AT&T", 7473: "Singtel", 9002: "RETN", 12389: "Rostelecom",
	12956: "Telxius", 20485: "TransTelecom", 31133: "MegaFon", 4134: "China Telecom", 4837: "China Unicom",
}

const Custom probe.Group = "route-custom"

const MaxTargets = 64

var hostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

func ParseTargets(spec string) (targets []Target, add bool, err error) {
	spec = strings.TrimSpace(spec)
	if rest, ok := strings.CutPrefix(spec, "+"); ok {
		add, spec = true, rest
	}
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		t := Target{Group: Custom, Unicast: true}
		if name, rest, ok := strings.Cut(entry, "="); ok {
			t.Name, entry = strings.TrimSpace(name), strings.TrimSpace(rest)
		}
		if host, asn, ok := strings.Cut(entry, "@"); ok {
			n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(asn)), "AS"), 10, 32)
			if err != nil || n == 0 {
				return nil, false, fmt.Errorf("target %q: bad AS number %q", entry, asn)
			}
			t.Expect, entry = uint(n), strings.TrimSpace(host)
		}
		t.Host = strings.ToLower(strings.TrimSuffix(entry, "."))
		if a, err := netip.ParseAddr(t.Host); err == nil {
			t.Host = a.Unmap().String()
		} else if !hostPattern.MatchString(t.Host) {
			return nil, false, fmt.Errorf("target %q: expected [name=]host[@asn] with a host name or an IP address", entry)
		}
		if t.Name == "" {
			t.Name = t.Host
		}
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		return nil, false, errors.New("no targets given")
	}
	return targets, add, nil
}

func Merge(base, extra []Target) ([]Target, error) {
	out := append([]Target(nil), base...)
	for _, t := range extra {
		if slices.ContainsFunc(out, func(x Target) bool { return x.Host == t.Host }) {
			continue
		}
		if slices.ContainsFunc(out, func(x Target) bool { return strings.EqualFold(x.Name, t.Name) }) {
			return nil, fmt.Errorf("route target name %q is already taken; give %s another name", t.Name, t.Host)
		}
		out = append(out, t)
	}
	if len(out) > MaxTargets {
		return nil, fmt.Errorf("too many route targets: %d, the limit is %d", len(out), MaxTargets)
	}
	return out, nil
}
