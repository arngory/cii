package route

import (
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
	Search: "Google", Social: "Social", CDN: "CDN", AI: "AI", Dev: "Dev", Messaging: "Messaging", Resolver: "DNS",
}

type Target struct {
	Name   string      `json:"name"`
	Host   string      `json:"host"`
	Expect uint        `json:"expect_asn,omitempty"`
	Group  probe.Group `json:"group"`
}

var Targets = []Target{
	{"Google", "www.google.com", 15169, Search},
	{"YouTube", "www.youtube.com", 15169, Search},
	{"Facebook", "www.facebook.com", 32934, Social},
	{"Instagram", "www.instagram.com", 32934, Social},
	{"WhatsApp", "web.whatsapp.com", 32934, Social},
	{"X", "x.com", 13414, Social},
	{"Telegram DC2", "149.154.167.51", 62041, Messaging},
	{"Telegram DC4", "149.154.167.91", 62041, Messaging},
	{"Discord", "discord.com", 13335, Messaging},
	{"Cloudflare", "www.cloudflare.com", 13335, CDN},
	{"Fastly", "www.fastly.com", 54113, CDN},
	{"Akamai", "www.akamai.com", 0, CDN},
	{"Amazon CloudFront", "d1.awsstatic.com", 16509, CDN},
	{"OpenAI API", "api.openai.com", 13335, AI},
	{"Claude", "claude.ai", 0, AI},
	{"GitHub", "github.com", 36459, Dev},
	{"Cloudflare DNS", "1.1.1.1", 13335, Resolver},
	{"Google DNS", "8.8.8.8", 15169, Resolver},
	{"Quad9", "9.9.9.9", 19281, Resolver},
}

func Rules(targets []Target) []netx.Rule {
	rules := make([]netx.Rule, 0, len(targets))
	for _, t := range targets {
		rules = append(rules, netx.Rule{Module: Module, Pattern: t.Host, Purpose: "route: path to " + t.Name})
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
