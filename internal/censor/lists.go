package censor

import (
	"net/url"
	"strings"

	"github.com/arngory/cii/internal/netx"
)

type resolver struct {
	Name string
	IP   string
	IP6  string
	DoH  string
	DoT  string
}

var resolvers = []resolver{
	{Name: "Cloudflare", IP: "1.1.1.1", IP6: "2606:4700:4700::1111", DoT: "cloudflare-dns.com"},
	{Name: "Cloudflare", IP: "1.0.0.1", IP6: "2606:4700:4700::1001", DoT: "cloudflare-dns.com"},
	{Name: "Google", IP: "8.8.8.8", IP6: "2001:4860:4860::8888", DoT: "dns.google"},
	{Name: "Google", IP: "8.8.4.4", IP6: "2001:4860:4860::8844", DoT: "dns.google"},
	{Name: "Quad9", IP: "9.9.9.9", IP6: "2620:fe::fe", DoT: "dns.quad9.net"},
	{Name: "Quad9", IP: "9.9.9.10", IP6: "2620:fe::10", DoH: "https://dns10.quad9.net/dns-query", DoT: "dns10.quad9.net"},
	{Name: "AdGuard", IP: "94.140.14.14", IP6: "2a10:50c0::ad1:ff", DoH: "https://dns.adguard-dns.com/dns-query", DoT: "dns.adguard-dns.com"},
	{Name: "AdGuard", IP: "94.140.15.15", IP6: "2a10:50c0::ad2:ff", DoH: "https://dns.adguard-dns.com/dns-query", DoT: "dns.adguard-dns.com"},
	{Name: "NextDNS", IP: "45.90.28.65", IP6: "2a07:a8c0::", DoH: "https://dns.nextdns.io/dns-query", DoT: "dns.nextdns.io"},
	{Name: "NextDNS", IP: "45.90.30.65", IP6: "2a07:a8c1::", DoH: "https://dns.nextdns.io/dns-query", DoT: "dns.nextdns.io"},
	{Name: "Yandex", IP: "77.88.8.8", IP6: "2a02:6b8::feed:0ff", DoH: "https://common.dot.dns.yandex.net/dns-query", DoT: "common.dot.dns.yandex.net"},
	{Name: "Yandex", IP: "77.88.8.1", IP6: "2a02:6b8:0:1::feed:0ff", DoH: "https://common.dot.dns.yandex.net/dns-query", DoT: "common.dot.dns.yandex.net"},
}

func (rs resolver) forFamily(fam netx.Family) resolver {
	if fam == netx.IPv6 {
		rs.IP = rs.IP6
	}
	if rs.DoH == "" && rs.IP != "" {
		host := rs.IP
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		rs.DoH = (&url.URL{Scheme: "https", Host: host, Path: "/dns-query"}).String()
	}
	return rs
}

func resolversFor(fam netx.Family) []resolver {
	out := make([]resolver, 0, len(resolvers))
	for _, rs := range resolvers {
		if rs := rs.forFamily(fam); rs.IP != "" {
			out = append(out, rs)
		}
	}
	return out
}

const availabilityDomain = "rutracker.org"

var hijackDomains = []string{"rutracker.org", "linkedin.com", "flibusta.is"}

type telegramDC struct {
	ID  int
	IP  string
	IP6 string
}

var telegramDCs = []telegramDC{
	{1, "149.154.175.50", "2001:b28:f23d:f001::a"},
	{2, "149.154.167.51", "2001:67c:4e8:f002::a"},
	{2, "95.161.76.100", ""},
	{3, "149.154.175.100", "2001:b28:f23d:f003::a"},
	{4, "149.154.167.91", "2001:67c:4e8:f004::a"},
	{5, "149.154.171.5", "2001:b28:f23f:f005::a"},
	{5, "91.108.56.130", ""},
}

func telegramDCsFor(fam netx.Family) []telegramDC {
	out := make([]telegramDC, 0, len(telegramDCs))
	for _, dc := range telegramDCs {
		if fam == netx.IPv6 {
			dc.IP = dc.IP6
		}
		if dc.IP != "" {
			out = append(out, dc)
		}
	}
	return out
}

const telegramPort = "443"

var dpiDomains = []string{
	"youtube.com",
	"redirector.googlevideo.com/report_mapping?di=no",
	"discord.com",
	"instagram.com",
	"facebook.com",
	"x.com",
	"linkedin.com",
	"rutracker.org",
	"digitalocean.com",
	"amnezia.org",
	"getoutline.org",
	"mailfence.com",
	"flibusta.is",
	"rezka.ag",
	"api.telegram.org",
	"play.google.com",
	"github.com",
	"raw.githubusercontent.com",
}

var geoblockDomains = []string{
	"spotify.com",
	"netflix.com",
	"patreon.com",
	"swagger.io",
	"snyk.io",
	"mongodb.com",
	"autodesk.com",
	"graylog.org",
	"redis.io",
	"copilot.microsoft.com",
}

var blockPageHosts = []string{
	"warning.rt.ru",
	"zapret-info.gov.ru",
	"eais.rkn.gov.ru",
	"blocklist.rkn.gov.ru",
}

var blockPageMarkers = []string{"block", "zapret", "warning", "forbidden", "restrict", "censor", "rkn"}
