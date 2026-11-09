package censor

type resolver struct {
	Name string
	IP   string
	DoH  string
	DoT  string
}

var resolvers = []resolver{
	{"Cloudflare", "1.1.1.1", "https://1.1.1.1/dns-query", "cloudflare-dns.com"},
	{"Cloudflare", "1.0.0.1", "https://1.0.0.1/dns-query", "cloudflare-dns.com"},
	{"Google", "8.8.8.8", "https://8.8.8.8/dns-query", "dns.google"},
	{"Google", "8.8.4.4", "https://8.8.4.4/dns-query", "dns.google"},
	{"Quad9", "9.9.9.9", "https://9.9.9.9/dns-query", "dns.quad9.net"},
	{"Quad9", "9.9.9.10", "https://dns10.quad9.net/dns-query", "dns10.quad9.net"},
	{"AdGuard", "94.140.14.14", "https://dns.adguard-dns.com/dns-query", "dns.adguard-dns.com"},
	{"AdGuard", "94.140.15.15", "https://dns.adguard-dns.com/dns-query", "dns.adguard-dns.com"},
	{"NextDNS", "45.90.28.65", "https://dns.nextdns.io/dns-query", "dns.nextdns.io"},
	{"NextDNS", "45.90.30.65", "https://dns.nextdns.io/dns-query", "dns.nextdns.io"},
	{"Yandex", "77.88.8.8", "https://common.dot.dns.yandex.net/dns-query", "common.dot.dns.yandex.net"},
	{"Yandex", "77.88.8.1", "https://common.dot.dns.yandex.net/dns-query", "common.dot.dns.yandex.net"},
}

const availabilityDomain = "rutracker.org"

var hijackDomains = []string{"rutracker.org", "linkedin.com", "flibusta.is"}

type telegramDC struct {
	ID int
	IP string
}

var telegramDCs = []telegramDC{
	{1, "149.154.175.50"},
	{2, "149.154.167.51"},
	{2, "95.161.76.100"},
	{3, "149.154.175.100"},
	{4, "149.154.167.91"},
	{5, "149.154.171.5"},
	{5, "91.108.56.130"},
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
