package report

import (
	"bytes"
	"net/netip"
	"time"

	"github.com/arngory/cii/internal/bench"
	"github.com/arngory/cii/internal/censor"
	"github.com/arngory/cii/internal/geodb"
	"github.com/arngory/cii/internal/ipdetect"
	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/risk"
	"github.com/arngory/cii/internal/services"
)

func demoFacts(usage, company string, score, level int, flags map[probe.Flag]bool) *probe.Facts {
	f := &probe.Facts{Usage: usage, Company: company, Flags: flags}
	if score >= 0 {
		f.Score, f.Level = &score, &level
	}
	return f
}

func Demo(mode string) *Report {
	r := New(mode)
	r.GeneratedAt = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	geo := []geodb.Record{
		{Source: "dbip-country-lite", Country: "DE", CountryName: "Germany"},
		{Source: "dbip-asn-lite", ASN: 3320, ASOrg: "Deutsche Telekom AG"},
	}
	v4 := NewHost(ipdetect.Address{Address: netip.MustParseAddr("203.0.113.7"), Source: "echo:cloudflare+ipify"}, geo)
	clean := map[probe.Flag]bool{probe.Proxy: false, probe.VPN: false, probe.Tor: false, probe.Hosting: false}
	v4.SetServices([]probe.Result{
		{Group: services.Streaming, Service: "Netflix", Status: probe.Yes, Country: "DE"},
		{Group: services.Streaming, Service: "Prime Video", Status: probe.Yes, Country: "DE"},
		{Group: services.Streaming, Service: "Disney+", Status: probe.Yes, Country: "DE", Extended: true},
		{Group: services.Streaming, Service: "YouTube Premium", Status: probe.Yes, Extended: true},
		{Group: services.Web, Service: "Reddit", Status: probe.Yes},
		{Group: services.Web, Service: "Wikipedia editing", Status: probe.Yes},
		{Group: services.AI, Service: "OpenAI API", Status: probe.Yes},
		{Group: services.AI, Service: "Anthropic API", Status: probe.Yes},
		{Group: services.AI, Service: "ChatGPT app", Status: probe.Yes},
		{Group: services.AI, Service: "NotebookLM", Status: probe.Yes},
		{Group: services.AI, Service: "DeepSeek API", Status: probe.Yes},
		{Group: services.AI, Service: "Kimi API (CN)", Status: probe.No, Reason: "region not supported"},
		{Group: risk.Reputation, Service: "proxycheck.io", Status: probe.Yes, Country: "DE", Detail: "Residential; risk 0",
			Facts: demoFacts("isp", "", 0, 0, clean)},
		{Group: risk.Reputation, Service: "ipinfo.io", Status: probe.Yes, Country: "DE", Detail: "ASN type isp", Extended: true,
			Facts: demoFacts("isp", "isp", -1, 0, clean)},
		{Group: risk.Network, Service: risk.PTRService, Status: probe.Yes, Detail: "p203-0-113-7.dip0.example.net"},
		{Group: risk.DNSBL, Service: "bl.spamcop.net", Status: probe.Yes},
		{Group: risk.DNSBL, Service: "psbl.surriel.com", Status: probe.Yes},
		{Group: risk.DNSBL, Service: "dnsbl.dronebl.org", Status: probe.Yes},
		{Group: risk.Mail, Service: "Outbound SMTP (25)", Status: probe.No, Detail: "connection timed out, port 25 likely filtered"},
		{Group: risk.Network, Service: "PeeringDB", Status: probe.Yes, Detail: "AS3320 Cable/DSL/ISP"},
		{Group: risk.Network, Service: "Known ranges", Status: probe.Yes, Detail: "not in: tor-exits, aws, gcp, oracle, cloudflare"},
	})
	v4.SetRegion(region.Summarize([]probe.Result{
		{Group: region.GeoIP, Service: "ipquery.io", Status: probe.OK, Country: "DE", Facts: demoFacts("", "", 0, 0, clean)},
		{Group: region.GeoIP, Service: "ip-api.com", Status: probe.OK, Country: "DE",
			Facts: demoFacts("", "", -1, 0, map[probe.Flag]bool{probe.Proxy: false, probe.Hosting: false})},
		{Group: region.GeoIP, Service: "ip2location.io", Status: probe.OK, Country: "DE", Facts: demoFacts("", "", -1, 0, map[probe.Flag]bool{probe.Proxy: false})},
		{Group: region.GeoIP, Service: "ipinfo.io", Status: probe.OK, Country: "DE"},
		{Group: region.Platform, Service: "Cloudflare", Status: probe.OK, Country: "DE"},
		{Group: region.Platform, Service: "Google", Status: probe.OK, Country: "DE"},
		{Group: region.Platform, Service: "Netflix", Status: probe.OK, Country: "DE"},
		{Group: region.CDN, Service: "Cloudflare", Status: probe.OK, Country: "DE", IATA: "FRA"},
		{Group: region.Registry, Service: "RIPEstat", Status: probe.OK, Country: "DE", Detail: "203.0.113.0/24 · AS3320 DTAG"},
	}))
	r.IPv4 = v4
	r.IPv6 = NewHost(ipdetect.Address{Error: "no IPv6 connectivity"}, nil)
	if mode != "lookup" {
		r.SetCensor([]probe.Result{
			{Group: censor.DNS, Service: "Cloudflare 1.1.1.1", Status: probe.Yes},
			{Group: censor.DNS, Service: "Google 8.8.8.8", Status: probe.Yes},
			{Group: censor.DNS, Service: "Port 53 interception (OpenDNS)", Status: probe.Yes},
			{Group: censor.Telegram, Service: "DC2", Status: probe.Yes},
			{Group: censor.Telegram, Service: "DC4", Status: probe.Yes},
			{Group: censor.Portal, Service: "Google", Status: probe.Yes},
			{Group: censor.Portal, Service: "Apple", Status: probe.Yes},
			{Group: censor.Portal, Service: "Arch Linux", Status: probe.Yes},
		})
		r.SetBench(&bench.Report{
			System: bench.System{OS: "linux", Kernel: "6.12.0", Arch: "amd64", Distro: "Debian GNU/Linux 13", CPUs: 2, CPUModel: "Example CPU @ 2.10GHz", AESNI: true,
				MemTotal: 2 << 30, MemFree: 1 << 30, Virt: "kvm", Uptime: 86400 * 3, Load1: 0.12},
			CPU:   &bench.CPUReport{Threads: 2, Single: bench.CPUScore{SHA256MBps: 280, AESGCMMBps: 1300, DeflateMBps: 60, Score: 180}, Multi: bench.CPUScore{Score: 350}},
			Speed: &bench.Speed{Server: "speed.cloudflare.com", Colo: "FRA", LatencyMs: 4.2, DownMbps: 930, UpMbps: 610},
			Iperf: []bench.IperfRun{
				{Server: bench.IperfServer{Host: "iperf.example.net", Provider: "Example", Location: "Frankfurt, DE"}, Client: "cii", Port: 5201, SendMbps: 880, RecvMbps: 910, Streams: 4},
			},
		})
	}
	r.Network = []ledger.Entry{{Module: "ipdetect", Host: "www.cloudflare.com", Proto: "https", Requests: 1, Purpose: "public IP echo (cloudflare)"}}
	return r
}

const (
	demoWide   = 118
	demoNarrow = 60
)

type DemoImage struct {
	File, Lang string
	Width      int
}

func DemoSVG(lang string, width int) ([]byte, error) {
	r := Demo("online")
	r.Bench = nil
	lines := r.Screen(Style{Color: true, Unicode: true, Width: width, Lang: lang}, r.Tool.Name+" demo", []string{Legend(r, true, lang)})
	var b bytes.Buffer
	err := WriteSVG(&b, lines)
	return b.Bytes(), err
}

func DemoImages() []DemoImage {
	return []DemoImage{
		{"demo-en.svg", "en", demoWide},
		{"demo-ru.svg", "ru", demoWide},
		{"demo-en-narrow.svg", "en", demoNarrow},
		{"demo-ru-narrow.svg", "ru", demoNarrow},
	}
}
