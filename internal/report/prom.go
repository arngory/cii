package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/arngory/cii/internal/bench"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
)

type promWriter struct {
	b       strings.Builder
	current string
}

func (p *promWriter) family(name, help string) {
	p.current = name
	fmt.Fprintf(&p.b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
}

var promEscape = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func (p *promWriter) sample(value float64, labels ...string) {
	p.b.WriteString(p.current)
	var pairs []string
	for i := 0; i+1 < len(labels); i += 2 {
		if labels[i+1] != "" {
			pairs = append(pairs, labels[i]+`="`+promEscape.Replace(labels[i+1])+`"`)
		}
	}
	if len(pairs) > 0 {
		p.b.WriteString("{" + strings.Join(pairs, ",") + "}")
	}
	p.b.WriteString(" " + strconv.FormatFloat(value, 'g', -1, 64) + "\n")
}

func availability(st probe.Status) (value float64, answered bool) {
	switch st {
	case probe.Yes, probe.OK:
		return 1, true
	case probe.Partial:
		return 0.5, true
	case probe.No, probe.IPBlock:
		return 0, true
	}
	return 0, false
}

func (r *Report) WritePrometheus(w io.Writer) error {
	p := &promWriter{}
	fams := r.families()

	p.family("cii_info", "Version of cii and the mode of the run that produced these metrics.")
	p.sample(1, "version", r.Tool.Version, "mode", r.Mode)
	p.family("cii_report_timestamp_seconds", "Unix time when the report was generated.")
	p.sample(float64(r.GeneratedAt.Unix()))

	p.family("cii_address_info", "Public address per point; address and ASN are omitted from masked reports.")
	for _, f := range fams {
		if f.host.Address == "" {
			continue
		}
		labels := []string{"point", f.label}
		if !r.Masked {
			labels = append(labels, "address", f.host.Address)
			for _, g := range f.host.Geo {
				if g.ASN != 0 {
					labels = append(labels, "asn", strconv.FormatUint(uint64(g.ASN), 10))
					break
				}
			}
		}
		if f.host.Region != nil && len(f.host.Region.Verdict) > 0 {
			labels = append(labels, "country", strings.Join(f.host.Region.Verdict, "/"))
		}
		p.sample(1, labels...)
	}

	p.family("cii_region_sources", "Sources that reported a country, per group.")
	agree := map[string][2]int{}
	var keys []string
	for _, f := range fams {
		if f.host.Region == nil {
			continue
		}
		for _, res := range f.host.Region.Results {
			if res.Status != probe.OK || res.Group == region.CDN || res.Group == region.Registry {
				continue
			}
			k := f.label + "\x00" + groupTitle(res.Group)
			v, seen := agree[k]
			if !seen {
				keys = append(keys, k)
			}
			v[1]++
			for _, cc := range f.host.Region.Verdict {
				if cc == res.Country {
					v[0]++
					break
				}
			}
			agree[k] = v
		}
	}
	for _, k := range keys {
		point, group, _ := strings.Cut(k, "\x00")
		p.sample(float64(agree[k][1]), "point", point, "group", group)
	}
	p.family("cii_region_sources_agreeing", "Sources whose country matches the verdict, per group.")
	for _, k := range keys {
		point, group, _ := strings.Cut(k, "\x00")
		p.sample(float64(agree[k][0]), "point", point, "group", group)
	}

	type check struct {
		point string
		res   probe.Result
	}
	var checks []check
	for _, f := range fams {
		for _, res := range f.host.Services {
			checks = append(checks, check{f.label, res})
		}
	}
	for _, res := range r.Censor {
		checks = append(checks, check{"", res})
	}
	p.family("cii_check_answered", "1 when the check gave an answer, 0 when it was unknown or failed.")
	for _, c := range checks {
		if c.res.Status == probe.Pending {
			continue
		}
		_, ok := availability(c.res.Status)
		v := 0.0
		if ok {
			v = 1
		}
		p.sample(v, "point", c.point, "group", groupTitle(c.res.Group), "service", c.res.Service)
	}
	p.family("cii_check_available", "Answered checks: 1 yes, 0.5 partial, 0 no or blocked.")
	for _, c := range checks {
		if v, ok := availability(c.res.Status); ok {
			p.sample(v, "point", c.point, "group", groupTitle(c.res.Group), "service", c.res.Service)
		}
	}

	p.family("cii_risk_score", "Risk score of the address per source, 0 to 100.")
	for _, f := range fams {
		if f.host.Profile == nil {
			continue
		}
		for _, s := range f.host.Profile.Scores {
			p.sample(float64(s.Score), "point", f.label, "source", s.Source)
		}
	}
	p.family("cii_risk_flag_sources", "Sources that reported on a risk flag.")
	for _, f := range fams {
		if f.host.Profile == nil {
			continue
		}
		for _, fl := range f.host.Profile.Factors {
			p.sample(float64(fl.Checked), "point", f.label, "flag", string(fl.Flag))
		}
	}
	p.family("cii_risk_flag_hits", "Sources that raised a risk flag.")
	for _, f := range fams {
		if f.host.Profile == nil {
			continue
		}
		for _, fl := range f.host.Profile.Factors {
			p.sample(float64(len(fl.Hits)), "point", f.label, "flag", string(fl.Flag))
		}
	}

	if rt := r.Route; rt != nil {
		p.family("cii_route_rtt_ms", "Round-trip time to a route target in milliseconds.")
		for _, path := range rt.Paths {
			if path.RTTms > 0 {
				p.sample(path.RTTms, "target", path.Target.Name)
			}
		}
		p.family("cii_route_verdict", "Verdict for the path to a route target.")
		for _, path := range rt.Paths {
			p.sample(1, "target", path.Target.Name, "verdict", path.Verdict)
		}
	}

	if b := r.Bench; b != nil {
		if b.Speed != nil {
			p.family("cii_bench_speed_mbps", "Cloudflare speed test throughput in Mbit/s.")
			p.sample(b.Speed.DownMbps, "direction", "down")
			p.sample(b.Speed.UpMbps, "direction", "up")
			p.family("cii_bench_latency_ms", "Latency to the speed test server in milliseconds.")
			p.sample(b.Speed.LatencyMs)
		}
		if b.CPU != nil {
			p.family("cii_bench_cpu_score", "CPU benchmark score.")
			p.sample(b.CPU.Single.Score, "mode", "single")
			p.sample(b.CPU.Multi.Score, "mode", "multi")
		}
		if b.Disk != nil {
			p.family("cii_bench_disk_mbps", "Disk throughput in MB/s.")
			for _, d := range append([]bench.DiskResult{b.Disk.Sequential}, b.Disk.Random...) {
				p.sample(d.ReadMBps, "block", d.Block, "op", "read")
				p.sample(d.WriteMBps, "block", d.Block, "op", "write")
			}
		}
		if len(b.Iperf) > 0 {
			p.family("cii_bench_iperf_mbps", "iperf3 throughput in Mbit/s.")
			for _, run := range b.Iperf {
				if run.Error != "" {
					continue
				}
				server := strings.TrimSpace(run.Server.Provider + " " + run.Server.Location)
				p.sample(run.SendMbps, "server", server, "client", run.Client, "direction", "send")
				p.sample(run.RecvMbps, "server", server, "client", run.Client, "direction", "recv")
			}
		}
	}
	_, err := io.WriteString(w, p.b.String())
	return err
}
