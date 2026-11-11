package bench

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
)

const Module = "bench"

type Options struct {
	Disk, CPU, Net, Iperf bool
	DiskDir               string
	DiskSize              int64
	Servers               string
	Duration              time.Duration
	SystemTools           bool
}

func Defaults() Options {
	return Options{Disk: true, CPU: true, Net: true, Iperf: true, DiskSize: 1 << 30, Servers: "global", Duration: 5 * time.Second}
}

type Report struct {
	System     System      `json:"system"`
	Disk       *DiskReport `json:"disk,omitempty"`
	Fio        *FioReport  `json:"fio,omitempty"`
	CPU        *CPUReport  `json:"cpu,omitempty"`
	Speed      *Speed      `json:"speed,omitempty"`
	Iperf      []IperfRun  `json:"iperf,omitempty"`
	Notes      []string    `json:"notes,omitempty"`
	DurationMs int64       `json:"duration_ms"`
}

const cloudflareSpeedHost = "speed.cloudflare.com"

func (o Options) Validate() error {
	if o.Duration < time.Second || o.Duration > time.Minute || o.Duration%time.Second != 0 {
		return errors.New("--duration must be a whole number of seconds between 1s and 1m")
	}
	if _, err := serversFor(o.Servers); err != nil {
		return fmt.Errorf("--servers: %w", err)
	}
	return nil
}

func Rules(opts Options) []netx.Rule {
	var rules []netx.Rule
	if opts.Net {
		rules = append(rules, netx.Rule{Module: Module, Pattern: cloudflareSpeedHost, Purpose: Module + ": Cloudflare speed test"})
	}
	if opts.Iperf {
		servers, _ := serversFor(opts.Servers)
		for _, s := range servers {
			rules = append(rules, netx.Rule{Module: Module, Pattern: s.Host, Purpose: Module + ": iperf3 " + s.Provider + ", " + s.Location})
		}
	}
	return rules
}

type Env struct {
	Net    *netx.Net
	Ledger *ledger.Ledger
}

func Run(ctx context.Context, env Env, opts Options, progress func(string)) Report {
	if progress == nil {
		progress = func(string) {}
	}
	start := time.Now()
	rep := Report{System: CollectSystem()}
	if opts.Disk {
		progress("disk")
		d, err := DiskTest(ctx, opts.DiskDir, opts.DiskSize)
		if err != nil {
			rep.Notes = append(rep.Notes, "disk: "+err.Error())
		} else {
			rep.Disk = &d
		}
		if opts.SystemTools {
			progress("fio")
			rep.Fio = runFio(ctx, &rep, opts)
		}
	}
	if opts.CPU {
		progress("cpu")
		c := CPUTest(ctx)
		rep.CPU = &c
	}
	if opts.Net {
		progress("cloudflare")
		s, err := CloudflareSpeed(ctx, env.Net, opts.Duration)
		if err != nil {
			rep.Notes = append(rep.Notes, "cloudflare: "+err.Error())
		} else {
			rep.Speed = &s
		}
	}
	if opts.Iperf {
		rep.Iperf = runIperf(ctx, env, &rep, opts, progress)
	}
	rep.DurationMs = time.Since(start).Milliseconds()
	return rep
}

func runFio(ctx context.Context, rep *Report, opts Options) *FioReport {
	path, err := lookTool("fio")
	if err != nil {
		rep.Notes = append(rep.Notes, "fio: "+err.Error())
		return nil
	}
	f, err := FioTest(ctx, path, opts.DiskDir, opts.DiskSize)
	if err != nil {
		rep.Notes = append(rep.Notes, "fio: "+err.Error())
		return nil
	}
	return &f
}

func runIperf(ctx context.Context, env Env, rep *Report, opts Options, progress func(string)) []IperfRun {
	servers, err := serversFor(opts.Servers)
	if err != nil {
		rep.Notes = append(rep.Notes, "iperf3: "+err.Error())
		return nil
	}
	if env.Net.Proxied() {
		rep.Notes = append(rep.Notes, "iperf3: skipped, a proxy is in effect and raw TCP would bypass it")
		return nil
	}
	external := ""
	if opts.SystemTools {
		path, err := lookTool("iperf3")
		if err != nil {
			rep.Notes = append(rep.Notes, "iperf3: "+err.Error())
		} else {
			external = path
		}
	}
	var out []IperfRun
	for _, s := range servers {
		if ctx.Err() != nil {
			break
		}
		progress("iperf3 " + s.Provider + " " + s.Location)
		out = append(out, IperfTest(ctx, env.Net, s, opts.Duration))
		if external != "" {
			out = append(out, SystemIperf3(ctx, env, external, s, opts.Duration))
		}
	}
	return out
}
