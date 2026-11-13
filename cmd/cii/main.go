package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"math"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/arngory/cii/internal/bench"
	"github.com/arngory/cii/internal/censor"
	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/datasrc"
	"github.com/arngory/cii/internal/geodb"
	"github.com/arngory/cii/internal/ipdetect"
	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/paths"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/region"
	"github.com/arngory/cii/internal/report"
	"github.com/arngory/cii/internal/risk"
	"github.com/arngory/cii/internal/route"
	"github.com/arngory/cii/internal/runlog"
	"github.com/arngory/cii/internal/services"
	"github.com/arngory/cii/internal/version"
)

const usage = `cii — complete information about current IP

Usage:
  cii                         in a terminal: a menu of modes, pick one by number (add m to mask, e.g. 2m)
  cii N[m] [flags]            run menu mode N directly, e.g. cii 2m; cii ip runs the standard check without the menu
  cii [flags]                 detect public IPv4/IPv6, describe them, check services, reputation and censorship (default)
  cii lookup [flags] IP...    describe given addresses using local data only (no network)
  cii data update [ID...]     download offline databases from their publishers
  cii data status             show local databases
  cii data sources            list supported databases and their licenses
  cii censor [flags]          only censorship: all modes, own lists and domains (see docs/CENSOR_CHECKS.md)
  cii bench [flags]           only the benchmark, with its own options (see docs/BENCH.md)
  cii route [flags]           paths to major networks: hops, transit, detours (see docs/ROUTE.md)
  cii diff [OLD NEW]          what changed between two runs (default: the last two local logs)
  cii show [LOG|JSON|-]       print a past run again (default: the latest local log); works with --mask, --json, --debug, --svg, --lang
  cii analyze [LOG|JSON|-]    conclusions drawn from a run (default: the latest local log); nothing is checked again
  cii stats [LOG...]          which checks did not always answer across local logs
  cii compare A B [C...]      reports from different machines side by side, plus the list of differences for two
  cii watch [flags]           repeat the check every --every (default 30m, minimum 5m) and print what changed; --count N stops after N runs
  cii version

Default command only:
  --no-censor        skip censorship checks (DNS and Telegram; DPI and geoblock with --extended)
  --bench            also run the benchmark after the checks: disk, CPU, Cloudflare speed, iperf3

Common flags:
  -4 / -6            IPv4 or IPv6 only (default: both)
  --iface NAME       bind outgoing connections to this interface's address
  --source ADDR      bind outgoing connections to this local address
  --proxy URL[,URL]  http://, https:// or socks5:// proxy for HTTP traffic; several URLs check each exit side by side
  --timeout DUR      per-request timeout (default 10s)
  --offline          never touch the network (local interfaces + databases only)
  --quick            skip region, service and censorship checks
  --extended         also run tier-B checks (vendors' internal APIs, public lookup pages) and the DPI and geoblock lists
  --catalog LIST     regional service catalogs: auto (by detected country), all, none, or codes like JP,EU
  --no-risk          skip IP reputation, DNSBL and outbound SMTP checks
  --plan             print every destination that may be contacted, then exit
  --json             machine-readable output
  --debug            detailed tables, failed checks, data sources and every network contact
  --no-log           do not write the local log (default: %s)
  --mask             hide addresses, prefixes, ASNs and AS holders (for screenshots)
  --svg FILE         also save the final screen as an SVG image (cii, lookup, censor, bench, route, show, compare)
  --prom             print the report as Prometheus metrics instead of the screen (not for lookup)
  --prom-file FILE   also write those metrics to FILE atomically, e.g. for the node_exporter textfile collector
  --demo             show the report on invented sample data without touching the network (cii only)
  --no-color         disable colours
  --lang LANG        interface language: auto (from LANG/LC_ALL), en or ru; the --debug report and JSON stay in English
  --config FILE      config file (default: %s)
  --data-dir DIR     database directory (default: %s)
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "cii:", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, usage, paths.LogDir(), config.DefaultPath(), paths.DataDir())
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 && interactive() {
		return runMenu(ctx)
	}
	cmd := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	if choicePattern.MatchString(cmd) {
		chosen, err := parseChoice(cmd)
		if errors.Is(err, errMenuExit) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("no mode %q: modes are 1-%d, see `cii` without arguments", cmd, len(menu))
		}
		return run(ctx, append(chosen, args...))
	}
	switch cmd {
	case "", "ip":
		return cmdIP(ctx, args)
	case "lookup":
		return cmdLookup(args)
	case "data":
		return cmdData(ctx, args)
	case "censor":
		return cmdCensor(ctx, args)
	case "bench":
		return cmdBench(ctx, args)
	case "route":
		return cmdRoute(ctx, args)
	case "diff":
		return cmdDiff(args)
	case "show":
		return cmdShow(args)
	case "analyze", "analyse":
		return cmdAnalyze(args)
	case "stats":
		return cmdStats(args)
	case "compare":
		return cmdCompare(args)
	case "watch":
		return cmdWatch(ctx, args)
	case "version":
		fmt.Println(version.Name, version.Version)
		return nil
	case "help":
		printUsage()
		return nil
	}
	printUsage()
	return fmt.Errorf("unknown command %q", cmd)
}

type common struct {
	v4, v6, offline, plan, json, mask, noColor, quick, extended, debug, noLog, noRisk, demo, prom, quiet bool
	iface, source, proxy, cfgPath, dataDir, catalog, lang, svg, from, promFile                           string
	timeout                                                                                              time.Duration
}

func (c *common) register(fs *flag.FlagSet) {
	fs.BoolVar(&c.v4, "4", false, "IPv4 only")
	fs.BoolVar(&c.v6, "6", false, "IPv6 only")
	fs.StringVar(&c.iface, "iface", "", "interface")
	fs.StringVar(&c.source, "source", "", "source address")
	fs.StringVar(&c.proxy, "proxy", "", "proxy URL")
	fs.StringVar(&c.lang, "lang", "auto", "interface language: auto, en or ru")
	fs.DurationVar(&c.timeout, "timeout", 10*time.Second, "per-request timeout")
	fs.BoolVar(&c.offline, "offline", false, "no network")
	fs.BoolVar(&c.quick, "quick", false, "skip region and service checks")
	fs.BoolVar(&c.extended, "extended", false, "run tier-B checks")
	fs.StringVar(&c.catalog, "catalog", "auto", "regional service catalogs")
	fs.BoolVar(&c.noRisk, "no-risk", false, "skip reputation, DNSBL and SMTP checks")
	fs.BoolVar(&c.plan, "plan", false, "print destinations and exit")
	fs.BoolVar(&c.json, "json", false, "JSON output")
	fs.BoolVar(&c.mask, "mask", false, "hide addresses, prefixes, ASNs and AS holders")
	fs.BoolVar(&c.noColor, "no-color", false, "disable colours")
	fs.BoolVar(&c.debug, "debug", false, "detailed output")
	fs.BoolVar(&c.noLog, "no-log", false, "do not write a local log")
	fs.StringVar(&c.cfgPath, "config", "", "config file")
	fs.StringVar(&c.dataDir, "data-dir", "", "database directory")
	fs.Usage = printUsage
}

func (c *common) registerSVG(fs *flag.FlagSet) {
	fs.StringVar(&c.svg, "svg", "", "also write the final screen as an SVG image to this file")
}

func (c *common) registerExports(fs *flag.FlagSet) {
	c.registerSVG(fs)
	fs.BoolVar(&c.prom, "prom", false, "print Prometheus metrics instead of the report")
	fs.StringVar(&c.promFile, "prom-file", "", "also write Prometheus metrics to this file")
}

func (c *common) color() bool { return !c.noColor && !c.json && !c.prom && report.ColorEnabled() }

func (c *common) language() string {
	switch c.lang {
	case "en", "ru":
		return c.lang
	}
	return report.DetectLang()
}

func (c *common) dir() string {
	if c.dataDir != "" {
		return c.dataDir
	}
	return paths.DataDir()
}

func (c *common) families() []netx.Family {
	switch {
	case c.v4 && !c.v6:
		return []netx.Family{netx.IPv4}
	case c.v6 && !c.v4:
		return []netx.Family{netx.IPv6}
	}
	return []netx.Family{netx.IPv4, netx.IPv6}
}

func (c *common) options(f netx.Family) (netx.Options, error) {
	o, err := c.baseOptions()
	if err != nil {
		return o, err
	}
	o.Family = f
	if o.Source.IsValid() && f != netx.Any && o.Source.Is4() != (f == netx.IPv4) {
		return o, fmt.Errorf("--source %s cannot be used for %s", o.Source, f)
	}
	if c.iface != "" {
		a, err := netx.SourceForInterface(c.iface, f)
		if err != nil {
			return o, err
		}
		o.Source = a
	}
	return o, nil
}

func (c *common) baseOptions() (netx.Options, error) {
	o := netx.Options{Timeout: c.timeout}
	if c.proxy != "" {
		u, err := url.Parse(c.proxy)
		if err != nil || u.Host == "" {
			return o, errors.New("bad --proxy: expected scheme://host:port")
		}
		switch u.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return o, fmt.Errorf("unsupported proxy scheme %q in %s", u.Scheme, u.Redacted())
		}
		o.Proxy = u
	}
	if c.source != "" && c.iface != "" {
		return o, errors.New("--source and --iface are mutually exclusive")
	}
	if c.source != "" {
		a, err := netip.ParseAddr(c.source)
		if err != nil {
			return o, fmt.Errorf("bad --source: %w", err)
		}
		o.Source = a.Unmap()
	}
	return o, nil
}

func (c *common) parse(fs *flag.FlagSet, args []string) error {
	c.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	return c.check()
}

func (c *common) check() error {
	switch c.lang {
	case "auto", "en", "ru":
		return nil
	}
	return fmt.Errorf("unknown --lang %q (known: auto, en, ru)", c.lang)
}

func cmdIP(ctx context.Context, args []string) error {
	var c common
	var f ipFlags
	fs := flag.NewFlagSet("cii", flag.ContinueOnError)
	f.register(fs)
	fs.BoolVar(&c.demo, "demo", false, "render invented sample data, no network")
	c.registerExports(fs)
	if err := c.parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q (did you mean `cii lookup`?)", fs.Arg(0))
	}
	if c.demo {
		c.noLog = true
		rep := report.Demo("online")
		if !f.bench {
			rep.Bench = nil
		}
		if c.mask {
			rep = rep.Scrubbed()
		}
		return output(rep, &c)
	}
	rep, err := collectIP(ctx, &c, f)
	if err != nil || rep == nil {
		return err
	}
	return output(rep, &c)
}

const (
	watchDefault = 30 * time.Minute
	watchMinimum = 5 * time.Minute
)

func cmdWatch(ctx context.Context, args []string) error {
	var c common
	var f ipFlags
	every, count := watchDefault, 0
	fs := flag.NewFlagSet("cii watch", flag.ContinueOnError)
	f.register(fs)
	c.registerExports(fs)
	fs.DurationVar(&every, "every", every, "pause between runs, 5m or more")
	fs.IntVar(&count, "count", count, "stop after this many runs (0: until interrupted)")
	if err := c.parse(fs, args); err != nil {
		return err
	}
	switch {
	case fs.NArg() > 0:
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	case every < watchMinimum:
		return fmt.Errorf("--every %s is too often: the checks query other people's services, the minimum is %s", every, watchMinimum)
	case count < 0:
		return errors.New("--count must not be negative")
	case c.prom:
		return errors.New("--prom prints a single report; with watch use --prom-file")
	}
	var prev *report.Report
	for n := 1; ; n++ {
		rc := c
		rc.quiet = prev != nil
		rep, err := collectIP(ctx, &rc, f)
		if ctx.Err() != nil && prev != nil {
			return nil
		}
		switch {
		case err != nil && prev == nil:
			return err
		case err != nil:
			fmt.Fprintf(os.Stderr, "%s  run %d failed: %v\n", time.Now().Format("15:04"), n, err)
		case rep == nil:
			return nil
		case prev == nil:
			if err := output(rep, &rc); err != nil {
				return err
			}
			prev = rep
		default:
			if err := watchStep(&rc, n, prev, rep); err != nil {
				return err
			}
			prev = rep
		}
		if ctx.Err() != nil || count > 0 && n >= count {
			return nil
		}
		timer := time.NewTimer(every)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func watchStep(c *common, n int, prev, cur *report.Report) error {
	logPath, logErr := writeLog(cur, c)
	if logErr != nil {
		fmt.Fprintln(os.Stderr, "cii: log not written:", logErr)
	}
	if c.svg != "" {
		if err := writeSVG(cur, c, logPath, logErr); err != nil {
			return fmt.Errorf("--svg: %w", err)
		}
	}
	if c.promFile != "" {
		if err := writeMetricsFile(cur, c.promFile); err != nil {
			return fmt.Errorf("--prom-file: %w", err)
		}
	}
	changes := report.Diff(prev, cur)
	stamp := cur.GeneratedAt.Local().Format("15:04")
	if c.json {
		return json.NewEncoder(os.Stdout).Encode(struct {
			Run     int             `json:"run"`
			Taken   time.Time       `json:"generated_at"`
			Changes []report.Change `json:"changes"`
		}{n, cur.GeneratedAt, append([]report.Change{}, changes...)})
	}
	if len(changes) == 0 {
		fmt.Printf("%s  run %d: %s\n", stamp, n, report.Translate(c.language(), "no changes"))
		return nil
	}
	fmt.Println()
	report.WriteDiff(os.Stdout, c.color(), prev.GeneratedAt.Local().Format("15:04"), stamp, changes)
	return nil
}

type ipFlags struct{ bench, noCensor, route bool }

func (f *ipFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&f.bench, "bench", false, "also run the benchmark (disk, CPU, speed, iperf3)")
	fs.BoolVar(&f.noCensor, "no-censor", false, "skip censorship checks")
	fs.BoolVar(&f.route, "route", false, "also analyse paths to major networks (see cii route)")
}

func collectIP(ctx context.Context, cp *common, f ipFlags) (*report.Report, error) {
	c := *cp
	defer func() { *cp = c }()
	withBench, noCensor, withRoute := f.bench, f.noCensor, f.route
	cfg, err := config.Load(c.cfgPath)
	if err != nil {
		return nil, err
	}
	exits := c.exits()
	for _, e := range exits {
		if _, err := e.c.baseOptions(); err != nil {
			return nil, err
		}
	}
	if len(exits) == 1 {
		c = exits[0].c
	}
	if len(exits) > 1 && c.offline {
		return nil, errors.New("--offline cannot check several proxies: exits are only known online")
	}
	if len(exits) > 1 && withBench {
		return nil, errors.New("--bench measures one path; run it without a list of proxies")
	}
	if len(exits) > 1 && withRoute {
		return nil, errors.New("--route measures one path; run it without a list of proxies")
	}
	if withRoute && c.offline {
		return nil, errors.New("--route needs the network; drop --offline")
	}

	providers := cfg.IPEcho
	if len(providers) == 0 {
		providers = ipdetect.DefaultProviders
	}
	if c.quick && c.extended {
		return nil, errors.New("--quick and --extended are mutually exclusive")
	}
	var checks []probe.Check
	var catalogs []string
	riskOn := !c.quick && !c.noRisk
	if !c.quick {
		checks = append(region.Select(cfg.Keys, c.extended), services.Select(cfg.Keys, c.extended)...)
		if catalogs, err = c.catalogs(); err != nil {
			return nil, err
		}
	}
	if riskOn {
		checks = append(checks, risk.Checks(cfg.Keys, c.extended)...)
	}
	censorOn := !c.quick && !noCensor && !c.offline && len(exits) == 1
	censorOpts := censor.Options{Modes: []string{"dns", "telegram", "portal"}, Protocol: "both"}
	if c.extended {
		censorOpts.Modes = nil
	}
	var routeList []route.Target
	benchOpts := bench.Defaults()
	benchOpts.Net, benchOpts.Iperf = !c.offline, !c.offline
	policy := netx.NewPolicy()
	if !c.offline {
		policy.Add(ipdetect.Rules(providers)...)
		policy.Add(probe.Rules(checks)...)
		policy.Add(probe.Rules(services.SelectRegional(catalogs, cfg.Keys, c.extended))...)
		if riskOn {
			policy.Add(risk.Rules(risk.Options{})...)
		}
		if censorOn {
			policy.Add(censor.Rules(censorOpts)...)
		}
		if withBench {
			policy.Add(bench.Rules(benchOpts)...)
		}
		if withRoute {
			if routeList, err = routeTargets(cfg, ""); err != nil {
				return nil, err
			}
			policy.Add(route.Rules(routeList)...)
		}
	}
	if c.plan {
		report.WritePlan(os.Stdout, c.color(), policy.Rules())
		return nil, nil
	}

	led := ledger.New()

	dbs, err := geodb.Open(c.dir())
	if err != nil {
		return nil, err
	}
	defer dbs.Close()

	mode := "online"
	if c.offline {
		mode = "offline"
	}
	s := &session{mode: mode, mask: c.mask, dbs: dbs, led: led}
	screen := startScreen(&c, s)
	defer screen.stop()

	nets := map[netx.Family]*netx.Net{}
	var targets []target
	if len(exits) > 1 {
		targets = exits
	} else {
		for _, f := range c.families() {
			targets = append(targets, target{family: f, c: c})
		}
	}
	var detect sync.WaitGroup
	for i, t := range targets {
		detect.Go(func() {
			f := t.family
			h := &hostRun{family: f, label: t.label, via: t.via, order: i, nets: nets}
			if t.label != "" {
				h.nets = map[netx.Family]*netx.Net{}
			}
			var n *netx.Net
			if opts, err := t.c.options(f); err != nil {
				h.addr = ipdetect.Address{Error: err.Error()}
			} else {
				n = netx.New(opts, policy, led)
				h.addr = ipdetect.Detect(ctx, n, f, ipdetect.Options{Providers: providers, Offline: c.offline, Iface: c.iface, Source: opts.Source})
			}
			if h.addr.Address.IsValid() {
				h.geo = dbs.Lookup(h.addr.Address)
				h.local = localOpinions(h.geo)
				if !c.offline {
					h.checks = slots(probe.Placeholders(checks))
					if riskOn {
						h.risk = risk.Placeholders(h.addr.Address, risk.Options{})
					}
				}
			}
			s.update(func() {
				s.hosts = append(s.hosts, h)
				if h.addr.Address.IsValid() {
					h.nets[f] = n
				}
			})
		})
	}
	detect.Wait()
	shared := nets[netx.IPv4]
	if shared == nil {
		shared = nets[netx.IPv6]
	}
	var side sync.WaitGroup
	if censorOn && shared != nil {
		s.update(func() { s.censor = censor.Placeholders(censorOpts) })
		side.Go(func() {
			rs := censor.Run(ctx, shared, censorOpts)
			s.update(func() { s.censor = rs })
		})
	}
	plan := stackPlan{c: &c, s: s, keys: cfg.Keys, checks: checks, catalogs: catalogs, risk: riskOn}
	var stacks sync.WaitGroup
	for _, h := range s.hosts {
		if h.addr.Address.IsValid() {
			stacks.Go(func() { plan.checkHost(ctx, h) })
		}
	}
	stacks.Wait()
	side.Wait()
	if withRoute {
		routeNet := shared
		if routeNet == nil {
			opts, err := c.options(c.families()[0])
			if err != nil {
				s.update(func() { s.route = &route.Report{Method: "none", Note: "skipped: " + err.Error()} })
			} else {
				routeNet = netx.New(opts, policy, led)
			}
		}
		if routeNet != nil {
			ro := route.Defaults()
			ro.Targets = routeList
			ro.ASN = asnLookup(dbs)
			ro.OwnASN = s.ownASN(routeNet.Options().Family)
			rep := route.Run(ctx, routeNet, ro)
			s.update(func() { s.route = rep })
		}
	}
	if withBench {
		benchNet, skipped := shared, ""
		if benchNet == nil && (benchOpts.Net || benchOpts.Iperf) {
			if opts, err := c.options(c.families()[0]); err != nil {
				benchOpts.Net, benchOpts.Iperf = false, false
				skipped = "network tests skipped: " + err.Error()
			} else {
				benchNet = netx.New(opts, policy, led)
			}
		}
		progress := benchProgress(&c, s, screen)
		b := bench.Run(ctx, bench.Env{Net: benchNet, Ledger: led}, benchOpts, progress)
		progress("")
		if skipped != "" {
			b.Notes = append(b.Notes, skipped)
		}
		s.update(func() { s.bench = &b })
	}
	screen.stop()
	return s.report(), nil
}

type target struct {
	family netx.Family
	label  string
	via    string
	c      common
}

func proxyLabel(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "proxy"
	}
	u.User = nil
	return u.String()
}

func (c *common) exits() []target {
	family := c.families()[0]
	var out []target
	for _, p := range strings.Split(c.proxy, ",") {
		if p = strings.TrimSpace(p); p != "" {
			cc := *c
			cc.proxy = p
			out = append(out, target{family: family, label: fmt.Sprintf("exit %d", len(out)+1), via: proxyLabel(p), c: cc})
		}
	}
	switch len(out) {
	case 0:
		return []target{{family: family, c: *c}}
	case 1:
		out[0].label, out[0].via = "", ""
	}
	return out
}

type stackPlan struct {
	c        *common
	s        *session
	keys     config.Keys
	checks   []probe.Check
	catalogs []string
	risk     bool
}

func (p stackPlan) checkHost(ctx context.Context, h *hostRun) {
	ip := h.addr.Address
	if !p.c.offline {
		env := probe.Env{Nets: h.nets, Keys: p.keys, Done: func(i int, rs []probe.Result) { p.s.update(func() { h.checks[i] = rs }) }}
		probe.Run(ctx, env, h.family, ip, p.checks)
		regional := services.SelectRegional(p.c.catalogsFor(p.catalogs, p.s.verdict(h)), p.keys, p.c.extended)
		p.s.update(func() { h.regional = slots(probe.Placeholders(regional)) })
		env.Done = func(i int, rs []probe.Result) { p.s.update(func() { h.regional[i] = rs }) }
		probe.Run(ctx, env, h.family, ip, regional)
		if p.risk {
			rs := risk.Run(ctx, h.nets[h.family], ip, risk.Options{})
			p.s.update(func() { h.risk = rs })
		}
	}
	if p.risk {
		rs := risk.Offline(p.c.dir(), ip, firstASN(h.geo))
		p.s.update(func() { h.offline = rs })
	}
}

func (c *common) catalogs() ([]string, error) {
	var all []string
	for _, cat := range services.Catalogs {
		all = append(all, cat.Code)
	}
	switch strings.ToLower(c.catalog) {
	case "auto", "all":
		return all, nil
	case "none", "":
		return nil, nil
	}
	var out []string
	for _, code := range strings.Split(strings.ToUpper(c.catalog), ",") {
		code = strings.TrimSpace(code)
		if !slices.Contains(all, code) {
			return nil, fmt.Errorf("unknown catalog %q (known: %s, all, none, auto)", code, strings.Join(all, ", "))
		}
		out = append(out, code)
	}
	return out, nil
}

func (c *common) catalogsFor(allowed, verdict []string) []string {
	if strings.ToLower(c.catalog) != "auto" {
		return allowed
	}
	var out []string
	for _, country := range verdict {
		for _, code := range services.CatalogsFor(country) {
			if slices.Contains(allowed, code) && !slices.Contains(out, code) {
				out = append(out, code)
			}
		}
	}
	return out
}

func firstASN(geo []geodb.Record) uint {
	for _, g := range geo {
		if g.ASN != 0 {
			return g.ASN
		}
	}
	return 0
}

func localOpinions(geo []geodb.Record) []probe.Result {
	var out []probe.Result
	for _, g := range geo {
		if g.Country != "" {
			out = append(out, probe.Result{Group: region.GeoIP, Service: "local:" + g.Source, Status: probe.OK, Country: g.Country})
		}
	}
	return out
}

func setHost(r *report.Report, f netx.Family, h *report.Host) {
	if f == netx.IPv4 {
		r.IPv4 = h
	} else {
		r.IPv6 = h
	}
}

func output(r *report.Report, c *common) error {
	logPath, logErr := writeLog(r, c)
	if err := printReport(r, c, logPath, logErr); err != nil {
		return err
	}
	if c.svg != "" {
		if err := writeSVG(r, c, logPath, logErr); err != nil {
			return fmt.Errorf("--svg: %w", err)
		}
	}
	if c.promFile != "" {
		if err := writeMetricsFile(r, c.promFile); err != nil {
			return fmt.Errorf("--prom-file: %w", err)
		}
	}
	return nil
}

func writeMetricsFile(r *report.Report, path string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	err = r.WritePrometheus(tmp)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o644)
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func printReport(r *report.Report, c *common, logPath string, logErr error) error {
	if logErr != nil && (c.json || c.debug || c.prom) {
		fmt.Fprintln(os.Stderr, "cii: log not written:", logErr)
	}
	switch {
	case c.prom:
		return r.WritePrometheus(os.Stdout)
	case c.json:
		return r.WriteJSON(os.Stdout)
	case c.debug:
		r.WriteDetailed(os.Stdout, c.color())
		if logPath != "" {
			fmt.Println("log:", logPath)
		}
		return nil
	}
	unicode := report.UnicodeTerminal()
	style := report.Style{Color: c.color(), Unicode: unicode, Width: terminalWidth(), Lang: c.language()}
	fmt.Println(strings.Join(r.Screen(style, screenTitle(r, c), footer(r, unicode, c.language(), logPath, logErr)), "\n"))
	return nil
}

const logScreenWidth = 160

func screenTitle(r *report.Report, c *common) string {
	title := r.Tool.Name + " " + r.Tool.Version
	if c.from != "" {
		title += " · " + c.from + " · " + r.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC")
	}
	return title
}

func writeLog(r *report.Report, c *common) (string, error) {
	if c.noLog {
		return "", nil
	}
	var text, js bytes.Buffer
	text.WriteString(strings.Join(r.Screen(report.Style{Unicode: true, Width: logScreenWidth, Lang: c.language()}, screenTitle(r, c), nil), "\n") + "\n\n")
	r.WriteDetailed(&text, false)
	if err := r.WriteJSON(&js); err != nil {
		return "", err
	}
	return runlog.Write(paths.LogDir(), time.Now(), text.Bytes(), []byte(runlog.JSONMarker), js.Bytes())
}

func footer(r *report.Report, unicode bool, lang, logPath string, logErr error) []string {
	t := func(s string) string { return report.Translate(lang, s) }
	var parts []string
	if legend := report.Legend(r, unicode, lang); legend != "" {
		parts = append(parts, legend)
	}
	hosts := map[string]bool{}
	for _, e := range r.Network {
		if e.Requests > 0 {
			hosts[e.Host] = true
		}
	}
	switch {
	case len(hosts) == 1:
		parts = append(parts, "1 "+t("host contacted"))
	case len(hosts) > 1:
		parts = append(parts, fmt.Sprintf("%d %s", len(hosts), t("hosts contacted")))
	default:
		parts = append(parts, t("no network contacts"))
	}
	if n := r.FailedChecks(); n > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", n, t("checks failed")))
	}
	if r.Extended() {
		parts = append(parts, "* "+t("--extended check"))
	}
	parts = append(parts, r.Attribution...)
	switch {
	case logErr != nil:
		parts = append(parts, t("log not written")+": "+logErr.Error())
	case logPath != "":
		parts = append(parts, t("details")+": --debug, "+logPath)
	default:
		parts = append(parts, t("details")+": --debug")
	}
	return parts
}

func writeSVG(r *report.Report, c *common, logPath string, logErr error) error {
	style := report.Style{Color: true, Unicode: true, Width: terminalWidth(), Lang: c.language()}
	f, err := os.Create(c.svg)
	if err != nil {
		return err
	}
	if err := report.WriteSVG(f, r.Screen(style, screenTitle(r, c), footer(r, true, c.language(), logPath, logErr))); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func terminalWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	if w, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && w > 0 {
		return w
	}
	return 100
}

func cmdLookup(args []string) error {
	var c common
	fs := flag.NewFlagSet("cii lookup", flag.ContinueOnError)
	c.registerSVG(fs)
	if err := c.parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("usage: cii lookup IP...")
	}
	dbs, err := geodb.Open(c.dir())
	if err != nil {
		return err
	}
	defer dbs.Close()

	rep := report.New("lookup")
	rep.SetData(dbs)
	for _, arg := range fs.Args() {
		a, err := netip.ParseAddr(arg)
		if err != nil {
			return fmt.Errorf("bad address %q", arg)
		}
		a = a.Unmap()
		h := report.NewHost(ipdetect.Address{Address: a, Source: "argument"}, dbs.Lookup(a))
		h.Query = h.Address
		rep.Results = append(rep.Results, h)
	}
	if c.mask {
		rep = rep.Scrubbed()
	}
	return output(rep, &c)
}

func loadReport(path string) (*report.Report, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	var r report.Report
	if err := json.Unmarshal(runlog.ReportJSON(data), &r); err != nil {
		return nil, fmt.Errorf("%s: not a cii log or JSON report: %w", path, err)
	}
	if r.Schema != report.Schema {
		return nil, fmt.Errorf("%s: unsupported report schema %q (want %s)", path, r.Schema, report.Schema)
	}
	return &r, nil
}

func cmdShow(args []string) error {
	var c common
	fs := flag.NewFlagSet("cii show", flag.ContinueOnError)
	c.registerExports(fs)
	if err := c.parse(fs, args); err != nil {
		return err
	}
	r, name, err := pastReport(&c, fs, "usage: cii show [LOG|JSON|-]")
	if err != nil {
		return err
	}
	c.noLog = true
	c.from = name
	return output(r, &c)
}

func pastReport(c *common, fs *flag.FlagSet, usage string) (*report.Report, string, error) {
	var path string
	switch fs.NArg() {
	case 0:
		logs, err := runlog.List(paths.LogDir())
		if err != nil || len(logs) == 0 {
			return nil, "", errors.New("no local logs yet; run cii first or pass a log or JSON file")
		}
		path = logs[len(logs)-1]
	case 1:
		path = fs.Arg(0)
	default:
		return nil, "", errors.New(usage)
	}
	r, err := loadReport(path)
	if err != nil {
		return nil, "", err
	}
	if c.mask {
		r = r.Scrubbed()
	}
	name := filepath.Base(path)
	if path == "-" {
		name = "stdin"
	}
	return r, name, nil
}

func cmdAnalyze(args []string) error {
	var c common
	fs := flag.NewFlagSet("cii analyze", flag.ContinueOnError)
	if err := c.parse(fs, args); err != nil {
		return err
	}
	r, name, err := pastReport(&c, fs, "usage: cii analyze [LOG|JSON|-]")
	if err != nil {
		return err
	}
	lang := c.language()
	if c.json {
		lang = "en"
	}
	findings := report.Analyze(r, lang)
	if c.json {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Source   string           `json:"source"`
			Taken    time.Time        `json:"generated_at"`
			Findings []report.Finding `json:"findings"`
		}{name, r.GeneratedAt, findings})
	}
	title := fmt.Sprintf("%s %s · %s · %s · %s", r.Tool.Name, r.Tool.Version, report.Translate(lang, "analysis"), name, r.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC"))
	report.WriteFindings(os.Stdout, report.Style{Color: c.color(), Unicode: report.UnicodeTerminal(), Width: terminalWidth(), Lang: lang}, title, findings)
	return nil
}

func loadReports(files []string, strict bool) ([]*report.Report, error) {
	var reps []*report.Report
	for _, f := range files {
		r, err := loadReport(f)
		switch {
		case err == nil:
			reps = append(reps, r)
		case strict:
			return nil, err
		}
	}
	if len(reps) == 0 {
		return nil, errors.New("no readable local logs; run cii first or pass log or JSON files")
	}
	return reps, nil
}

func cmdCompare(args []string) error {
	var c common
	fs := flag.NewFlagSet("cii compare", flag.ContinueOnError)
	c.registerExports(fs)
	if err := c.parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() < 2 || fs.NArg() > 6 {
		return errors.New("usage: cii compare A B [C...] (two to six logs or JSON reports)")
	}
	reps, err := loadReports(fs.Args(), true)
	if err != nil {
		return err
	}
	names := make([]string, len(reps))
	for i, f := range fs.Args() {
		names[i] = strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))
	}
	combined, err := report.Compare(reps, names)
	if err != nil {
		return err
	}
	if c.mask {
		combined = combined.Scrubbed()
		for i := range reps {
			reps[i] = reps[i].Scrubbed()
		}
	}
	c.noLog = true
	c.from = "compare"
	if err := output(combined, &c); err != nil {
		return err
	}
	if len(reps) == 2 && !c.json && !c.prom {
		fmt.Println()
		report.WriteDiff(os.Stdout, c.color(), "A", "B", report.Diff(reps[0], reps[1]))
	}
	return nil
}

func cmdStats(args []string) error {
	var c common
	fs := flag.NewFlagSet("cii stats", flag.ContinueOnError)
	if err := c.parse(fs, args); err != nil {
		return err
	}
	files, named := fs.Args(), fs.NArg() > 0
	if !named {
		files, _ = runlog.List(paths.LogDir())
	}
	reps, err := loadReports(files, named)
	if err != nil {
		return err
	}
	stats := report.Stats(reps)
	if c.json {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Runs   int                `json:"runs"`
			Checks []report.CheckStat `json:"checks"`
		}{len(reps), stats})
	}
	report.WriteStats(os.Stdout, c.color(), c.language(), len(reps), stats)
	return nil
}

func cmdDiff(args []string) error {
	var c common
	fs := flag.NewFlagSet("cii diff", flag.ContinueOnError)
	if err := c.parse(fs, args); err != nil {
		return err
	}
	files := fs.Args()
	switch len(files) {
	case 0:
		logs, err := runlog.List(paths.LogDir())
		if err != nil || len(logs) < 2 {
			return errors.New("need two local logs to compare; run cii twice or pass two files")
		}
		files = logs[len(logs)-2:]
	case 2:
	default:
		return errors.New("usage: cii diff [OLD NEW]")
	}
	var reps [2]*report.Report
	for i, f := range files {
		r, err := loadReport(f)
		if err != nil {
			return err
		}
		reps[i] = r
		if c.mask {
			reps[i] = r.Scrubbed()
		}
	}
	changes := report.Diff(reps[0], reps[1])
	if c.json {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Old     string          `json:"old"`
			New     string          `json:"new"`
			Changes []report.Change `json:"changes"`
		}{files[0], files[1], changes})
	}
	report.WriteDiff(os.Stdout, c.color(), filepath.Base(files[0]), filepath.Base(files[1]), changes)
	return nil
}

func cmdData(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: cii data update|status|sources")
	}
	switch args[0] {
	case "-h", "-help", "--help":
		printUsage()
		return flag.ErrHelp
	}
	sub, args := args[0], args[1:]
	var c common
	fs := flag.NewFlagSet("cii data "+sub, flag.ContinueOnError)
	if err := c.parse(fs, args); err != nil {
		return err
	}
	switch sub {
	case "sources":
		for _, s := range datasrc.Registry {
			key := "no key"
			if s.NeedsKey != "" {
				key = "needs your " + s.NeedsKey
			}
			def := ""
			if s.Default {
				def = " [default]"
			}
			fmt.Printf("%-18s %s%s\n  %s; %s; %s\n  %s\n", s.ID, s.Title, def, s.Kind, s.License, key, s.Homepage)
		}
		for _, s := range risk.DataSources {
			fmt.Printf("risk:%-13s %s [default]\n  %s; %s; no key\n  %s\n", s.ID, s.Title, s.Kind, s.Terms, s.Homepage)
		}
		return nil
	case "status":
		m, err := datasrc.LoadManifest(c.dir())
		if err != nil {
			return err
		}
		fmt.Println("data dir:", c.dir())
		if len(m.Entries) == 0 {
			fmt.Println("no databases yet; run `cii data update`")
		}
		for _, id := range slices.Sorted(maps.Keys(m.Entries)) {
			e := m.Entries[id]
			fmt.Printf("%-18s %s  fetched %s  built %s  %d bytes  sha256 %s\n", e.ID, e.DBType,
				e.FetchedAt.Format("2006-01-02"), time.Unix(int64(e.BuildEpoch), 0).UTC().Format("2006-01-02"), e.Size, shortHash(e.SHA256))
		}
		rm, err := risk.DataManifest(c.dir())
		if err != nil {
			return err
		}
		for _, id := range slices.Sorted(maps.Keys(rm)) {
			e := rm[id]
			fmt.Printf("risk:%-13s %d prefixes  fetched %s  %d bytes  sha256 %s\n", e.ID, e.Prefixes, e.FetchedAt.Format("2006-01-02"), e.Size, shortHash(e.SHA256))
		}
		return nil
	case "update":
		return dataUpdate(ctx, &c, fs.Args())
	}
	return fmt.Errorf("unknown data command %q", sub)
}

func dataUpdate(ctx context.Context, c *common, ids []string) error {
	cfg, err := config.Load(c.cfgPath)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		ids = cfg.Data.Sources
	}
	var srcs []datasrc.Source
	if len(ids) == 0 {
		for _, s := range datasrc.Registry {
			if s.Default {
				srcs = append(srcs, s)
			}
		}
	}
	var riskIDs []string
	for _, id := range ids {
		if rid, ok := strings.CutPrefix(id, "risk:"); ok {
			if _, known := risk.DataSourceByID(rid); !known {
				return fmt.Errorf("unknown source %q (see `cii data sources`)", id)
			}
			riskIDs = append(riskIDs, rid)
			continue
		}
		s, ok := datasrc.ByID(id)
		if !ok {
			return fmt.Errorf("unknown source %q (see `cii data sources`)", id)
		}
		srcs = append(srcs, s)
	}
	updateRisk := len(riskIDs) > 0 || len(ids) == 0
	policy := netx.NewPolicy()
	if !c.offline {
		policy.Add(datasrc.Rules(srcs)...)
		if updateRisk {
			policy.Add(risk.DataRules()...)
		}
	}
	if c.plan {
		report.WritePlan(os.Stdout, c.color(), policy.Rules())
		return nil
	}
	if c.offline {
		return errors.New("--offline: refusing to download")
	}
	f := netx.Any
	if fams := c.families(); len(fams) == 1 {
		f = fams[0]
	}
	opts, err := c.options(f)
	if err != nil {
		return err
	}
	led := ledger.New()
	n := netx.New(opts, policy, led)
	var failed int
	for _, s := range srcs {
		fmt.Printf("%-18s ", s.ID)
		e, err := datasrc.Update(ctx, n, c.dir(), s, cfg.Keys)
		if err != nil {
			failed++
			fmt.Println("FAILED:", err)
			continue
		}
		fmt.Printf("ok  %s, %d bytes, sha256 %s\n", e.DBType, e.Size, shortHash(e.SHA256))
	}
	total := len(srcs)
	if updateRisk {
		done, err := risk.Update(ctx, n, c.dir(), riskIDs...)
		for _, e := range done {
			unit := "prefixes"
			if s, _ := risk.DataSourceByID(e.ID); s.ByASN {
				unit = "networks"
			}
			fmt.Printf("risk:%-13s ok  %d %s, sha256 %s\n", e.ID, e.Prefixes, unit, shortHash(e.SHA256))
		}
		if err != nil {
			failed++
			fmt.Println("risk data FAILED:", err)
		}
		total++
	}
	fmt.Println()
	report.WriteContacts(os.Stdout, c.color(), led.Entries())
	if failed > 0 {
		return fmt.Errorf("%d of %d sources failed", failed, total)
	}
	return nil
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

func cmdCensor(ctx context.Context, args []string) error {
	var c common
	var mode, domainsFile, domain, protocol string
	var retries int
	fs := flag.NewFlagSet("cii censor", flag.ContinueOnError)
	c.register(fs)
	c.registerExports(fs)
	fs.StringVar(&mode, "mode", "all", "all, dns, dpi, geoblock, telegram, portal (comma-separated)")
	fs.StringVar(&domainsFile, "domains", "", "file with one domain per line instead of the built-in lists")
	fs.StringVar(&domain, "domain", "", "check a single domain")
	fs.StringVar(&protocol, "protocol", "both", "http, https or both")
	fs.IntVar(&retries, "retries", 0, "extra attempts per target")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if c.offline {
		return errors.New("--offline: censorship checks need the network")
	}
	for _, m := range strings.Split(mode, ",") {
		if !censor.ValidMode(m) {
			return fmt.Errorf("unknown mode %q (known: %s, all)", m, strings.Join(censor.Modes, ", "))
		}
	}
	if !censor.ValidProtocol(protocol) {
		return fmt.Errorf("unknown protocol %q (known: http, https, both)", protocol)
	}
	opts := censor.Options{Modes: strings.Split(mode, ","), DomainsFile: domainsFile, Domain: domain, Protocol: protocol, Retries: retries}
	policy := netx.NewPolicy(censor.Rules(opts)...)
	if c.plan {
		report.WritePlan(os.Stdout, c.color(), policy.Rules())
		return nil
	}
	f := netx.IPv4
	if fams := c.families(); len(fams) == 1 {
		f = fams[0]
	}
	netOpts, err := c.options(f)
	if err != nil {
		return err
	}
	led := ledger.New()
	n := netx.New(netOpts, policy, led)
	s := &session{mode: "censor", mask: c.mask, led: led, censor: censor.Placeholders(opts)}
	screen := startScreen(&c, s)
	defer screen.stop()
	rs := censor.Run(ctx, n, opts)
	s.update(func() { s.censor = rs })
	screen.stop()
	return output(s.report(), &c)
}

func cmdBench(ctx context.Context, args []string) error {
	var c common
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	c.register(fs)
	c.registerExports(fs)
	opts := bench.Defaults()
	var noDisk, noCPU, noNet, noIperf bool
	var diskSize string
	fs.BoolVar(&noDisk, "no-disk", false, "skip the disk test")
	fs.BoolVar(&noCPU, "no-cpu", false, "skip the CPU test")
	fs.BoolVar(&noNet, "no-speed", false, "skip the Cloudflare speed test")
	fs.BoolVar(&noIperf, "no-iperf", false, "skip iperf3")
	fs.StringVar(&opts.DiskDir, "disk-dir", "", "directory for the disk test file (default: temp dir)")
	fs.StringVar(&diskSize, "disk-size", "1G", "disk test file size")
	fs.StringVar(&opts.Servers, "servers", opts.Servers, "iperf3 servers: global, ru, all or host:ports[:provider[:location]],...")
	fs.DurationVar(&opts.Duration, "duration", opts.Duration, "duration of each network transfer")
	fs.BoolVar(&opts.SystemTools, "system", false, "also run installed iperf3 and fio")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	size, err := parseSize(diskSize)
	if err != nil {
		return fmt.Errorf("bad --disk-size: %w", err)
	}
	opts.DiskSize = size
	opts.Disk, opts.CPU, opts.Net, opts.Iperf = !noDisk, !noCPU, !noNet && !c.offline, !noIperf && !c.offline
	if err := opts.Validate(); err != nil {
		return err
	}
	policy := netx.NewPolicy(bench.Rules(opts)...)
	if c.plan {
		report.WritePlan(os.Stdout, c.color(), policy.Rules())
		return nil
	}
	f := netx.IPv4
	if fams := c.families(); len(fams) == 1 {
		f = fams[0]
	}
	netOpts, err := c.options(f)
	if err != nil {
		return err
	}
	led := ledger.New()
	n := netx.New(netOpts, policy, led)
	s := &session{mode: "bench", mask: c.mask, led: led}
	screen := startScreen(&c, s)
	defer screen.stop()
	progress := benchProgress(&c, s, screen)
	b := bench.Run(ctx, bench.Env{Net: n, Ledger: led}, opts, progress)
	progress("")
	s.update(func() { s.bench = &b })
	screen.stop()
	return output(s.report(), &c)
}

func routeTargets(cfg *config.Config, flag string) ([]route.Target, error) {
	targets := route.Targets
	if len(cfg.Route.Targets) > 0 {
		extra, _, err := route.ParseTargets(strings.Join(cfg.Route.Targets, ","))
		if err != nil {
			return nil, fmt.Errorf("config route.targets: %w", err)
		}
		if targets, err = route.Merge(targets, extra); err != nil {
			return nil, err
		}
	}
	if flag == "" {
		return targets, nil
	}
	given, add, err := route.ParseTargets(flag)
	if err != nil {
		return nil, fmt.Errorf("--targets: %w", err)
	}
	if !add {
		targets = nil
	}
	return route.Merge(targets, given)
}

func asnLookup(dbs *geodb.Set) func(netip.Addr) (uint, string) {
	return func(a netip.Addr) (uint, string) {
		for _, r := range dbs.Lookup(a) {
			if r.ASN != 0 {
				return r.ASN, r.ASOrg
			}
		}
		return 0, ""
	}
}

func cmdRoute(ctx context.Context, args []string) error {
	var c common
	var tcpOnly bool
	var targetSpec string
	fs := flag.NewFlagSet("cii route", flag.ContinueOnError)
	fs.StringVar(&targetSpec, "targets", "", "own targets: [+][name=]host[@asn],... (+ adds to the built-in list)")
	c.register(fs)
	c.registerExports(fs)
	opts := route.Defaults()
	fs.BoolVar(&tcpOnly, "tcp", false, "skip ICMP tracing, measure TCP connect time only")
	fs.IntVar(&opts.Rounds, "rounds", opts.Rounds, "ICMP probe rounds (1-15)")
	fs.IntVar(&opts.MaxTTL, "max-hops", opts.MaxTTL, "maximum hops (1-31)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if c.offline {
		return errors.New("--offline: path analysis needs the network")
	}
	if opts.Rounds < 1 || opts.Rounds > 15 || opts.MaxTTL < 1 || opts.MaxTTL > 31 {
		return errors.New("--rounds must be 1-15 and --max-hops 1-31")
	}
	opts.TCPOnly = tcpOnly
	cfg, err := config.Load(c.cfgPath)
	if err != nil {
		return err
	}
	if opts.Targets, err = routeTargets(cfg, targetSpec); err != nil {
		return err
	}
	policy := netx.NewPolicy(route.Rules(opts.Targets)...)
	if c.plan {
		report.WritePlan(os.Stdout, c.color(), policy.Rules())
		return nil
	}
	f := netx.IPv4
	if fams := c.families(); len(fams) == 1 {
		f = fams[0]
	}
	netOpts, err := c.options(f)
	if err != nil {
		return err
	}
	dbs, err := geodb.Open(c.dir())
	if err != nil {
		return err
	}
	defer dbs.Close()
	opts.ASN = asnLookup(dbs)
	led := ledger.New()
	n := netx.New(netOpts, policy, led)
	s := &session{mode: "route", mask: c.mask, dbs: dbs, led: led}
	screen := startScreen(&c, s)
	defer screen.stop()
	rep := route.Run(ctx, n, opts)
	s.update(func() { s.route = rep })
	screen.stop()
	return output(s.report(), &c)
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	given := s
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "G"):
		mult, s = 1<<30, strings.TrimSuffix(s, "G")
	case strings.HasSuffix(s, "M"):
		mult, s = 1<<20, strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "K"):
		mult, s = 1<<10, strings.TrimSuffix(s, "K")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n > math.MaxInt64/mult {
		return 0, fmt.Errorf("expected a number with optional K, M or G suffix up to 8589934591G, got %q", given)
	}
	return n * mult, nil
}
