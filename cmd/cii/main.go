package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
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
	"github.com/arngory/cii/internal/runlog"
	"github.com/arngory/cii/internal/services"
	"github.com/arngory/cii/internal/version"
)

const usage = `cii — complete information about current IP

Usage:
  cii [flags]                 detect public IPv4/IPv6, describe them, check services, reputation and censorship (default)
  cii lookup [flags] IP...    describe given addresses using local data only (no network)
  cii data update [ID...]     download offline databases from their publishers
  cii data status             show local databases
  cii data sources            list supported databases and their licenses
  cii censor [flags]          only censorship: all modes, own lists and domains (see docs/CENSOR_CHECKS.md)
  cii bench [flags]           only the benchmark, with its own options (see docs/BENCH.md)
  cii version

Default command only:
  --no-censor        skip censorship checks (DNS and Telegram; DPI and geoblock with --extended)
  --bench            also run the benchmark after the checks: disk, CPU, Cloudflare speed, iperf3

Common flags:
  -4 / -6            IPv4 or IPv6 only (default: both)
  --iface NAME       bind outgoing connections to this interface's address
  --source ADDR      bind outgoing connections to this local address
  --proxy URL        http://, https:// or socks5:// proxy for HTTP traffic
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
  --mask             mask addresses (for screenshots)
  --no-color         disable colours
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
	cmd := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
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
	v4, v6, offline, plan, json, mask, noColor, quick, extended, debug, noLog, noRisk bool
	iface, source, proxy, cfgPath, dataDir, catalog                                   string
	timeout                                                                           time.Duration
}

func (c *common) register(fs *flag.FlagSet) {
	fs.BoolVar(&c.v4, "4", false, "IPv4 only")
	fs.BoolVar(&c.v6, "6", false, "IPv6 only")
	fs.StringVar(&c.iface, "iface", "", "interface")
	fs.StringVar(&c.source, "source", "", "source address")
	fs.StringVar(&c.proxy, "proxy", "", "proxy URL")
	fs.DurationVar(&c.timeout, "timeout", 10*time.Second, "per-request timeout")
	fs.BoolVar(&c.offline, "offline", false, "no network")
	fs.BoolVar(&c.quick, "quick", false, "skip region and service checks")
	fs.BoolVar(&c.extended, "extended", false, "run tier-B checks")
	fs.StringVar(&c.catalog, "catalog", "auto", "regional service catalogs")
	fs.BoolVar(&c.noRisk, "no-risk", false, "skip reputation, DNSBL and SMTP checks")
	fs.BoolVar(&c.plan, "plan", false, "print destinations and exit")
	fs.BoolVar(&c.json, "json", false, "JSON output")
	fs.BoolVar(&c.mask, "mask", false, "mask addresses")
	fs.BoolVar(&c.noColor, "no-color", false, "disable colours")
	fs.BoolVar(&c.debug, "debug", false, "detailed output")
	fs.BoolVar(&c.noLog, "no-log", false, "do not write a local log")
	fs.StringVar(&c.cfgPath, "config", "", "config file")
	fs.StringVar(&c.dataDir, "data-dir", "", "database directory")
	fs.Usage = printUsage
}

func (c *common) color() bool { return !c.noColor && !c.json && report.ColorEnabled() }

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
	return fs.Parse(args)
}

func cmdIP(ctx context.Context, args []string) error {
	var c common
	var withBench, noCensor bool
	fs := flag.NewFlagSet("cii", flag.ContinueOnError)
	fs.BoolVar(&withBench, "bench", false, "also run the benchmark (disk, CPU, speed, iperf3)")
	fs.BoolVar(&noCensor, "no-censor", false, "skip censorship checks")
	if err := c.parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q (did you mean `cii lookup`?)", fs.Arg(0))
	}
	cfg, err := config.Load(c.cfgPath)
	if err != nil {
		return err
	}
	if _, err := c.baseOptions(); err != nil {
		return err
	}

	providers := cfg.IPEcho
	if len(providers) == 0 {
		providers = ipdetect.DefaultProviders
	}
	if c.quick && c.extended {
		return errors.New("--quick and --extended are mutually exclusive")
	}
	var checks []probe.Check
	var catalogs []string
	riskOn := !c.quick && !c.noRisk
	if !c.quick {
		checks = append(region.Select(cfg.Keys, c.extended), services.Select(cfg.Keys, c.extended)...)
		if catalogs, err = c.catalogs(); err != nil {
			return err
		}
	}
	if riskOn {
		checks = append(checks, risk.Checks(cfg.Keys, c.extended)...)
	}
	censorOn := !c.quick && !noCensor && !c.offline
	censorOpts := censor.Options{Modes: []string{"dns", "telegram"}, Protocol: "both"}
	if c.extended {
		censorOpts.Modes = nil
	}
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
	}
	if c.plan {
		report.WritePlan(os.Stdout, c.color(), policy.Rules())
		return nil
	}

	led := ledger.New()

	dbs, err := geodb.Open(c.dir())
	if err != nil {
		return err
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
	var detect sync.WaitGroup
	for _, f := range c.families() {
		detect.Go(func() {
			h := &hostRun{family: f}
			var n *netx.Net
			if opts, err := c.options(f); err != nil {
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
					nets[f] = n
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
	plan := stackPlan{c: &c, s: s, nets: nets, keys: cfg.Keys, checks: checks, catalogs: catalogs, risk: riskOn}
	var stacks sync.WaitGroup
	for _, h := range s.hosts {
		if h.addr.Address.IsValid() {
			stacks.Go(func() { plan.checkHost(ctx, h) })
		}
	}
	stacks.Wait()
	side.Wait()
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
	return output(s.report(), &c)
}

type stackPlan struct {
	c        *common
	s        *session
	nets     map[netx.Family]*netx.Net
	keys     config.Keys
	checks   []probe.Check
	catalogs []string
	risk     bool
}

func (p stackPlan) checkHost(ctx context.Context, h *hostRun) {
	ip := h.addr.Address
	if !p.c.offline {
		env := probe.Env{Nets: p.nets, Keys: p.keys, Done: func(i int, rs []probe.Result) { p.s.update(func() { h.checks[i] = rs }) }}
		probe.Run(ctx, env, h.family, ip, p.checks)
		regional := services.SelectRegional(p.c.catalogsFor(p.catalogs, p.s.verdict(h)), p.keys, p.c.extended)
		p.s.update(func() { h.regional = slots(probe.Placeholders(regional)) })
		env.Done = func(i int, rs []probe.Result) { p.s.update(func() { h.regional[i] = rs }) }
		probe.Run(ctx, env, h.family, ip, regional)
		if p.risk {
			rs := risk.Run(ctx, p.nets[h.family], ip, risk.Options{})
			p.s.update(func() { h.risk = rs })
		}
	}
	if p.risk {
		rs := risk.Offline(p.c.dir(), ip)
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
	if logErr != nil && (c.json || c.debug) {
		fmt.Fprintln(os.Stderr, "cii: log not written:", logErr)
	}
	switch {
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
	style := report.Style{Color: c.color(), Unicode: unicode, Width: terminalWidth()}
	if usesScreen(r) {
		fmt.Println(strings.Join(r.Screen(style, screenTitle(r), footer(r, unicode, logPath, logErr)), "\n"))
		return nil
	}
	r.WriteCompact(os.Stdout, style, footer(r, unicode, logPath, logErr))
	return nil
}

const logScreenWidth = 160

func usesScreen(r *report.Report) bool { return r.Mode != "lookup" }

func screenTitle(r *report.Report) string { return r.Tool.Name + " " + r.Tool.Version }

func writeLog(r *report.Report, c *common) (string, error) {
	if c.noLog {
		return "", nil
	}
	var text, js bytes.Buffer
	if usesScreen(r) {
		text.WriteString(strings.Join(r.Screen(report.Style{Unicode: true, Width: logScreenWidth}, screenTitle(r), nil), "\n") + "\n\n")
	}
	r.WriteDetailed(&text, false)
	if err := r.WriteJSON(&js); err != nil {
		return "", err
	}
	return runlog.Write(paths.LogDir(), time.Now(), text.Bytes(), []byte("\n--- JSON ---\n"), js.Bytes())
}

func footer(r *report.Report, unicode bool, logPath string, logErr error) []string {
	var parts []string
	if legend := report.Legend(r, unicode); legend != "" {
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
		parts = append(parts, "1 host contacted")
	case len(hosts) > 1:
		parts = append(parts, fmt.Sprintf("%d hosts contacted", len(hosts)))
	default:
		parts = append(parts, "no network contacts")
	}
	if n := r.FailedChecks(); n > 0 {
		parts = append(parts, fmt.Sprintf("%d checks failed", n))
	}
	if r.Extended() {
		parts = append(parts, "* --extended check")
	}
	parts = append(parts, r.Attribution...)
	switch {
	case logErr != nil:
		parts = append(parts, "log not written: "+logErr.Error())
	case logPath != "":
		parts = append(parts, "details: --debug or "+logPath)
	default:
		parts = append(parts, "details: --debug")
	}
	return parts
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

	rep := report.New("lookup", c.mask)
	rep.SetData(dbs)
	for _, arg := range fs.Args() {
		a, err := netip.ParseAddr(arg)
		if err != nil {
			return fmt.Errorf("bad address %q", arg)
		}
		a = a.Unmap()
		h := report.NewHost(ipdetect.Address{Address: a, Source: "argument"}, dbs.Lookup(a), c.mask)
		h.Query = h.Address
		rep.Results = append(rep.Results, h)
	}
	return output(rep, &c)
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
			fmt.Printf("risk:%-13s ok  %d prefixes, sha256 %s\n", e.ID, e.Prefixes, shortHash(e.SHA256))
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
	fs.StringVar(&mode, "mode", "all", "all, dns, dpi, geoblock, telegram (comma-separated)")
	fs.StringVar(&domainsFile, "domains", "", "file with one domain per line instead of the built-in lists")
	fs.StringVar(&domain, "domain", "", "check a single domain")
	fs.StringVar(&protocol, "protocol", "both", "http, https or both")
	fs.IntVar(&retries, "retries", 0, "extra attempts per target")
	if err := fs.Parse(args); err != nil {
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
