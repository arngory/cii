package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/datasrc"
	"github.com/arngory/cii/internal/geodb"
	"github.com/arngory/cii/internal/ipdetect"
	"github.com/arngory/cii/internal/ledger"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/paths"
	"github.com/arngory/cii/internal/report"
	"github.com/arngory/cii/internal/version"
)

const usage = `cii — complete information about current IP

Usage:
  cii [flags]                 detect public IPv4/IPv6 and describe them (default)
  cii lookup [flags] IP...    describe given addresses using local data only (no network)
  cii data update [ID...]     download offline databases from their publishers
  cii data status             show local databases
  cii data sources            list supported databases and their licenses
  cii version

Common flags:
  -4 / -6            IPv4 or IPv6 only (default: both)
  --iface NAME       bind outgoing connections to this interface's address
  --source ADDR      bind outgoing connections to this local address
  --proxy URL        http://, https:// or socks5:// proxy for HTTP traffic
  --timeout DUR      per-request timeout (default 10s)
  --offline          never touch the network (local interfaces + databases only)
  --plan             print every destination that may be contacted, then exit
  --json             machine-readable output
  --mask             mask addresses (for screenshots)
  --no-color         disable colours
  --config FILE      config file (default: %s)
  --data-dir DIR     database directory (default: %s)
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
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
	fmt.Fprintf(os.Stderr, usage, config.DefaultPath(), paths.DataDir())
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
	v4, v6, offline, plan, json, mask, noColor bool
	iface, source, proxy, cfgPath, dataDir     string
	timeout                                    time.Duration
}

func (c *common) register(fs *flag.FlagSet) {
	fs.BoolVar(&c.v4, "4", false, "IPv4 only")
	fs.BoolVar(&c.v6, "6", false, "IPv6 only")
	fs.StringVar(&c.iface, "iface", "", "interface")
	fs.StringVar(&c.source, "source", "", "source address")
	fs.StringVar(&c.proxy, "proxy", "", "proxy URL")
	fs.DurationVar(&c.timeout, "timeout", 10*time.Second, "per-request timeout")
	fs.BoolVar(&c.offline, "offline", false, "no network")
	fs.BoolVar(&c.plan, "plan", false, "print destinations and exit")
	fs.BoolVar(&c.json, "json", false, "JSON output")
	fs.BoolVar(&c.mask, "mask", false, "mask addresses")
	fs.BoolVar(&c.noColor, "no-color", false, "disable colours")
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
		o.Source = a
	}
	return o, nil
}

func (c *common) parse(fs *flag.FlagSet, args []string) error {
	c.register(fs)
	return fs.Parse(args)
}

func cmdIP(ctx context.Context, args []string) error {
	var c common
	fs := flag.NewFlagSet("cii", flag.ContinueOnError)
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
	policy := netx.NewPolicy()
	if !c.offline {
		policy.Add(ipdetect.Rules(providers)...)
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
	rep := report.New(mode, c.mask)
	rep.SetData(dbs)

	for _, f := range c.families() {
		opts, err := c.options(f)
		if err != nil {
			setHost(rep, f, report.NewHost(ipdetect.Address{Error: err.Error()}, nil, c.mask))
			continue
		}
		n := netx.New(opts, policy, led)
		addr := ipdetect.Detect(ctx, n, f, ipdetect.Options{Providers: providers, Offline: c.offline, Iface: c.iface})
		var geo []geodb.Record
		if addr.Address.IsValid() {
			geo = dbs.Lookup(addr.Address)
		}
		setHost(rep, f, report.NewHost(addr, geo, c.mask))
	}
	rep.Network = led.Entries()
	return output(rep, &c)
}

func setHost(r *report.Report, f netx.Family, h *report.Host) {
	if f == netx.IPv4 {
		r.IPv4 = h
	} else {
		r.IPv6 = h
	}
}

func output(r *report.Report, c *common) error {
	if c.json {
		return r.WriteJSON(os.Stdout)
	}
	r.WriteText(os.Stdout, c.color())
	return nil
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
	for _, id := range ids {
		s, ok := datasrc.ByID(id)
		if !ok {
			return fmt.Errorf("unknown source %q (see `cii data sources`)", id)
		}
		srcs = append(srcs, s)
	}
	policy := netx.NewPolicy(datasrc.Rules(srcs)...)
	if c.plan {
		report.WritePlan(os.Stdout, c.color(), policy.Rules())
		return nil
	}
	if c.offline {
		return errors.New("--offline: refusing to download")
	}
	opts, err := c.options(netx.Any)
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
	fmt.Println()
	report.WriteContacts(os.Stdout, c.color(), led.Entries())
	if failed > 0 {
		return fmt.Errorf("%d of %d sources failed", failed, len(srcs))
	}
	return nil
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}
