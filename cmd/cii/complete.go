package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/arngory/cii/internal/version"
)

type command struct {
	name, help string
	sub        []string
	probe      []string
}

var shells = []string{"bash", "zsh", "fish"}

var commands = []command{
	{name: "ip", help: "detect the public addresses and check them (the default command)", probe: []string{"ip"}},
	{name: "lookup", help: "describe given addresses from local data, no network", probe: []string{"lookup"}},
	{name: "data", help: "download, show or list the offline databases", sub: []string{"update", "status", "sources"}, probe: []string{"data", "update"}},
	{name: "censor", help: "censorship checks only", probe: []string{"censor"}},
	{name: "bench", help: "benchmark only", probe: []string{"bench"}},
	{name: "route", help: "paths to major networks", probe: []string{"route"}},
	{name: "diff", help: "what changed between two runs", probe: []string{"diff"}},
	{name: "show", help: "print a past run again", probe: []string{"show"}},
	{name: "analyze", help: "conclusions drawn from a past run", probe: []string{"analyze"}},
	{name: "stats", help: "which checks did not always answer", probe: []string{"stats"}},
	{name: "compare", help: "reports from different machines side by side", probe: []string{"compare"}},
	{name: "watch", help: "repeat the check and print what changed", probe: []string{"watch"}},
	{name: "completion", help: "print a shell completion script", sub: shells},
	{name: "man", help: "print the manual page"},
	{name: "version", help: "print the version"},
	{name: "help", help: "print the usage"},
}

type flagInfo struct {
	name, usage string
}

var (
	listing   *[]flagInfo
	errListed = errors.New("flags listed")
)

func parseFlags(fs *flag.FlagSet, args []string) error {
	if listing == nil {
		return fs.Parse(args)
	}
	fs.VisitAll(func(f *flag.Flag) { *listing = append(*listing, flagInfo{f.Name, f.Usage}) })
	return errListed
}

func flagsOf(c command) []flagInfo {
	if c.probe == nil {
		return nil
	}
	var out []flagInfo
	listing = &out
	defer func() { listing = nil }()
	if err := run(context.Background(), c.probe); !errors.Is(err, errListed) {
		return nil
	}
	return out
}

func option(name string) string {
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

func options(c command) []string {
	var out []string
	for _, f := range flagsOf(c) {
		out = append(out, option(f.name))
	}
	return out
}

func commandNames() []string {
	var out []string
	for _, c := range commands {
		out = append(out, c.name)
	}
	return out
}

func cmdCompletion(args []string) error {
	if len(args) != 1 || !slices.Contains(shells, args[0]) {
		return fmt.Errorf("usage: cii completion %s", strings.Join(shells, "|"))
	}
	fmt.Print(completionScript(args[0]))
	return nil
}

func completionScript(shell string) string {
	switch shell {
	case "bash":
		return bashCompletion()
	case "zsh":
		return zshCompletion()
	}
	return fishCompletion()
}

func bashCompletion() string {
	var b strings.Builder
	b.WriteString(`_cii() {
	local cur cmd i
	cur="${COMP_WORDS[COMP_CWORD]}"
	cmd=""
	for ((i = 1; i < COMP_CWORD; i++)); do
		case "${COMP_WORDS[i]}" in
		-*) ;;
		*)
			cmd="${COMP_WORDS[i]}"
			break
			;;
		esac
	done
	COMPREPLY=()
	case "$cur" in
	-*)
		case "$cmd" in
`)
	for _, c := range commands[1:] {
		if opts := options(c); len(opts) > 0 {
			fmt.Fprintf(&b, "\t\t%s) COMPREPLY=($(compgen -W \"%s\" -- \"$cur\")) ;;\n", c.name, strings.Join(opts, " "))
		}
	}
	fmt.Fprintf(&b, "\t\t*) COMPREPLY=($(compgen -W \"%s\" -- \"$cur\")) ;;\n\t\tesac\n\t\t;;\n\t*)\n\t\tcase \"$cmd\" in\n", strings.Join(options(commands[0]), " "))
	fmt.Fprintf(&b, "\t\t\"\") COMPREPLY=($(compgen -W \"%s\" -- \"$cur\")) ;;\n", strings.Join(commandNames(), " "))
	for _, c := range commands {
		if len(c.sub) > 0 {
			fmt.Fprintf(&b, "\t\t%s) COMPREPLY=($(compgen -W \"%s\" -- \"$cur\")) ;;\n", c.name, strings.Join(c.sub, " "))
		}
	}
	b.WriteString("\t\tesac\n\t\t;;\n\tesac\n}\ncomplete -o default -F _cii cii\n")
	return b.String()
}

var zshEscape = strings.NewReplacer(`\`, `\\`, "'", `'\''`, ":", `\:`)

func zshItem(name, help string) string {
	return "'" + zshEscape.Replace(name) + ":" + zshEscape.Replace(help) + "'"
}

func zshFlags(c command) string {
	var parts []string
	for _, f := range flagsOf(c) {
		parts = append(parts, zshItem(option(f.name), f.usage))
	}
	return strings.Join(parts, " ")
}

func zshCompletion() string {
	var b strings.Builder
	b.WriteString("#compdef cii\n\n_cii() {\n\tlocal -a commands flags subs\n\tcommands=(\n")
	for _, c := range commands {
		fmt.Fprintf(&b, "\t\t%s\n", zshItem(c.name, c.help))
	}
	b.WriteString("\t)\n\tlocal cmd=\"\"\n\tif (( CURRENT > 2 )) && [[ ${words[2]} != -* ]]; then\n\t\tcmd=${words[2]}\n\tfi\n\tcase $cmd in\n")
	for _, c := range commands[1:] {
		if flags := zshFlags(c); flags != "" {
			fmt.Fprintf(&b, "\t%s) flags=(%s) ;;\n", c.name, flags)
		}
	}
	fmt.Fprintf(&b, "\t*) flags=(%s) ;;\n\tesac\n\tcase $cmd in\n", zshFlags(commands[0]))
	for _, c := range commands {
		if len(c.sub) > 0 {
			fmt.Fprintf(&b, "\t%s) subs=(%s) ;;\n", c.name, strings.Join(c.sub, " "))
		}
	}
	b.WriteString(`	esac
	if [[ ${words[CURRENT]} == -* ]]; then
		_describe -o 'flag' flags
	elif [[ -z $cmd ]]; then
		_describe 'command' commands
	elif (( ${#subs} > 0 && CURRENT == 3 )); then
		compadd -a subs
	else
		_files
	fi
}

_cii "$@"
`)
	return b.String()
}

func fishQuote(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", `\'`) + "'"
}

func fishCompletion() string {
	var b strings.Builder
	names := strings.Join(commandNames(), " ")
	for _, c := range commands {
		fmt.Fprintf(&b, "complete -c cii -n '__fish_use_subcommand' -a %s -d %s\n", c.name, fishQuote(c.help))
		for _, s := range c.sub {
			fmt.Fprintf(&b, "complete -c cii -f -n '__fish_seen_subcommand_from %s; and not __fish_seen_subcommand_from %s' -a %s\n", c.name, strings.Join(c.sub, " "), s)
		}
	}
	flags := func(c command, cond string) {
		for _, f := range flagsOf(c) {
			kind := "-l"
			if len(f.name) == 1 {
				kind = "-s"
			}
			fmt.Fprintf(&b, "complete -c cii -n %s %s %s -d %s\n", fishQuote(cond), kind, f.name, fishQuote(f.usage))
		}
	}
	flags(commands[0], "not __fish_seen_subcommand_from "+names+"; or __fish_seen_subcommand_from ip")
	for _, c := range commands[1:] {
		flags(c, "__fish_seen_subcommand_from "+c.name)
	}
	return b.String()
}

var (
	usageEntry = regexp.MustCompile(`^  (\S.*?)(?:\s{2,}(.*))?$`)
	roffEscape = strings.NewReplacer(`\`, `\e`, "-", `\-`)
)

func roff(s string) string {
	s = roffEscape.Replace(s)
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "'") {
		s = `\&` + s
	}
	return s
}

func manPage() string {
	var b strings.Builder
	fmt.Fprintf(&b, ".TH CII 1 \"\" \"%s\" \"User Commands\"\n", roff(version.Name+" "+version.Version))
	b.WriteString(".SH NAME\ncii \\- complete information about current IP\n")
	b.WriteString(".SH SYNOPSIS\n.B cii\n[\\fICOMMAND\\fR] [\\fIFLAGS\\fR]\n")
	b.WriteString(".SH DESCRIPTION\n" + roff("cii detects the public IPv4 and IPv6 addresses of this machine and describes them: the country as GeoIP databases and services see it, service availability, IP quality and reputation, censorship on the path, routes to major networks and a benchmark. It contacts only the destinations that cii --plan lists, and it reports results as they are; conclusions come from cii analyze.") + "\n")
	text := fmt.Sprintf(usage, "~/.local/state/cii/logs", "~/.config/cii/config.yaml", "~/.local/share/cii")
	for _, line := range strings.Split(text, "\n")[1:] {
		switch m := usageEntry.FindStringSubmatch(line); {
		case m != nil:
			fmt.Fprintf(&b, ".TP\n\\fB%s\\fR\n%s\n", roff(m[1]), roff(m[2]))
		case strings.HasSuffix(line, ":"):
			title := strings.TrimSuffix(line, ":")
			if title == "Usage" {
				title = "Commands"
			}
			fmt.Fprintf(&b, ".SH %s\n", roff(strings.ToUpper(title)))
		}
	}
	var shared []string
	for _, f := range flagsOf(commands[0]) {
		shared = append(shared, f.name)
	}
	b.WriteString(".SH COMMAND FLAGS\n")
	for _, c := range commands[1:] {
		var own []flagInfo
		for _, f := range flagsOf(c) {
			if !slices.Contains(shared, f.name) {
				own = append(own, f)
			}
		}
		if len(own) == 0 {
			continue
		}
		fmt.Fprintf(&b, ".SS cii %s\n", roff(c.name))
		for _, f := range own {
			fmt.Fprintf(&b, ".TP\n\\fB%s\\fR\n%s\n", roff(option(f.name)), roff(f.usage))
		}
	}
	b.WriteString(".SH FILES\n")
	for _, f := range [][2]string{
		{"~/.config/cii/config.yaml", "Optional configuration: echo services, your own API keys, route targets and service checks. CII_CONFIG_DIR or --config moves it."},
		{"~/.local/share/cii", "Offline databases fetched by cii data update. CII_DATA_DIR or --data-dir moves it."},
		{"~/.local/state/cii/logs", "The last 20 runs, mode 0600, never sent anywhere. CII_LOG_DIR moves it; --no-log turns it off."},
	} {
		fmt.Fprintf(&b, ".TP\n\\fI%s\\fR\n%s\n", roff(f[0]), roff(f[1]))
	}
	b.WriteString(".SH ENVIRONMENT\n")
	for _, e := range [][2]string{
		{"CII_CONFIG_DIR, CII_DATA_DIR, CII_LOG_DIR", "Directories for the config, the databases and the logs."},
		{"CII_*_KEY, CII_IPINFO_TOKEN", "Your own API keys; they take priority over the config file."},
		{"NO_COLOR", "Any value turns colours off."},
		{"LC_ALL, LC_MESSAGES, LANG", "A value that starts with ru selects the Russian interface; --lang overrides it."},
		{"HTTPS_PROXY, HTTP_PROXY, ALL_PROXY, NO_PROXY", "Proxy for HTTP traffic when --proxy is not given."},
	} {
		fmt.Fprintf(&b, ".TP\n\\fB%s\\fR\n%s\n", roff(e[0]), roff(e[1]))
	}
	b.WriteString(".SH SEE ALSO\n" + roff("Documentation: https://github.com/arngory/cii/tree/main/docs") + "\n")
	return b.String()
}
