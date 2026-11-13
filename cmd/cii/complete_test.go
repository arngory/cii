package main

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestCommandTableMatchesUsage(t *testing.T) {
	inUsage := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^  cii ([a-z]+)`).FindAllStringSubmatch(usage, -1) {
		inUsage[m[1]] = true
	}
	for _, c := range commands {
		if !inUsage[c.name] && c.name != "ip" && c.name != "help" {
			t.Errorf("command %s is missing from the usage text", c.name)
		}
		delete(inUsage, c.name)
		if c.probe == nil {
			continue
		}
		flags := flagsOf(c)
		if len(flags) == 0 {
			t.Errorf("command %s lists no flags", c.name)
		}
		for _, f := range flags {
			if f.usage == "" {
				t.Errorf("flag --%s of %s has no description", f.name, c.name)
			}
		}
	}
	for name := range inUsage {
		t.Errorf("usage names the command %s, which the completion table lacks", name)
	}
	if listing != nil {
		t.Fatal("flag listing mode was left on")
	}
	if err := run(context.Background(), []string{"no-such-command"}); err == nil || errors.Is(err, errListed) {
		t.Errorf("unknown command = %v", err)
	}
}

func TestFlagsOf(t *testing.T) {
	names := func(name string) []string {
		i := slices.IndexFunc(commands, func(c command) bool { return c.name == name })
		return options(commands[i])
	}
	for cmd, want := range map[string][]string{
		"ip": {"-4", "--mask", "--html", "--demo", "--bench"}, "route": {"--tcp", "--targets", "--mask"},
		"watch": {"--every", "--count"}, "censor": {"--mode", "--domain"}, "bench": {"--no-disk"}, "data": {"--config"},
	} {
		got := names(cmd)
		for _, w := range want {
			if !slices.Contains(got, w) {
				t.Errorf("%s lacks %s: %v", cmd, w, got)
			}
		}
	}
	if slices.Contains(names("lookup"), "--demo") || len(names("man")) != 0 {
		t.Error("flags of one command leaked into another")
	}
}

func TestBashCompletion(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	script := bashCompletion() + `
t() { COMP_WORDS=("$@"); COMP_CWORD=$(($# - 1)); _cii; echo "${COMPREPLY[*]}"; }
t cii ro
t cii route --tc
t cii --ma
t cii data ""
t cii completion ""
t cii watch --ev
t cii show --sv
`
	out, err := exec.Command(bash, "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	want := "route\n--tcp\n--mask\nupdate status sources\nbash zsh fish\n--every\n--svg\n"
	if string(out) != want {
		t.Errorf("completions:\n%s\nwant:\n%s", out, want)
	}
}

func TestCompletionScripts(t *testing.T) {
	zsh := completionScript("zsh")
	for _, want := range []string{"#compdef cii\n", "'route:paths to major networks'", "route) flags=(", "'--tcp:skip ICMP tracing, measure TCP connect time only'",
		"data) subs=(update status sources) ;;", `'--targets:own targets\: [+][name=]host[@asn],... (+ adds to the built-in list)'`} {
		if !strings.Contains(zsh, want) {
			t.Errorf("zsh script lacks %q", want)
		}
	}
	fish := completionScript("fish")
	for _, want := range []string{"complete -c cii -n '__fish_use_subcommand' -a route -d 'paths to major networks'\n",
		"complete -c cii -n '__fish_seen_subcommand_from route' -l tcp -d 'skip ICMP tracing, measure TCP connect time only'\n",
		" -s 4 -d 'IPv4 only'\n", "-a update\n"} {
		if !strings.Contains(fish, want) {
			t.Errorf("fish script lacks %q", want)
		}
	}
	for name, script := range map[string]string{"zsh": zsh, "fish": fish} {
		for i, line := range strings.Split(script, "\n") {
			if strings.Count(strings.ReplaceAll(strings.ReplaceAll(line, `'\''`, ""), `\'`, ""), "'")%2 != 0 {
				t.Errorf("%s line %d has an unbalanced quote: %s", name, i+1, line)
			}
		}
	}
	if err := cmdCompletion([]string{"powershell"}); err == nil {
		t.Error("an unknown shell was accepted")
	}
	if err := cmdCompletion(nil); err == nil {
		t.Error("a missing shell was accepted")
	}
}

func TestManPage(t *testing.T) {
	page := manPage()
	if !strings.HasPrefix(page, ".TH CII 1 ") {
		t.Fatalf("no title line:\n%.200s", page)
	}
	macro := regexp.MustCompile(`^\.(TH|SH|SS|TP|B)( |$)`)
	for i, line := range strings.Split(page, "\n") {
		if (strings.HasPrefix(line, ".") || strings.HasPrefix(line, "'")) && !macro.MatchString(line) {
			t.Errorf("line %d would be read as an unknown request: %s", i+1, line)
		}
		if strings.Contains(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(line, `\-`, ""), `\e`, ""), `\f`, ""), `\&`, ""), `\`) {
			t.Errorf("line %d has an unescaped backslash: %s", i+1, line)
		}
	}
	for _, want := range []string{".SH NAME\n", ".SH COMMANDS\n", ".SH COMMON FLAGS\n", ".SH COMMAND FLAGS\n", ".SS cii route\n", `\fB\-\-tcp\fR`, `\fB\-\-mask\fR`,
		`\fBcii lookup [flags] IP...\fR`, ".SH FILES\n", ".SH ENVIRONMENT\n", "~/.config/cii/config.yaml", ".SH SEE ALSO\n"} {
		if !strings.Contains(page, want) {
			t.Errorf("manual page lacks %q", want)
		}
	}
	if strings.Contains(page, "%!") || strings.Contains(page, "/home/") || strings.Contains(page, "/root/") {
		t.Errorf("manual page has a formatting error or a path of this machine")
	}
}
