package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/arngory/cii/internal/geodb"
	"github.com/arngory/cii/internal/paths"
	"github.com/arngory/cii/internal/report"
	"github.com/arngory/cii/internal/version"
)

type menuItem struct {
	args   []string
	report bool
	title  map[string]string
	hint   map[string]string
}

var menu = []menuItem{
	{[]string{"ip"}, true,
		map[string]string{"en": "Standard check", "ru": "Обычная проверка"},
		map[string]string{"en": "address, IP quality, region, services, reputation, censorship", "ru": "адрес, качество IP, регион, сервисы, репутация, цензура"}},
	{[]string{"ip", "--extended"}, true,
		map[string]string{"en": "Extended check", "ru": "Расширенная проверка"},
		map[string]string{"en": "standard + vendors' internal APIs, risk pages, DPI and geoblock lists", "ru": "обычная + внутренние API сервисов, страницы риска, списки DPI и геоблокировок"}},
	{[]string{"ip", "--extended", "--route", "--bench"}, true,
		map[string]string{"en": "Everything", "ru": "Всё сразу"},
		map[string]string{"en": "extended + routes + benchmark (minutes, 1 GiB on disk)", "ru": "расширенная + маршруты + бенчмарк (минуты, 1 ГиБ на диске)"}},
	{[]string{"ip", "--quick"}, true,
		map[string]string{"en": "Quick", "ru": "Быстро"},
		map[string]string{"en": "address and local databases only", "ru": "только адрес и локальные базы"}},
	{[]string{"censor"}, true,
		map[string]string{"en": "Censorship only", "ru": "Только цензура"},
		map[string]string{"en": "DNS, DPI, geoblocking, Telegram, connectivity checks", "ru": "DNS, DPI, геоблокировки, Telegram, проверки связи"}},
	{[]string{"route"}, true,
		map[string]string{"en": "Routes only", "ru": "Только маршруты"},
		map[string]string{"en": "paths to major networks (hops need root)", "ru": "пути к крупным сетям (для хопов нужен root)"}},
	{[]string{"bench"}, true,
		map[string]string{"en": "Benchmark only", "ru": "Только бенчмарк"},
		map[string]string{"en": "system, disk, CPU, speed, iperf3", "ru": "система, диск, CPU, скорость, iperf3"}},
	{[]string{"show"}, true,
		map[string]string{"en": "Show the last run", "ru": "Показать прошлый запуск"},
		map[string]string{"en": "from the local log, no network", "ru": "из локального лога, без сети"}},
	{[]string{"analyze"}, true,
		map[string]string{"en": "Analyse the last run", "ru": "Разобрать прошлый запуск"},
		map[string]string{"en": "conclusions from the local log, no network", "ru": "выводы по локальному логу, без сети"}},
	{[]string{"data", "update"}, false,
		map[string]string{"en": "Update databases", "ru": "Обновить базы"},
		map[string]string{"en": "DB-IP Lite and range lists from their publishers", "ru": "DB-IP Lite и списки диапазонов у издателей"}},
}

var menuTexts = map[string]map[string]string{
	"en": {
		"prompt":  "Number (add m to hide addresses and provider, e.g. 2m; 0 exits) [1]: ",
		"short":   "Number (2m masks, 0 exits) [1]: ",
		"bad":     "Enter a number from 0 to %d, optionally followed by m.",
		"nodata":  "No local databases yet: %d downloads them (country and ASN without asking services).",
		"tagline": "complete information about current IP",
	},
	"ru": {
		"prompt":  "Номер (добавьте m, чтобы скрыть адреса и провайдера, например 2m; 0 — выход) [1]: ",
		"short":   "Номер (2m — маска, 0 — выход) [1]: ",
		"bad":     "Введите число от 0 до %d, при желании с буквой m.",
		"nodata":  "Локальных баз пока нет: пункт %d скачает их (страна и ASN без обращений к сервисам).",
		"tagline": "полная информация о текущем IP",
	},
}

var choicePattern = regexp.MustCompile(`(?i)^(\d{1,2})(m?)$`)

var errMenuExit = errors.New("exit")

func parseChoice(s string) ([]string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		s = "1"
	}
	m := choicePattern.FindStringSubmatch(s)
	if m == nil {
		return nil, fmt.Errorf("bad choice %q", s)
	}
	n, _ := strconv.Atoi(m[1])
	if n == 0 {
		return nil, errMenuExit
	}
	if n > len(menu) {
		return nil, fmt.Errorf("bad choice %q", s)
	}
	item := menu[n-1]
	args := append([]string(nil), item.args...)
	if m[2] == "m" && item.report {
		args = append(args, "--mask")
	}
	return args, nil
}

func interactive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func menuWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	return 80
}

func menuPrompt(lang string, width int) string {
	t := menuTexts[lang]
	if len([]rune(t["prompt"])) >= width {
		return t["short"]
	}
	return t["prompt"]
}

func menuLines(lang string, width int) []string {
	titleW, hintW := 0, 0
	for _, it := range menu {
		titleW = max(titleW, len([]rune(it.title[lang])))
		hintW = max(hintW, len([]rune(it.hint[lang])))
	}
	hints := 6+titleW+2+hintW <= width
	var out []string
	for i, it := range menu {
		line := fmt.Sprintf("  %2d  %s", i+1, it.title[lang])
		if hints {
			line += strings.Repeat(" ", titleW-len([]rune(it.title[lang]))) + "  " + it.hint[lang]
		}
		out = append(out, line)
	}
	return out
}

func printMenu(lang string) {
	t := menuTexts[lang]
	width := menuWidth()
	c := func(code, s string) string {
		if !report.ColorEnabled() {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	fmt.Printf("%s %s — %s\n\n", c("1", version.Name), version.Version, t["tagline"])
	for i, line := range menuLines(lang, width) {
		title := "  " + fmt.Sprintf("%2d", i+1) + "  " + menu[i].title[lang]
		fmt.Println(c("1", line[:6]) + line[6:len(title)] + c("2", line[len(title):]))
	}
	fmt.Println()
	if dbs, err := geodb.Open(paths.DataDir()); err == nil {
		empty := len(dbs.DBs) == 0
		dbs.Close()
		if empty {
			for _, l := range wrapWords(fmt.Sprintf(t["nodata"], len(menu)), width) {
				fmt.Println(c("33", l))
			}
		}
	}
}

func runMenu(ctx context.Context) error {
	lang := report.DetectLang()
	printMenu(lang)
	lines := make(chan string)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	for range 3 {
		fmt.Print(menuPrompt(lang, menuWidth()))
		var line string
		var ok bool
		select {
		case <-ctx.Done():
			fmt.Println()
			return nil
		case line, ok = <-lines:
			if !ok {
				fmt.Println()
				return nil
			}
		}
		args, err := parseChoice(line)
		switch {
		case errors.Is(err, errMenuExit):
			return nil
		case err != nil:
			fmt.Printf(menuTexts[lang]["bad"]+"\n", len(menu))
			continue
		}
		fmt.Println()
		return run(ctx, args)
	}
	return errors.New("no valid choice")
}

func wrapWords(s string, width int) []string {
	var out []string
	line := ""
	for _, w := range strings.Fields(s) {
		if line != "" && len([]rune(line))+1+len([]rune(w)) > width {
			out = append(out, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}
