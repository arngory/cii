package report

import (
	"cmp"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"

	"github.com/arngory/cii/internal/censor"
	"github.com/arngory/cii/internal/probe"
	"github.com/arngory/cii/internal/risk"
	"github.com/arngory/cii/internal/route"
)

const (
	Alert = "alert"
	Warn  = "warn"
	Info  = "info"
)

type Finding struct {
	Level  string `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

var analysisRU = map[string]string{
	"Address is classed as hosting (%s)":                                                          "Адрес считается хостинговым (%s)",
	"Streaming and AI services often refuse hosting ranges whatever the country.":                 "Стриминг и AI-сервисы часто отказывают хостинговым диапазонам независимо от страны.",
	"Sources disagree on the address type: %s":                                                    "Источники расходятся в типе адреса: %s",
	"%s flagged by %d of %d sources: %s":                                                          "%s: отметили %d из %d источников: %s",
	"High risk score: %s":                                                                         "Высокая оценка риска: %s",
	"Registration country %s differs from where services see the address (%s)":                    "Страна регистрации %s не совпадает с тем, где адрес видят сервисы (%s)",
	"%s reports %s, the country of its CDN edge (%s)":                                             "%s сообщает %s — это страна его узла CDN (%s)",
	"This is how the service picks a country, not a geolocation mismatch.":                        "Так сервис выбирает страну; это не расхождение геолокации.",
	"%s sees the address in %s, not %s":                                                           "%s видит адрес в %s, а не в %s",
	"Sources are split between countries: %s":                                                     "Источники разделились между странами: %s",
	"Not available from here: %s":                                                                 "Отсюда недоступны: %s",
	"Refuse this address or network, not the country: %s":                                         "Отказывают этому адресу или сети, а не стране: %s",
	"Listed in %d DNSBL: %s":                                                                      "Адрес в %d чёрных списках: %s",
	"Mail from this address is likely to be rejected.":                                            "Почту с этого адреса, скорее всего, будут отклонять.",
	"Spamhaus was not checked: the query went through a public resolver":                          "Spamhaus не проверен: запрос ушёл через публичный резолвер",
	"Use your own recursive resolver to get an answer from this list.":                            "Чтобы получить ответ этого списка, нужен собственный рекурсивный резолвер.",
	"Outbound port 25 is closed: mail cannot be sent directly from this address":                  "Исходящий порт 25 закрыт: напрямую с этого адреса почту не отправить",
	"Address is in a known range: %s":                                                             "Адрес входит в известный диапазон: %s",
	"Echo services saw different addresses: %s":                                                   "Echo-сервисы увидели разные адреса: %s",
	"Traffic is split between several exits (policy routing or a balancer).":                      "Трафик расходится по нескольким выходам (маршрутизация по правилам или балансировщик).",
	"No IPv6: the resolver returns no AAAA records":                                               "IPv6 нет: резолвер не отдаёт AAAA-записи",
	"IPv6 is switched off or filtered on this network.":                                           "IPv6 выключен или фильтруется в этой сети.",
	"Port 53 DNS is intercepted on the path":                                                      "DNS на 53-м порту перехватывается по пути",
	"%s. Answers match the reference, so this is a transparent forwarder; DoH and DoT bypass it.": "%s. Ответы совпадают с эталоном, значит это прозрачный форвардер; DoH и DoT его обходят.",
	"%s. Some answers are also spoofed.":                                                          "%s. Часть ответов к тому же подменена.",
	"DNS answers are spoofed: %s":                                                                 "Ответы DNS подменяются: %s",
	"Encrypted DNS is blocked: %s":                                                                "Шифрованный DNS блокируется: %s",
	"Telegram data centres unreachable: %d of %d":                                                 "Недоступны дата-центры Telegram: %d из %d",
	"Blocked on the path (DPI): %s":                                                               "Блокируются по пути (DPI): %s",
	"Refuse this country or network: %s":                                                          "Отказывают этой стране или сети: %s",
	"Plain HTTP or TLS is altered on the path":                                                    "HTTP или TLS изменяется по пути",
	"Connectivity check endpoints did not answer: %d":                                             "Адреса проверки связи не ответили: %d",
	"Port 25 is open, but the mail server did not accept this address":                            "Порт 25 открыт, но почтовый сервер не принял этот адрес",
	"Traffic leaves through a tunnel":                                                             "Трафик уходит через туннель",
	"Every result describes the tunnel exit, not this machine's own connection.":                  "Все результаты описывают выход туннеля, а не собственное подключение этой машины.",
	"DNS queries leave through a resolver in %s, while the address is in %s":                      "DNS-запросы уходят через резолвер в %s, а адрес находится в %s",
	"Behind a VPN or proxy this is a DNS leak: the resolver's operator sees the names you look up. Without one it is just a resolver abroad.": "За VPN или прокси это утечка DNS: оператор резолвера видит имена, которые вы запрашиваете. Без них это просто резолвер за границей.",
	"The resolver passes your subnet on to name servers (ECS)":                                                                                "Резолвер передаёт вашу подсеть серверам имён (ECS)",
	"The sites' name servers learn the network a query came from, though not the exact address.":                                              "Серверы имён сайтов узнают сеть, из которой пришёл запрос, но не точный адрес.",
	"Interface MTU is %s": "MTU интерфейса — %s",
	"Below 1500 there is a tunnel or PPPoE on the way; large packets are fragmented or rely on path MTU discovery.": "Меньше 1500 — на пути туннель или PPPoE; большие пакеты фрагментируются или зависят от определения MTU пути.",
	"UDP does not get through: no STUN server answered":                                                             "UDP не проходит: не ответил ни один STUN-сервер",
	"Calls, WireGuard, QUIC and peer-to-peer connections rely on UDP.":                                              "От UDP зависят звонки, WireGuard, QUIC и прямые соединения между узлами.",
	"NAT is symmetric": "NAT симметричный",
	"Each destination gets its own port mapping, so peer-to-peer connections need a relay.":   "Для каждого адресата выдаётся свой порт, поэтому прямым соединениям между узлами нужен ретранслятор.",
	"Carrier-grade NAT: the public address is shared with other subscribers":                  "NAT оператора (CGNAT): публичный адрес общий с другими абонентами",
	"Inbound connections and port forwarding are not possible.":                               "Входящие соединения и проброс портов невозможны.",
	"UDP leaves through another address than HTTP":                                            "UDP выходит через другой адрес, чем HTTP",
	"Traffic is split between exits by protocol.":                                             "Трафик разделён между выходами по протоколу.",
	"Blocked by name (SNI or Host), not by address: %s":                                       "Блокируются по имени (SNI или Host), а не по адресу: %s",
	"The addresses themselves answer; only connections that carry the name are cut.":          "Сами адреса отвечают; обрываются только соединения, в которых названо имя.",
	"QUIC (HTTP/3) does not get through: %s":                                                  "QUIC (HTTP/3) не проходит: %s",
	"Browsers fall back to TCP; applications that need QUIC will not work.":                   "Браузеры перейдут на TCP; приложения, которым нужен QUIC, работать не будут.",
	"DNS is answered by a local fake-IP proxy":                                                "DNS отвечает локальный прокси в режиме fake-IP",
	"Route probes were answered locally":                                                      "На замеры маршрутов ответили локально",
	"A local proxy, tunnel or sandbox ends the connections; path verdicts mean nothing here.": "Соединения завершает локальный прокси, туннель или песочница; вердикты маршрутов здесь ничего не значат.",
	"Detours: %s":                  "Крюки: %s",
	"Through transit networks: %s": "Через транзитные сети: %s",
	"Unreachable: %s":              "Недоступны: %s",
	"No hop data for routes":       "Нет данных о хопах маршрутов",
	"No local databases":           "Нет локальных баз",
	"Run `cii data update` for country and ASN without asking services.": "Выполните `cii data update`: страна и ASN будут определяться без обращений к сервисам.",
	"%d checks gave no answer": "%d проверок не дали ответа",
	"See them with --debug; `cii stats` shows which ones never answer.": "Они видны с --debug; `cii stats` покажет, какие не отвечают никогда.",
	"Nothing unusual found": "Ничего необычного не найдено",
}

type analysis struct {
	lang string
	out  []Finding
}

func (a *analysis) t(s string, args ...any) string {
	if a.lang == "ru" {
		if v, ok := analysisRU[s]; ok {
			s = v
		}
	}
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}

func (a *analysis) add(level, title, detail string) {
	a.out = append(a.out, Finding{Level: level, Title: title, Detail: detail})
}

func names(rs []probe.Result) string {
	var out []string
	for _, r := range rs {
		if !slices.Contains(out, r.Service) {
			out = append(out, r.Service)
		}
	}
	return strings.Join(out, ", ")
}

func pick(rs []probe.Result, keep func(probe.Result) bool) []probe.Result {
	var out []probe.Result
	for _, r := range rs {
		if keep(r) {
			out = append(out, r)
		}
	}
	return out
}

func riskGroup(g probe.Group) bool {
	return g == risk.Reputation || g == risk.DNSBL || g == risk.Mail || g == risk.Network
}

func Analyze(r *Report, lang string) []Finding {
	a := &analysis{lang: lang}
	fams := r.families()
	withAddr := 0
	for _, f := range fams {
		if f.host.Address != "" {
			withAddr++
		}
	}
	for _, f := range fams {
		prefix := ""
		if withAddr > 1 {
			prefix = f.label + ": "
		}
		before := len(a.out)
		a.host(f.label, f.host)
		for i := before; i < len(a.out); i++ {
			a.out[i].Title = prefix + a.out[i].Title
		}
	}
	a.censor(r.Censor)
	a.resolverExit(r)
	a.transport(r)
	if r.Route != nil {
		a.route(r.Route)
	}
	unanswered := 0
	for _, f := range fams {
		for _, res := range f.host.factResults() {
			if res.Status == probe.Failed {
				unanswered++
			}
		}
	}
	if len(r.Data) == 0 && (r.Mode == "online" || r.Mode == "offline" || r.Mode == "lookup") {
		a.add(Info, a.t("No local databases"), a.t("Run `cii data update` for country and ASN without asking services."))
	}
	if unanswered > 0 {
		a.add(Info, a.t("%d checks gave no answer", unanswered), a.t("See them with --debug; `cii stats` shows which ones never answer."))
	}
	order := map[string]int{Alert: 0, Warn: 1, Info: 2}
	slices.SortStableFunc(a.out, func(x, y Finding) int { return cmp.Compare(order[x.Level], order[y.Level]) })
	if !slices.ContainsFunc(a.out, func(f Finding) bool { return f.Level != Info }) {
		a.out = append([]Finding{{Level: Info, Title: a.t("Nothing unusual found")}}, a.out...)
	}
	return a.out
}

func (a *analysis) host(label string, h *Host) {
	if h.Address == "" {
		if label == "IPv6" && strings.Contains(h.Error, "no AAAA records") {
			a.add(Info, a.t("No IPv6: the resolver returns no AAAA records"), a.t("IPv6 is switched off or filtered on this network."))
		}
		return
	}
	if len(h.Disagree) > 0 {
		a.add(Warn, a.t("Echo services saw different addresses: %s", strings.Join(h.Disagree, "; ")), a.t("Traffic is split between several exits (policy routing or a balancer)."))
	}
	if p := h.Profile; p != nil {
		if len(p.Usage) > 0 && p.Usage[0].Value == "hosting" {
			a.add(Warn, a.t("Address is classed as hosting (%s)", strings.Join(p.Usage[0].Sources, ", ")), a.t("Streaming and AI services often refuse hosting ranges whatever the country."))
		} else if len(p.Usage) > 1 {
			var parts []string
			for _, v := range p.Usage {
				parts = append(parts, v.Value+" — "+strings.Join(v.Sources, ", "))
			}
			a.add(Info, a.t("Sources disagree on the address type: %s", strings.Join(parts, "; ")), "")
		}
		for _, f := range p.Factors {
			if len(f.Hits) > 0 && f.Flag != probe.Hosting {
				a.add(Warn, a.t("%s flagged by %d of %d sources: %s", flagTitles[f.Flag], len(f.Hits), f.Checked, strings.Join(f.Hits, ", ")), "")
			}
		}
		if p.GeoConsistent != nil && !*p.GeoConsistent && h.Region != nil {
			a.add(Warn, a.t("Registration country %s differs from where services see the address (%s)", p.Registered, strings.Join(h.Region.Verdict, "/")), "")
		}
	}
	var high []string
	for _, res := range h.factResults() {
		if res.Facts != nil && res.Facts.Level != nil && res.Facts.Score != nil && *res.Facts.Level >= 3 {
			high = append(high, fmt.Sprintf("%s %d", res.Service, *res.Facts.Score))
		}
	}
	if len(high) > 0 {
		a.add(Warn, a.t("High risk score: %s", strings.Join(high, ", ")), "")
	}
	if s := h.Region; s != nil {
		if len(s.Verdict) > 1 {
			a.add(Warn, a.t("Sources are split between countries: %s", strings.Join(s.Verdict, ", ")), "")
		}
		for _, res := range s.Attention {
			if edge := edgeIn(s, res.Country); edge != "" {
				a.add(Info, a.t("%s reports %s, the country of its CDN edge (%s)", res.Service, res.Country, edge), a.t("This is how the service picks a country, not a geolocation mismatch."))
			} else {
				a.add(Warn, a.t("%s sees the address in %s, not %s", res.Service, res.Country, strings.Join(s.Verdict, "/")), "")
			}
		}
	}
	svc := pick(h.Services, func(res probe.Result) bool { return !riskGroup(res.Group) })
	if no := pick(svc, func(res probe.Result) bool { return res.Status == probe.No }); len(no) > 0 {
		a.add(Info, a.t("Not available from here: %s", names(no)), "")
	}
	if blocked := pick(svc, func(res probe.Result) bool { return res.Status == probe.IPBlock }); len(blocked) > 0 {
		a.add(Warn, a.t("Refuse this address or network, not the country: %s", names(blocked)), "")
	}
	lists := pick(h.Services, func(res probe.Result) bool { return res.Group == risk.DNSBL })
	if listed := pick(lists, func(res probe.Result) bool { return res.Status == probe.No }); len(listed) > 0 {
		a.add(Alert, a.t("Listed in %d DNSBL: %s", len(listed), names(listed)), a.t("Mail from this address is likely to be rejected."))
	}
	if slices.ContainsFunc(lists, func(res probe.Result) bool {
		return res.Status == probe.Unknown && strings.Contains(res.Reason+res.Detail, "public/open resolver")
	}) {
		a.add(Info, a.t("Spamhaus was not checked: the query went through a public resolver"), a.t("Use your own recursive resolver to get an answer from this list."))
	}
	for _, res := range h.Services {
		switch {
		case res.Group == risk.Mail && res.Status == probe.No && strings.HasPrefix(res.Detail, "connection "):
			a.add(Info, a.t("Outbound port 25 is closed: mail cannot be sent directly from this address"), "")
		case res.Group == risk.Mail && res.Status == probe.No:
			a.add(Warn, a.t("Port 25 is open, but the mail server did not accept this address"), res.Detail)
		case res.Group == risk.Network && res.Service == "Known ranges" && (res.Status == probe.No || res.Status == probe.Partial):
			level := Info
			if res.Status == probe.No {
				level = Alert
			}
			a.add(level, a.t("Address is in a known range: %s", res.Detail), "")
		}
	}
}

func (a *analysis) censor(rs []probe.Result) {
	if len(rs) == 0 {
		return
	}
	byGroup := func(g probe.Group) []probe.Result {
		return pick(rs, func(res probe.Result) bool { return res.Group == g })
	}
	failed := func(res probe.Result) bool { return res.Status == probe.No || res.Status == probe.IPBlock }
	dns := byGroup(censor.DNS)
	spoofed := pick(dns, func(res probe.Result) bool { return strings.HasSuffix(res.Service, "spoofing") && failed(res) })
	if hits := pick(dns, func(res probe.Result) bool {
		return strings.HasPrefix(res.Service, "Port 53 interception") && failed(res)
	}); len(hits) > 0 {
		var ev []string
		for _, h := range hits {
			ev = append(ev, strings.TrimSuffix(strings.TrimPrefix(h.Service, "Port 53 interception ("), ")")+": "+cmp.Or(h.Detail, h.Reason))
		}
		detail := strings.Join(ev, "; ")
		clean := slices.ContainsFunc(dns, func(res probe.Result) bool {
			return strings.HasSuffix(res.Service, "spoofing") && (res.Status == probe.Yes || res.Status == probe.OK)
		})
		switch {
		case len(spoofed) > 0:
			detail = a.t("%s. Some answers are also spoofed.", detail)
		case clean:
			detail = a.t("%s. Answers match the reference, so this is a transparent forwarder; DoH and DoT bypass it.", detail)
		}
		a.add(Alert, a.t("Port 53 DNS is intercepted on the path"), detail)
	}
	if len(spoofed) > 0 {
		a.add(Alert, a.t("DNS answers are spoofed: %s", names(spoofed)), "")
	}
	if enc := pick(dns, func(res probe.Result) bool {
		return (strings.HasSuffix(res.Service, " DoH") || strings.HasSuffix(res.Service, " DoT")) && failed(res)
	}); len(enc) > 0 {
		a.add(Warn, a.t("Encrypted DNS is blocked: %s", names(enc)), "")
	}
	tg := byGroup(censor.Telegram)
	if down := pick(tg, failed); len(down) > 0 {
		a.add(Warn, a.t("Telegram data centres unreachable: %d of %d", len(down), len(tg)), names(down))
	}
	site := func(rs []probe.Result) string {
		var out []string
		for _, res := range rs {
			host := strings.TrimSuffix(strings.TrimSuffix(res.Service, " HTTPS"), " HTTP")
			if !slices.Contains(out, host) {
				out = append(out, host)
			}
		}
		return strings.Join(out, ", ")
	}
	if dpi := pick(byGroup(censor.DPI), failed); len(dpi) > 0 {
		a.add(Warn, a.t("Blocked on the path (DPI): %s", site(dpi)), "")
	}
	if geo := pick(byGroup(censor.Geoblock), failed); len(geo) > 0 {
		a.add(Info, a.t("Refuse this country or network: %s", site(geo)), "")
	}
	var altered, down []string
	for _, res := range pick(byGroup(censor.Portal), failed) {
		if strings.HasPrefix(res.Reason, "altered") || strings.HasPrefix(res.Reason, "redirected") || strings.HasPrefix(res.Reason, "TLS interception") {
			altered = append(altered, res.Service+": "+res.Reason)
		} else {
			down = append(down, res.Service+": "+res.Reason)
		}
	}
	if len(altered) > 0 {
		a.add(Alert, a.t("Plain HTTP or TLS is altered on the path"), strings.Join(altered, "; "))
	}
	if len(down) > 0 {
		a.add(Warn, a.t("Connectivity check endpoints did not answer: %d", len(down)), strings.Join(down, "; "))
	}
	for _, res := range byGroup(censor.Local) {
		if res.Status != probe.Partial {
			continue
		}
		if res.Service == "System resolver" {
			a.add(Warn, a.t("DNS is answered by a local fake-IP proxy"), res.Reason)
		} else {
			a.add(Warn, a.t("Traffic leaves through a tunnel"), a.t("Every result describes the tunnel exit, not this machine's own connection."))
		}
	}
}

func (a *analysis) resolverExit(r *Report) {
	exits := pick(r.Censor, func(res probe.Result) bool {
		return strings.HasPrefix(res.Service, censor.EgressPrefix) && res.Status == probe.Yes
	})
	var home, abroad []string
	for _, f := range r.families() {
		if f.host.Region != nil {
			home = append(home, f.host.Region.Verdict...)
		}
		for _, g := range f.host.Geo {
			if g.Country != "" {
				home = append(home, g.Country)
			}
		}
	}
	slices.Sort(home)
	home = slices.Compact(home)
	for _, e := range exits {
		if e.Country != "" && len(home) > 0 && !slices.Contains(home, e.Country) && !slices.Contains(abroad, e.Country) {
			abroad = append(abroad, e.Country)
		}
	}
	if len(abroad) > 0 {
		level := Info
		if slices.ContainsFunc(r.Censor, func(res probe.Result) bool {
			return res.Group == censor.Local && res.Service != "System resolver" && res.Status == probe.Partial
		}) {
			level = Warn
		}
		a.add(level, a.t("DNS queries leave through a resolver in %s, while the address is in %s", strings.Join(abroad, ", "), strings.Join(home, ", ")),
			a.t("Behind a VPN or proxy this is a DNS leak: the resolver's operator sees the names you look up. Without one it is just a resolver abroad."))
	}
	if slices.ContainsFunc(exits, func(res probe.Result) bool { return strings.Contains(res.Reason, "(ECS)") }) {
		a.add(Info, a.t("The resolver passes your subnet on to name servers (ECS)"),
			a.t("The sites' name servers learn the network a query came from, though not the exact address."))
	}
}

func (a *analysis) transport(r *Report) {
	var named, quicDown []string
	for _, res := range r.Censor {
		switch {
		case strings.HasPrefix(res.Reason, "blocked by SNI") || strings.HasPrefix(res.Reason, "blocked by Host header"):
			host := strings.TrimSuffix(strings.TrimSuffix(res.Service, " HTTPS"), " HTTP")
			if !slices.Contains(named, host) {
				named = append(named, host)
			}
		case res.Group != censor.Transport && res.Group != censor.Local:
		case strings.HasPrefix(res.Service, "QUIC ") && res.Status == probe.No:
			quicDown = append(quicDown, strings.TrimPrefix(res.Service, "QUIC "))
		case res.Service == "Interface MTU":
			if mtu, _, _ := strings.Cut(res.Reason, " "); len(mtu) < 4 || len(mtu) == 4 && mtu < "1500" {
				a.add(Info, a.t("Interface MTU is %s", res.Reason), a.t("Below 1500 there is a tunnel or PPPoE on the way; large packets are fragmented or rely on path MTU discovery."))
			}
		case res.Service != "NAT (STUN)":
		case res.Status == probe.No:
			a.add(Warn, a.t("UDP does not get through: no STUN server answered"), a.t("Calls, WireGuard, QUIC and peer-to-peer connections rely on UDP."))
		case res.Status == probe.Partial:
			a.add(Info, a.t("NAT is symmetric"), a.t("Each destination gets its own port mapping, so peer-to-peer connections need a relay."))
		}
		if res.Service == "NAT (STUN)" && strings.Contains(res.Reason, "carrier-grade NAT") {
			a.add(Info, a.t("Carrier-grade NAT: the public address is shared with other subscribers"), a.t("Inbound connections and port forwarding are not possible."))
		}
		if _, mapped, ok := strings.Cut(res.Detail, "→ "); ok && res.Service == "NAT (STUN)" && r.IPv4 != nil && r.IPv4.Address != "" {
			first, _, _ := strings.Cut(mapped, ",")
			if ap, err := netip.ParseAddrPort(first); err == nil && ap.Addr().Is4() && ap.Addr().String() != r.IPv4.Address {
				a.add(Info, a.t("UDP leaves through another address than HTTP"), a.t("Traffic is split between exits by protocol."))
			}
		}
	}
	if len(named) > 0 {
		a.add(Warn, a.t("Blocked by name (SNI or Host), not by address: %s", strings.Join(named, ", ")), a.t("The addresses themselves answer; only connections that carry the name are cut."))
	}
	if len(quicDown) > 0 {
		a.add(Info, a.t("QUIC (HTTP/3) does not get through: %s", strings.Join(quicDown, ", ")), a.t("Browsers fall back to TCP; applications that need QUIC will not work."))
	}
}

func (a *analysis) route(rt *route.Report) {
	by := func(verdict string) []string {
		var out []string
		for _, p := range rt.Paths {
			if p.Verdict == verdict {
				out = append(out, p.Target.Name)
			}
		}
		return out
	}
	if hit := by(route.Intercepted); len(hit) > 0 {
		a.add(Alert, a.t("Route probes were answered locally"), a.t("A local proxy, tunnel or sandbox ends the connections; path verdicts mean nothing here."))
		return
	}
	if hit := by(route.Detour); len(hit) > 0 {
		a.add(Warn, a.t("Detours: %s", strings.Join(hit, ", ")), "")
	}
	if hit := by(route.Unreachable); len(hit) > 0 {
		a.add(Warn, a.t("Unreachable: %s", strings.Join(hit, ", ")), "")
	}
	if hit := by(route.Transit); len(hit) > 0 {
		a.add(Info, a.t("Through transit networks: %s", strings.Join(hit, ", ")), "")
	}
	if rt.Method != "icmp" && rt.Note != "" {
		a.add(Info, a.t("No hop data for routes"), rt.Note)
	}
}

func WriteFindings(w io.Writer, st Style, title string, findings []Finding) {
	c := paint(st.Color)
	m := asciiMarks
	if st.Unicode {
		m = unicodeMarks
	}
	width := st.Width
	if width <= 0 {
		width = 100
	}
	fmt.Fprintln(w, c.bold(title))
	fmt.Fprintln(w)
	for _, f := range findings {
		sym, style := m.none, c.dim
		switch f.Level {
		case Alert:
			sym, style = m.no, c.red
		case Warn:
			sym, style = m.warn, c.yellow
		}
		for i, line := range wrapVisible(f.Title, width-4) {
			lead := "  "
			if i == 0 {
				lead = style(sym) + " "
			}
			fmt.Fprintln(w, lead+c.bold(strings.TrimLeft(line, " ")))
		}
		if f.Detail != "" {
			for _, line := range wrapVisible(f.Detail, width-4) {
				fmt.Fprintln(w, "  "+c.dim(strings.TrimLeft(line, " ")))
			}
		}
	}
}

type CheckStat struct {
	Group    string `json:"group"`
	Service  string `json:"service"`
	Runs     int    `json:"runs"`
	Answered int    `json:"answered"`
	Unknown  int    `json:"unknown"`
	Failed   int    `json:"failed"`
}

func Stats(reps []*Report) []CheckStat {
	idx := map[string]int{}
	out := []CheckStat{}
	rank := func(st probe.Status) int {
		switch st {
		case probe.Failed:
			return 2
		case probe.Unknown:
			return 1
		}
		return 0
	}
	for _, r := range reps {
		worst := map[string]probe.Result{}
		var order []string
		note := func(res probe.Result) {
			if res.Status == probe.Pending || res.Service == "" {
				return
			}
			key := string(res.Group) + "\x00" + res.Service
			prev, seen := worst[key]
			if !seen {
				order = append(order, key)
			}
			if !seen || rank(res.Status) > rank(prev.Status) {
				worst[key] = res
			}
		}
		for _, f := range r.families() {
			for _, res := range f.host.factResults() {
				note(res)
			}
		}
		for _, res := range r.Censor {
			note(res)
		}
		for _, key := range order {
			res := worst[key]
			i, ok := idx[key]
			if !ok {
				i = len(out)
				idx[key] = i
				out = append(out, CheckStat{Group: groupTitle(res.Group), Service: res.Service})
			}
			out[i].Runs++
			switch rank(res.Status) {
			case 2:
				out[i].Failed++
			case 1:
				out[i].Unknown++
			default:
				out[i].Answered++
			}
		}
	}
	out = slices.DeleteFunc(out, func(s CheckStat) bool { return s.Answered == s.Runs })
	slices.SortStableFunc(out, func(x, y CheckStat) int {
		if d := cmp.Compare(float64(x.Answered)/float64(x.Runs), float64(y.Answered)/float64(y.Runs)); d != 0 {
			return d
		}
		return cmp.Compare(y.Runs, x.Runs)
	})
	return out
}

func WriteStats(w io.Writer, color bool, lang string, runs int, stats []CheckStat) {
	c := paint(color)
	tr := func(s string) string { return Translate(lang, s) }
	fmt.Fprintf(w, "%s %d\n", c.bold(tr("Runs analysed:")), runs)
	if len(stats) == 0 {
		fmt.Fprintln(w, c.green(tr("Every check answered in every run.")))
		return
	}
	fmt.Fprintln(w, c.dim(tr("Checks that did not always answer (answered / runs; ? no answer, ! error):")))
	fmt.Fprintln(w)
	var rows [][]gcell
	for _, s := range stats {
		style := c.yellow
		if s.Answered == 0 && s.Runs > 1 {
			style = c.red
		}
		rows = append(rows, []gcell{
			plain("  " + s.Group), plain(s.Service),
			{text: fmt.Sprintf("%d/%d", s.Answered, s.Runs), style: style},
			{text: fmt.Sprintf("? %d  ! %d", s.Unknown, s.Failed), style: c.dim},
		})
	}
	writeGrid(w, rows)
}
