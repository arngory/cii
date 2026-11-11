# Проверки цензуры: `cii censor`

Порт [vernette/censorcheck](https://github.com/vernette/censorcheck) (MIT) на Go внутри общей сетевой политики cii. Она отвечает не на вопрос «где мой адрес», а «что с этой точки блокируют». Обычный запуск `cii` проверяет режимы `dns` и `telegram` (секунды), `cii --extended` — все четыре, `--no-censor` и `--quick` отключают проверки; на экране это панель «Censorship» со счётчиками и находками. `cii censor` — только цензура, со всеми режимами, полной сеткой и своими списками. `--plan` показывает все адреса, к которым проверки могут обратиться.

```bash
cii censor
```

```bash
cii censor --mode dns,telegram
```

```bash
cii censor --domains my-list.txt --protocol https
```

Режимы (`--mode`, через запятую, по умолчанию `all`): `dns`, `dpi`, `geoblock`, `telegram` (`tg`), `portal`. В основном запуске `cii` без `--extended` выполняются `dns`, `telegram` и `portal`, с `--extended` — все. Флаги `--domains FILE` и `--domain HOST` заменяют встроенные списки своими; `--protocol` — `http`, `https` или `both` (другое значение — ошибка); `--retries N` — дополнительные попытки на цель (по умолчанию 0: одна попытка). Общие флаги cii (`-4`/`-6`, `--iface`, `--source`, `--timeout`, `--json`, `--debug`, `--mask`) работают как обычно.

## DNS

Для каждого из 12 резолверов (Cloudflare, Google, Quad9, AdGuard, NextDNS, Яндекс — по два адреса) запрашивается `rutracker.org` тремя транспортами. У каждого резолвера есть IPv4- и IPv6-адрес; с `-6` используются вторые, а запрашивается запись AAAA. Для Telegram с `-6` берутся IPv6-адреса дата-центров (по одному на DC):

| Транспорт | Как | Статусы |
|---|---|---|
| UDP/53 | собственный DNS-пакет через `netx.Dial("udp")`, ID ответа сверяется с запросом | ответ получен → `yes`; таймаут/отказ → `no` |
| DoH | `POST https://…/dns-query` с `application/dns-message` через `netx.HTTPClient` | адрес в ответе → `yes`; HTTP-ошибка или пустой ответ → `?`; недоступность → `no` |
| DoT | TLS на 853 с проверкой сертификата по системным корням | как DoH; неверный сертификат → `?` с деталью |

**Подмена DNS.** Первый доступный DoH (или DoT) становится эталоном. Для доменов `rutracker.org`, `linkedin.com`, `flibusta.is` эталонный ответ сравнивается с ответами тех же 12 резолверов по обычному UDP: совпадение хотя бы одного адреса — `clean`; `NXDOMAIN` или адреса без пересечения — `spoofed`; приватный/локальный адрес в ответе помечается как «bogus». Как и в censorcheck, проверка останавливается на первом домене, где найдена подмена, и отдельной строкой «DNS hijacking» даёт итог. Без доступного DoH/DoT итог — `?`.

Строки в выводе: `Имя IP` (UDP), `Имя IP DoH`, `Имя IP DoT`, затем `DNS hijacking` и по строке на резолвер с результатом сравнения.

**Перехват 53-го порта.** Сверка с DoH ловит только поддельные ответы. Прозрачное перенаправление 53-го порта на чужой резолвер, который отвечает правильно, она не видит. Для него есть две отдельные проверки (идея из [remnawave/geocheck](https://github.com/remnawave/geocheck)):

- `Port 53 interception (OpenDNS)` — TXT-запрос `which.opendns.com` к 208.67.222.222 (по IPv6 — 2620:119:35::35). Настоящий резолвер OpenDNS отвечает именем своего сервера. Любой другой резолвер получает запись от авторитетных серверов, а там написано «I am not an OpenDNS resolver». Такой ответ значит, что запрос перехватили по пути: `✗`.
- `Port 53 interception (Google)` — запрос класса CHAOS `id.server` к 8.8.8.8 (по IPv6 — 2001:4860:4860::8888). Google такие запросы не поддерживает. Любой TXT-ответ пришёл не от Google: `✗`.

Нет ответа или тайм-аут — `?`: недоступность ещё не перехват. При прокси обе проверки не выполняются, как и весь обычный DNS.

## Local

Две проверки без обращений в сеть. Они показывают, что результаты других проверок описывают не прямое подключение:

- `Default route` — через какой интерфейс ядро отправило бы трафик в интернет. Чтобы это узнать, создаётся UDP-сокет к документационному адресу 192.0.2.1 (2001:db8::1 для IPv6): пакетов при этом не уходит. Point-to-point интерфейс или имя `tun*`, `utun*`, `tap*`, `ppp*`, `wg*`, `ipsec*`, `gpd*`, `nordlynx*`, `tailscale*`, `zt*` — `partial`: трафик идёт через туннель, и результаты описывают его выход.
- `System resolver` — адреса `nameserver` из `/etc/resolv.conf`. Адрес из 198.18.0.0/15 (диапазон для бенчмарков, в реальных сетях не встречается) — `partial`: DNS отвечает локальный прокси в режиме fake-IP, как у Clash или sing-box. Если файла нет (Windows), строка не выводится.


## Portal

Проверки связи, по которым операционные системы определяют, есть ли интернет и нет ли captive-портала (идея и эталоны из [remnawave/geocheck](https://github.com/remnawave/geocheck)). Каждый адрес отвечает заранее известным кодом и телом. Ответ сверяется с эталоном, редиректы не выполняются:

| Строка | Адрес | Эталон |
|---|---|---|
| Google, Google HTTPS | `connectivitycheck.gstatic.com/generate_204` по HTTP и HTTPS | 204, пустое тело |
| Cloudflare, Cloudflare HTTPS | `cp.cloudflare.com/generate_204` по HTTP и HTTPS | 204 |
| Apple | `http://captive.apple.com/hotspot-detect.html` | 200, `<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>` |
| Microsoft NCSI | `http://www.msftconnecttest.com/connecttest.txt` | 200, `Microsoft Connect Test` |
| Microsoft Edge | `http://edge-http.microsoft.com/captiveportal/generate_204` | 204 |
| Firefox | `http://detectportal.firefox.com/success.txt` | 200, `success` |
| Ubuntu | `http://connectivity-check.ubuntu.com/` | 204 |
| Arch Linux | `http://ping.archlinux.org/` | 200, фраза о проверке связи |

Адреса принадлежат разным сетям (Google, Cloudflare, Apple, Akamai, Microsoft, Fastly, Canonical, Hetzner), поэтому сбой одного CDN не выглядит как проблема всей сети. Тело сравнивается без учёта пробелов по краям.

Вердикты:
- совпало — `✓`;
- редирект 3xx — `✗` «captive portal or filter page», с хостом, куда ведёт редирект;
- 200 вместо 204 — `✗`: ответ переписал прокси;
- другой код или другое тело — `✗` с началом полученного тела;
- неверный сертификат на HTTPS — `✗` «TLS interception»;
- 5xx и сетевые ошибки — `?` или `✗` по типу ошибки, как в DPI.

Если HTTP-проверки не проходят, а HTTPS-пара совпадает, путь переписывает незашифрованный HTTP. Если не проходит и HTTPS, а HTTP совпадает, это признак перехвата TLS. При прокси (`--proxy`) проверяется путь от прокси, а не от этой машины.

## DPI и геоблокировки

Списки доменов перенесены из censorcheck без изменений: 18 «DPI» (YouTube, Discord, Instagram, Facebook, X, LinkedIn, rutracker, DigitalOcean, Amnezia, Outline, Mailfence, Flibusta, rezka, `api.telegram.org`, Google Play, GitHub…) и 10 «geoblock» (Spotify, Netflix, Patreon, Swagger, Snyk, MongoDB, Autodesk, Graylog, Redis, Copilot). Для каждого домена делается `GET` по HTTP (без перехода) и HTTPS (с переходами внутри того же сайта) с честным User-Agent.

Классификация:

| Результат | Условие |
|---|---|
| `yes` available | 2xx, или редирект внутри того же сайта |
| `no` redirected to block page | редирект на известные страницы блокировок (`warning.rt.ru`, `zapret-info.gov.ru`, `*.rkn.gov.ru`), на приватный адрес или на хост с маркерами `block`, `zapret`, `warning`, `forbidden`, `restrict`, `censor`, `rkn` |
| `no` denied / legal | 403 или 451 |
| `no` TLS handshake … (likely DPI) | обрыв или таймаут на этапе TLS — характерный почерк DPI |
| `no` invalid certificate | подмена сертификата (MITM или заглушка) |
| `no` blocked by port | соединение на порт не установилось |
| `⊘` blocked by IP | недоступны и 80, и 443 — адрес, вероятно, в чёрном списке |
| `?` | редирект на чужой сайт, другой код ответа, домен не разрешился |

Фаза, на которой оборвался запрос, определяется через `httptrace`, а не по тексту ошибки.

## Telegram

Для семи дата-центров (DC1–DC5, адреса из censorcheck) выполняется настоящее MTProto-рукопожатие по обфусцированному транспорту official-клиентов: случайный 64-байтный заголовок с запретом сигнатур HTTP/TLS, тег `ee ee ee ee` и номер DC, AES-256-CTR с ключом и IV из заголовка, `req_pq_multi` со случайным nonce, проверка `res_pq` и nonce в расшифрованном ответе. Алгоритм сверен с censorcheck побайтно: тест `TestMTProtoHelloMatchesReference` сравнивает результат с шифротекстом, посчитанным независимо через `openssl`.

| Результат | Условие |
|---|---|
| `yes` MTProto handshake OK | корректный `res_pq` |
| `no` TCP connect failed | порт 443 DC недоступен |
| `no` handshake dropped (likely DPI) | TCP открылся, ответа нет или соединение сброшено |
| `no` unexpected MTProto reply | ответ есть, но не MTProto (подмена) |

## Отличия от censorcheck

- Все адреса объявлены в сетевой политике и попадают в журнал соединений; свои списки доменов добавляются в политику при запуске.
- Нет собственной поддержки SOCKS5 для Telegram: при любом прокси (флаг или окружение) «сырые» соединения и UDP/DoT запрещены политикой, и DNS/Telegram-строки показывают `?` с причиной; DPI/geoblock по HTTP работают через прокси.
- По умолчанию одна попытка на цель (у censorcheck — 2 повтора), чтобы не создавать лишнего трафика; `--retries` возвращает повторы.
- Классификация с `httptrace` различает обрыв на TLS и на соединении точнее, чем разбор кодов curl.
- Зависимости curl, dig, jq, column, openssl не нужны — всё в бинарнике.
