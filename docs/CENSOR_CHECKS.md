# Проверки цензуры: `cii censor`

Порт [vernette/censorcheck](https://github.com/vernette/censorcheck) (MIT) на Go внутри общей сетевой политики cii. Команда отдельная: она отвечает не на вопрос «где мой адрес», а «что с этой точки блокируют». Запускается явно; `--plan` показывает все адреса, к которым она может обратиться.

```bash
cii censor
```

```bash
cii censor --mode dns,telegram
```

```bash
cii censor --domains my-list.txt --protocol https
```

Режимы (`--mode`, через запятую, по умолчанию `all`): `dns`, `dpi`, `geoblock`, `telegram` (`tg`). Флаги `--domains FILE` и `--domain HOST` заменяют встроенные списки своими; `--protocol` — `http`, `https` или `both`; `--retries N` — дополнительные попытки на цель (по умолчанию 0: одна попытка). Общие флаги cii (`-4`/`-6`, `--iface`, `--source`, `--timeout`, `--json`, `--debug`, `--mask`) работают как обычно.

## DNS

Для каждого из 12 резолверов (Cloudflare, Google, Quad9, AdGuard, NextDNS, Яндекс — по два адреса) запрашивается `rutracker.org` тремя транспортами. У каждого резолвера есть IPv4- и IPv6-адрес; с `-6` используются вторые, а запрашивается запись AAAA. Для Telegram с `-6` берутся IPv6-адреса дата-центров (по одному на DC):

| Транспорт | Как | Статусы |
|---|---|---|
| UDP/53 | собственный DNS-пакет через `netx.Dial("udp")`, ID ответа сверяется с запросом | ответ получен → `yes`; таймаут/отказ → `no` |
| DoH | `POST https://…/dns-query` с `application/dns-message` через `netx.HTTPClient` | адрес в ответе → `yes`; HTTP-ошибка или пустой ответ → `?`; недоступность → `no` |
| DoT | TLS на 853 с проверкой сертификата по системным корням | как DoH; неверный сертификат → `?` с деталью |

**Подмена DNS.** Первый доступный DoH (или DoT) становится эталоном. Для доменов `rutracker.org`, `linkedin.com`, `flibusta.is` эталонный ответ сравнивается с ответами тех же 12 резолверов по обычному UDP: совпадение хотя бы одного адреса — `clean`; `NXDOMAIN` или адреса без пересечения — `spoofed`; приватный/локальный адрес в ответе помечается как «bogus». Как и в censorcheck, проверка останавливается на первом домене, где найдена подмена, и отдельной строкой «DNS hijacking» даёт итог. Без доступного DoH/DoT итог — `?`.

Строки в выводе: `Имя IP` (UDP), `Имя IP DoH`, `Имя IP DoT`, затем `DNS hijacking` и по строке на резолвер с результатом сравнения.

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
