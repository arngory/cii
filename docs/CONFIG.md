# Конфигурация

[English version](en/CONFIG.md)

Конфиг необязателен. По умолчанию он ищется в `<каталог конфига>/cii/config.yaml`: на Linux это `~/.config/cii/config.yaml`; путь можно переопределить через `CII_CONFIG_DIR` или `--config`. Каталог данных: `~/.local/share/cii` на Linux, `~/Library/Application Support/cii` на macOS, `%LOCALAPPDATA%\cii` на Windows; переопределяется через `CII_DATA_DIR` или `--data-dir`.

```yaml
ip_echo:
  - name: my-echo
    url4: https://echo4.example.org/
    url6: https://echo6.example.org/
    format: plain

keys:
  ipinfo_token: ""
  maxmind_account_id: ""
  maxmind_license_key: ""
  ipregistry_key: ""
  geoapify_key: ""
  ip2location_key: ""
  ipapi_is_key: ""
  proxycheck_key: ""
  abuseipdb_key: ""
  ipqs_key: ""
  ipdata_key: ""
  gemini_api_key: ""

data:
  sources: [dbip-country-lite, dbip-asn-lite, ipinfo-lite]

route:
  targets:
    - home=vps.example.org@64500

dns: system

services:
  - name: Shop
    url: https://shop.example.org/
    expect: 200
    contains: "Add to cart"
    blocked: "not available in your country"
    group: Work
```

## `ip_echo`

Заменяет встроенный список echo-сервисов (Cloudflare `cdn-cgi/trace`, ipify, icanhazip). Сервисы опрашиваются параллельно. Адрес принимается, как только его назвали два сервиса; если ответил только один, берётся его ответ. Если сервисы назвали разные адреса, побеждает адрес с большинством, а остальные показываются строкой «Also seen» в панели качества IP и в `disagree[]` JSON. Так видно раздельную маршрутизацию или балансировку по нескольким выходам. Форматы ответа:

| `format` | Ответ |
|---|---|
| `plain` | тело ответа — это адрес |
| `trace` | строки `ключ=значение`, адрес в `ip=` |
| `json:поле` | JSON-объект, адрес в указанном поле |

Чтобы ни от кого не зависеть, поднимите свой echo-сервис. Хватит одной строки nginx: `return 200 $remote_addr;`.

## `keys`

Только **ваши собственные** ключи. Переменные окружения `CII_IPINFO_TOKEN`, `CII_MAXMIND_ACCOUNT_ID`, `CII_MAXMIND_LICENSE_KEY`, `CII_IPREGISTRY_KEY`, `CII_GEOAPIFY_KEY`, `CII_IP2LOCATION_KEY`, `CII_IPAPI_IS_KEY`, `CII_PROXYCHECK_KEY`, `CII_ABUSEIPDB_KEY`, `CII_IPQS_KEY`, `CII_IPDATA_KEY` и `CII_GEMINI_API_KEY` имеют приоритет над файлом. Ключи никогда не попадают в отчёты, ошибки и `manifest.json`.

| Ключ | Где используется |
|---|---|
| `ipinfo_token` | загрузка IPinfo Lite; запросы к ipinfo.io без анонимных лимитов |
| `maxmind_account_id`, `maxmind_license_key` | загрузка GeoLite2; веб-сервис GeoLite в проверках региона |
| `ipregistry_key`, `geoapify_key` | включают соответствующие проверки региона |
| `ip2location_key` | снимает суточный лимит анонимных запросов к ip2location.io |
| `proxycheck_key` | снимает дневной лимит анонимных запросов к proxycheck.io |
| `ipapi_is_key`, `abuseipdb_key`, `ipqs_key`, `ipdata_key` | включают соответствующие проверки репутации (см. [RISK_CHECKS.md](RISK_CHECKS.md)) |
| `gemini_api_key` | включает проверку региона Gemini API (см. [SERVICE_CHECKS.md](SERVICE_CHECKS.md)) |

## `data.sources`

Какие базы скачивает `cii data update`, если ID не указаны в командной строке. По умолчанию — `dbip-country-lite` и `dbip-asn-lite`. Полный список: `cii data sources`.

Любой другой `.mmdb`, положенный в каталог данных (например, коммерческая база), тоже используется: в отчёте он подписан именем файла.

## `dns`

Через какой резолвер проверки разрешают имена. По умолчанию — системный (`/etc/resolv.conf` на Linux и macOS, настройки адаптеров на Windows). Флаг `--dns` имеет приоритет; `--dns system` возвращает системный, даже если в конфиге задан другой.

```yaml
dns: quad9
```

| Значение | Что это |
|---|---|
| `quad9` | Quad9: 9.9.9.9, 149.112.112.112, 2620:fe::fe, 2620:fe::9, DNS-over-TLS `dns.quad9.net` |
| `cznic` | CZ.NIC ODVR: 193.17.47.1, 185.43.135.1, 2001:148f:ffff::1, 2001:148f:fffe::1, DNS-over-TLS `odvr.nic.cz` |
| `cloudflare` | Cloudflare: 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001, DNS-over-TLS `cloudflare-dns.com` |
| `google` | Google: 8.8.8.8, 8.8.4.4, 2001:4860:4860::8888, 2001:4860:4860::8844, DNS-over-TLS `dns.google` |
| `adguard` | AdGuard: 94.140.14.14, 94.140.15.15, 2a10:50c0::ad1:ff, 2a10:50c0::ad2:ff, DNS-over-TLS `dns.adguard-dns.com` |
| `192.0.2.53`, `[2001:db8::53]:5353` | обычный DNS (UDP, при длинном ответе TCP) на этот адрес; порт по умолчанию 53 |
| `tls://192.0.2.53#dns.example` | свой DNS-over-TLS: адрес, необязательный порт (по умолчанию 853) и имя в сертификате |

Сервер задаётся адресом, а не именем: чтобы найти резолвер по имени, нужен другой резолвер. У пресетов сначала пробуются адреса IPv4, затем IPv6 — запросы по IPv6-проверкам тоже уходят по IPv4, если он работает. Сертификат DNS-over-TLS проверяется по системным корневым сертификатам.

Каждый адрес сервера — правило сетевой политики модуля `dns`: он виден в `--plan`, а каждое соединение с ним — в журнале сети. В подвале экрана пишется, через какой резолвер шли запросы. Что меняется:

- через выбранный сервер идут все имена проверок: echo-сервисы, регион, сервисы, репутация, DNSBL, маршруты, бенчмарк, `cii data update`, DPI- и геоблок-проверки;
- проверки цензуры, которые исследуют сам системный резолвер (`System resolver spoofing`, выход DNS), по-прежнему спрашивают системный;
- при прокси имена разрешает прокси, и `--dns` не используется;
- Spamhaus ZEN не опрашивается, если выбранный сервер публичный (все пресеты публичные): Spamhaus не отвечает публичным резолверам. Для ZEN нужен свой рекурсивный резолвер — задайте его адресом.

DNS-over-HTTPS пока не поддерживается.

## `route`

`targets` — свои цели для `cii route` и `cii --route` в виде `[имя=]хост[@asn]`; они добавляются к встроенному списку. Подробности — в [ROUTE.md](ROUTE.md).

## `services`

Свои проверки доступности: по одному запросу `GET` на каждый адрес, результат попадает в панель «Регион и сервисы» рядом со встроенными. До 32 проверок. Как читается ответ — в [SERVICE_CHECKS.md](SERVICE_CHECKS.md#свои-проверки).

| Поле | Значение |
|---|---|
| `url` | обязательно; `https://` или `http://`, без логина и пароля в адресе |
| `name` | подпись в отчёте; по умолчанию — хост из `url`. Без точки с запятой и не совпадает с названием встроенной проверки |
| `expect` | ожидаемый код ответа или список: `200`, `[401, 403]`; по умолчанию подходит любой код ниже 400 |
| `contains` | строка, которая должна быть в теле ответа |
| `blocked` | строка, по которой узнаётся отказ: если она есть в теле, результат — `no` |
| `group` | заголовок группы; `Streaming`, `AI` и `Web` добавляют проверку во встроенную группу, без поля — группа `Custom` |
