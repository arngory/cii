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

## `route`

`targets` — свои цели для `cii route` и `cii --route` в виде `[имя=]хост[@asn]`; они добавляются к встроенному списку. Подробности — в [ROUTE.md](ROUTE.md).

## `services`

Свои проверки доступности: по одному запросу `GET` на каждый адрес, результат попадает в панель «Регион и сервисы» рядом со встроенными. До 32 проверок. Как читается ответ — в [SERVICE_CHECKS.md](SERVICE_CHECKS.md#свои-проверки).

| Поле | Значение |
|---|---|
| `url` | обязательно; `https://` или `http://`, без логина и пароля в адресе |
| `name` | подпись в отчёте; по умолчанию — хост из `url` |
| `expect` | ожидаемый код ответа или список: `200`, `[401, 403]`; по умолчанию подходит любой код ниже 400 |
| `contains` | строка, которая должна быть в теле ответа |
| `blocked` | строка, по которой узнаётся отказ: если она есть в теле, результат — `no` |
| `group` | заголовок группы; `Streaming`, `AI` и `Web` добавляют проверку во встроенную группу, без поля — группа `Custom` |
