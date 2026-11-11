# Конфигурация

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

data:
  sources: [dbip-country-lite, dbip-asn-lite, ipinfo-lite]
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

Только **ваши собственные** ключи. Переменные окружения `CII_IPINFO_TOKEN`, `CII_MAXMIND_ACCOUNT_ID`, `CII_MAXMIND_LICENSE_KEY`, `CII_IPREGISTRY_KEY`, `CII_GEOAPIFY_KEY`, `CII_IP2LOCATION_KEY`, `CII_IPAPI_IS_KEY`, `CII_PROXYCHECK_KEY`, `CII_ABUSEIPDB_KEY`, `CII_IPQS_KEY` и `CII_IPDATA_KEY` имеют приоритет над файлом. Ключи никогда не попадают в отчёты, ошибки и `manifest.json`.

| Ключ | Где используется |
|---|---|
| `ipinfo_token` | загрузка IPinfo Lite; запросы к ipinfo.io без анонимных лимитов |
| `maxmind_account_id`, `maxmind_license_key` | загрузка GeoLite2; веб-сервис GeoLite в проверках региона |
| `ipregistry_key`, `geoapify_key` | включают соответствующие проверки региона |
| `ip2location_key` | снимает суточный лимит анонимных запросов к ip2location.io |
| `proxycheck_key` | снимает дневной лимит анонимных запросов к proxycheck.io |
| `ipapi_is_key`, `abuseipdb_key`, `ipqs_key`, `ipdata_key` | включают соответствующие проверки репутации (см. [RISK_CHECKS.md](RISK_CHECKS.md)) |

## `data.sources`

Какие базы скачивает `cii data update`, если ID не указаны в командной строке. По умолчанию — `dbip-country-lite` и `dbip-asn-lite`. Полный список: `cii data sources`.

Любой другой `.mmdb`, положенный в каталог данных (например, коммерческая база), тоже используется: в отчёте он подписан именем файла.
