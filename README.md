# cii

**cii — complete information about current IP.** Один статический бинарник на Go, который собирает в одном отчёте то, для чего обычно запускают несколько скриптов: где «находится» ваш IP по мнению разных баз, кому принадлежит сеть, какие сервисы доступны из этой точки, есть ли цензура или DPI, какая скорость.

Главный принцип — **автономность от авторов**. cii ходит только по адресам, которые его модули объявили заранее. Он не отправляет отчёты на чужие серверы, не ведёт счётчиков запусков и телеметрии, не скачивает и не исполняет код, не пользуется чужими прокси, ключами и аккаунтами. Подробнее — в [docs/NETWORK_POLICY.md](docs/NETWORK_POLICY.md).

> Статус: ранняя разработка. Готовы ядро (сетевая политика, журнал соединений, определение IP, офлайн-гео и ASN), проверки региона и первый набор проверок доступности сервисов. План работ — в [docs/ROADMAP.md](docs/ROADMAP.md).

## Быстрый старт

```bash
make build
```

```bash
./cii data update
```

```bash
./cii
```

Первая команда собирает бинарник, вторая один раз скачивает офлайн-базы DB-IP Lite напрямую у DB-IP, третья определяет ваш публичный IPv4/IPv6, описывает его по локальным базам и спрашивает у GeoIP-провайдеров и сервисов, в какой стране они вас видят (см. [docs/REGION_CHECKS.md](docs/REGION_CHECKS.md)).

## Команды

| Команда | Что делает | Сеть |
|---|---|---|
| `cii` | определяет публичные адреса, описывает их по локальным базам, проверяет регион и доступность сервисов | только хосты из `--plan` |
| `cii --extended` | то же плюс проверки уровня B (внутренние API сервисов, см. [docs/REGION_CHECKS.md](docs/REGION_CHECKS.md)) | хосты из `--plan --extended` |
| `cii --quick` | без проверок региона, сервисов и репутации | только echo-сервисы |
| `cii --no-risk` | без проверок репутации, DNSBL и почты | — |
| `cii --plan` | печатает все адреса, куда cii может обратиться, и выходит | нет |
| `cii --offline` | берёт адреса с интерфейсов, ищет по локальным базам | нет |
| `cii lookup IP...` | описывает указанные адреса по локальным базам | нет |
| `cii data update [ID...]` | скачивает базы у их издателей | только хосты издателей |
| `cii data status` | показывает локальные базы, даты и sha256 | нет |
| `cii data sources` | список поддерживаемых баз и их лицензий | нет |
| `cii censor` | резолверы и подмена DNS, DPI и геоблокировки, Telegram (см. [docs/CENSOR_CHECKS.md](docs/CENSOR_CHECKS.md)) | резолверы, проверяемые домены, DC Telegram |

Общие флаги: `-4`, `-6`, `--iface`, `--source`, `--proxy`, `--timeout`, `--quick`, `--extended`, `--catalog`, `--no-risk`, `--json`, `--debug`, `--no-log`, `--mask`, `--no-color`, `--config`, `--data-dir`.

## Вывод

По умолчанию отчёт занимает минимум места и подстраивается под ширину терминала. Пример условный: адрес из диапазона для документации, остальные значения придуманы для иллюстрации формата.

```
IPv4  203.0.113.7 · DE Germany · AS3320 Deutsche Telekom AG

Region  DE Germany · GeoIP 12/12 · platforms 12/12 · ChatGPT* says NL
CDN     Cloudflare FRA DE · YouTube FRA DE · Netflix* AMS NL

Streaming  ✓ Netflix          ✓ Prime Video      ✓ Disney+*         ✓ Spotify signup*  ✗ YouTube Premium*
AI         ✓ OpenAI API       ✓ Anthropic API    ✓ Grok API         ✓ Mistral API      …
Web        ✓ Reddit           ✓ Wikipedia editing

✓ yes, ✗ no · 50 hosts contacted · * --extended check · IP Geolocation by DB-IP (https://db-ip.com)
details: --debug or ~/.local/state/cii/logs/20260101-120000.log
```

- Регион — одной строкой: вердикт, сколько источников согласны, и только несогласные.
- Сервисы — сеткой по секциям. Страна рядом с сервисом показывается, только если она отличается от вердикта. При двух стеках у каждого сервиса две отметки: первая для IPv4, вторая для IPv6.
- Отметки: `✓` да, `✗` нет, `◐` частично, `⊘` адрес заблокирован сервисом, `?` нет ответа, `!` ошибка; в терминале без UTF-8 — `+ - ~ x ? !`.
- Региональный каталог сервисов подбирается по стране из вердикта (`--catalog auto`). Можно задать вручную: `--catalog JP,EU`, `all` или `none`.
- Секции Reputation, DNSBL, Mail и Network описывают, как адрес выглядит со стороны: VPN/прокси/дата-центр, чёрные списки рассылок, исходящий 25-й порт, диапазоны Tor и облаков. Что для этого спрашивается и у кого — в [docs/RISK_CHECKS.md](docs/RISK_CHECKS.md).

`--debug` печатает полные таблицы по каждому источнику, причины неудачных проверок, сведения о локальных базах и журнал соединений: каждый хост, число запросов, назначение и попытки, заблокированные политикой (`BLOCKED`). Тот же подробный отчёт вместе с JSON при каждом запуске сохраняется в локальный лог: `~/.local/state/cii/logs` на Linux, `~/Library/Logs/cii` на macOS, `%LOCALAPPDATA%\cii\logs` на Windows. Права на файл — 0600, хранятся последние 20 запусков. Лог содержит ваш адрес (если не указан `--mask`) и никуда не отправляется. Отключение — `--no-log`, другой каталог — `CII_LOG_DIR`.

## Документация

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — устройство, модули, формат отчёта
- [docs/NETWORK_POLICY.md](docs/NETWORK_POLICY.md) — сетевая политика и правила ToS/FUP
- [docs/CONFIG.md](docs/CONFIG.md) — конфигурация, свои ключи, свой echo-сервис
- [docs/REGION_CHECKS.md](docs/REGION_CHECKS.md) — проверки региона, уровни и исключения
- [docs/SERVICE_CHECKS.md](docs/SERVICE_CHECKS.md) — проверки доступности сервисов; региональные каталоги — в [docs/catalogs/](docs/catalogs/)
- [docs/RISK_CHECKS.md](docs/RISK_CHECKS.md) — репутация адреса, DNSBL, почта, известные диапазоны
- [docs/CENSOR_CHECKS.md](docs/CENSOR_CHECKS.md) — `cii censor`: DNS, DPI, геоблокировки, Telegram
- [docs/DATA_SOURCES.md](docs/DATA_SOURCES.md) — офлайн-базы, встроенные справочники и лицензии
- [docs/UPSTREAM_AUDIT.md](docs/UPSTREAM_AUDIT.md) — разбор проектов-примеров
- [docs/ROADMAP.md](docs/ROADMAP.md) — план работ
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — сборка, тесты, релизы, ревью-хук
- [CREDITS.md](CREDITS.md) — благодарности и происхождение идей

## Лицензия

[AGPL-3.0](LICENSE).
