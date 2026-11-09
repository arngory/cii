# План работ

## 1. Ядро — готово

- [x] Сетевая политика (deny by default, правила по модулям, проверка редиректов), журнал соединений, `--plan`, `--offline`
- [x] Транспорт: `-4`/`-6`, `--iface`, `--source`, `--proxy` (запрет сырых сокетов при прокси), таймауты, честный UA
- [x] Определение публичного IP: интерфейсы + настраиваемые echo-сервисы
- [x] Офлайн-гео и ASN: DB-IP Lite, IPinfo Lite, GeoLite2 (с ключами пользователя), любые свои `.mmdb`
- [x] `cii data update/status/sources`, манифест с sha256
- [x] Отчёт: текст и JSON `cii.report/v1`, маскирование
- [x] Кросс-сборка, CI, release-workflow (с опциональным `IPINFO_TOKEN`)

## 2. Мнения о регионе (по мотивам ipregion) — готово

- [x] 11 бесплатных GeoIP-провайдеров без ключа + ipregistry, geoapify, GeoLite web — с ключом пользователя
- [x] RDAP с редиректом к нужному RIR (страна регистрации)
- [x] Регион по ответам 11 сервисов уровня A (Cloudflare, Google, YouTube, Reddit, TikTok, Apple, Steam, Microsoft, Ookla, JetBrains, PlayStation)
- [x] CDN-площадки Cloudflare и YouTube, встроенный справочник IATA
- [x] Вердикт с равным весом групп, список расхождений, локальные базы как мнения
- [x] Встроенные названия стран (CLDR)
- [x] Уровень B (Twitch, ChatGPT, Claude, Netflix, Spotify, Disney+) за флагом `--extended`; вживую не проверен

## 3. Сервисы (RegionRestrictionCheck + IPQuality + ipregion)

- [x] Общий движок `probe` для региона и сервисов: каталог в Go-структурах, уровни A/B, ключи пользователя
- [x] Мультирегиональный набор: Netflix, Prime Video, Reddit, Wikipedia, 17 API ИИ-сервисов; уровень B — Disney+, Spotify, YouTube Premium, DAZN
- [x] Дедупликация пересечений RegionRestrictionCheck, IPQuality и ipregion
- [ ] Региональные каталоги RegionRestrictionCheck: HK, TW, JP, NA, SA, EU, OC, KR, SEA, AF — по одному региону, с тестами на записанных ответах

## 3а. Региональные каталоги — готово

- [x] HK, TW, JP, KR, NA, SA, EU, OC, SEA, IN, AF и Sport: ~100 проверок, уровни A/B, исключения с причинами в `docs/catalogs/`
- [x] Общие реализации для сервисов из нескольких каталогов, один запрос за запуск
- [x] Автовыбор каталога по стране вердикта, `--catalog`

## 4. Риски и почта (IPQuality) — готово

- [x] DNSBL с учётом FUP: 7 зон, Spamhaus только через непубличный резолвер, заглушки `127.255.255.x` → неизвестно
- [x] Офлайн-наборы: Tor, AWS, GCP, Oracle, Cloudflare, DigitalOcean (`cii data update`)
- [x] proxycheck.io без ключа; ipapi.is, AbuseIPDB, IPQS, ipdata — с ключом пользователя
- [x] Проба исходящего 25-го порта
- [x] Профиль адреса по разделам 1–4 IPQuality: страна регистрации и geo-consistent/discrepant, тип, оценки, факторы риска — из уже получаемых ответов
- [ ] Тип сети по офлайн-данным ASN; FireHOL — после проверки лицензий списков

## 5. Цензура (censorcheck) — готово

- [x] `cii censor`: 12 резолверов по UDP/DoH/DoT, подмена DNS относительно DoH-эталона, DPI и geoblock по спискам censorcheck и своим файлам, MTProto-проба 7 DC Telegram (сверено с оригиналом побайтно)
- [x] При прокси (флаг или окружение) сырые соединения запрещены и показаны как `?`, HTTP-часть идёт через прокси

## 6. Бенчмарки (`cii bench`)

- [x] Свой iperf3-клиент; списки серверов: мировой и российский (собственный, с подсказкой от itdoginfo)
- [x] Скорость через Cloudflare
- [x] Сведения о системе, дисковый тест (O_DIRECT / F_NOCACHE / FILE_FLAG_NO_BUFFERING), CPU-тест
- [x] Системные iperf3 и fio — по флагу `--system`, если установлены; иначе подсказка установки для дистрибутива (apt, dnf, apk, pacman, opkg, zypper, pkg, brew, winget)
- [ ] Ookla Speedtest CLI не подключается: его лицензию cii за пользователя принять не может

## 7. Сопровождение

- [ ] Ручное отслеживание изменений в проектах-примерах и перенос исправлений проверок
- [ ] Ограниченные сборки для роутеров (без тяжёлых модулей)
