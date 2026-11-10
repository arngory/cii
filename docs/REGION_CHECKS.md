# Проверки региона

Модуль `region` спрашивает у GeoIP-провайдеров и у самих сервисов, в какой стране они «видят» ваш адрес, и выводит общий вердикт. Идея и набор источников — из [vernette/ipregion](https://github.com/vernette/ipregion), реализация своя. Каждая проверка — один запрос на адрес за запуск, с честным User-Agent. `--quick` отключает модуль, `--plan` показывает все его хосты.

## Группы и вердикт

| Группа | Что это | Участвует в вердикте |
|---|---|---|
| **GeoIP** | базы геолокации: онлайн-провайдеры, которым передаётся адрес, и локальные `.mmdb` (`local:<id>`) | да |
| **Registry** | страна регистрации блока адресов по RDAP региональных регистраторов (RIR) | нет: показывается рядом с вердиктом как `registered XX` с пометкой `geo-consistent` (совпадает с вердиктом) или `geo-discrepant` (не совпадает) |
| **Platforms** | страна, которую сервис определил по входящему соединению | да |
| **CDN** | площадка (IATA-код), через которую сервис отдаёт трафик; страна берётся по встроенному справочнику аэропортов | нет |

Вердикт: каждая из групп GeoIP и Platforms даёт одинаковый суммарный вес, независимо от числа проверок в ней; побеждает страна с наибольшим весом, при равенстве выводятся все. Результаты из GeoIP и Platforms, расходящиеся с вердиктом, перечисляются отдельно («Disagrees with the verdict»).

Статусы: `ok` (страна получена), `unknown` (ответ без страны или с `ZZ`), `ipblock` (сервис отказал этому адресу), `error` (сбой сети, лимит, HTTP-ошибка; причина выводится в «Failed checks»).

## Уровень A — включено по умолчанию

### GeoIP (адрес передаётся явно)

| Сервис | Запрос | Ключ | Заметки |
|---|---|---|---|
| ipinfo.io | `ipinfo.io/{ip}/json` | `ipinfo_token` — необязательно | без токена действуют лимиты анонимного доступа |
| ipapi.co | `ipapi.co/{ip}/json/` | — | бесплатный лимит без ключа |
| ifconfig.co | `ifconfig.co/country-iso?ip=` | — | открытый сервис echoip, ограничение частоты |
| ip2location.io | `api.ip2location.io/?ip=` | `ip2location_key` — необязательно | без ключа — суточный лимит (сервис сообщает его в ответе); в том же ответе — флаг прокси |
| country.is | `api.country.is/{ip}` | — | открытый сервис |
| geojs.io | `get.geojs.io/v1/ip/country.json?ip=` | — | |
| ipbase.com | `api.ipbase.com/v2/info?ip=` | — | бесплатный лимит без ключа |
| ipquery.io | `api.ipquery.io/{ip}` | — | в том же ответе — флаги VPN, Tor, прокси, дата-центр, мобильная сеть и оценка риска (см. [RISK_CHECKS.md](RISK_CHECKS.md#профиль-адреса)) |
| ipwho.is | `ipwho.is/{ip}` | — | бесплатно для некоммерческого использования |
| ip-api.com | `http://ip-api.com/json/{ip}?fields=status,countryCode,proxy,hosting,mobile` | — | бесплатно для некоммерческого использования, только HTTP и только по IPv4; для IPv6-адреса запрос идёт по IPv4; в том же ответе — флаги прокси, хостинга и мобильной сети |
| ipregistry.co | `api.ipregistry.co/{ip}` | `ipregistry_key` — **обязательно** | без вашего ключа не запускается; в том же ответе — тип подключения и компании, флаги безопасности |
| geoapify.com | `api.geoapify.com/v1/ipinfo?ip=` | `geoapify_key` — **обязательно** | без вашего ключа не запускается |
| MaxMind GeoLite | `geolite.info/geoip/v2.1/country/{ip}` | `maxmind_account_id` + `maxmind_license_key` — **обязательно** | бесплатный веб-сервис GeoLite вашей учётной записи |

### Registry (адрес передаётся явно)

| Сервис | Запрос | Ключ | Заметки |
|---|---|---|---|
| RDAP (RIR) | `rdap.db.ripe.net/ip/{ip}` с редиректом к нужному RIR | — | страна регистрации, а не геолокация; для ARIN — из адреса регистранта. Разрешены RIPE, ARIN, APNIC, LACNIC, registro.br, AFRINIC; редирект к другим NIR блокируется политикой |

### Platforms (по входящему соединению)

| Сервис | Запрос | Откуда страна |
|---|---|---|
| Cloudflare | `www.cloudflare.com/cdn-cgi/trace` | `loc=`; из того же ответа берётся `colo=` для группы CDN |
| Google | `accounts.google.com/v3/signin/identifier` | скрытое поле `region` (`ZZ` = не определено) |
| YouTube | `www.youtube.com/sw.js_data` | данные service worker |
| Reddit | `www.reddit.com/api/v1/not-found` | текст страницы 404; 403 = `ipblock` |
| TikTok | `www.tiktok.com/api/v1/web-cookie-privacy/config` | `body.appProps.region` |
| Apple | `gspe1-ssl.ls.apple.com/pep/gcc` | тело ответа |
| Steam | `HEAD store.steampowered.com` | cookie `steamCountry` |
| Microsoft | `login.live.com` | `sRequestCountry` в странице |
| Ookla | `www.speedtest.net/api/js/config-sdk` | `location.countryCode` |
| JetBrains | `data.services.jetbrains.com/geo` | `code` |
| PlayStation | `HEAD www.playstation.com` (без перехода по редиректу) | cookie `country` |

### CDN

| Сервис | Запрос | Площадка |
|---|---|---|
| Cloudflare | тот же `cdn-cgi/trace` | `colo=` |
| YouTube | `redirector.googlevideo.com/report_mapping?di=no` | код из имени узла (`yyz10s25` → YYZ) |

## Уровень B — только с `--extended`

Эти проверки обращаются к внутренним API сервисов с идентификаторами, которые сами сервисы встраивают в свои официальные веб- и мобильные клиенты. Все такие идентификаторы собраны в одном файле — `internal/clientids/clientids.go`. По умолчанию проверки выключены, их хосты не попадают в политику и в `--plan`. В отчёте они помечены `*`, а в JSON — полем `"extended": true`.

| Сервис | Запрос | Что используется |
|---|---|---|
| Twitch | `POST gql.twitch.tv/gql` | публичный `Client-Id` веб-клиента Twitch, persisted query |
| ChatGPT | `POST ab.chatgpt.com/v1/initialize` | клиентский ключ Statsig из веб-клиента |
| Claude | `GET claude.ai/api/bootstrap` | User-Agent и заголовок платформы Android-приложения |
| Netflix | `GET api.fast.com/netflix/speedtest/v2` | токен из страницы fast.com; из того же ответа — CDN-узел Netflix |
| Spotify | `GET spclient.wg.spotify.com/signup/public/v1/account` | ключ и `X-Client-Id` страницы регистрации |
| Disney+ | `POST disney.api.edge.bamgrid.com/graph/v1/device/graphql` | публичный API-ключ устройства Android |

Риски, которые вы принимаете, включая флаг:
- такие запросы, скорее всего, противоречат условиям использования этих сервисов, даже при одном запросе за запуск;
- сервисы меняют идентификаторы и внутренние API без предупреждения — тогда проверка вернёт `unknown` или `error`, а исправлять нужно `clientids.go`;
- проверки уровня B написаны по рабочей реализации ipregion и покрыты тестами на записанных ответах, но **в среде разработки вживую не запускались**: автоматическая проверка безопасности этой среды запрещает такие запросы.

## Исключено

| Что | Почему |
|---|---|
| демо-токен MaxMind со страницы демо, `demo.ip-api.com` | постоянный демо-ключ сайта и демо-эндпоинт платного API (уровень C). `ipinfo.io/widget/demo` в проверке региона не используется; модуль risk обращается к нему только с `--extended` (см. [RISK_CHECKS.md](RISK_CHECKS.md)) |
| встроенные ключи ipregistry, geoapify, air-port-codes | чужие ключи (уровень C); ipregistry и geoapify доступны с вашими ключами, справочник аэропортов встроен |
| `speed.cloudflare.com/meta` | без поддельного `Referer` отвечает 403; та же информация есть в `cdn-cgi/trace` |
