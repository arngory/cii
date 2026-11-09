# Каталог NA — Северная Америка

Перенос блока `NA_UnlockTest` из [RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck) (RRC). Код — `internal/services/region_na.go`, тесты — `region_na_test.go`, идентификаторы уровня B — `internal/clientids/region_nasa.go`. Общие правила — в [NETWORK_POLICY.md](../NETWORK_POLICY.md) и [MODULES.md](../MODULES.md). Каталог выбирается для US и CA.

Одна проверка — один запрос. User-Agent честный (`cii/…`), браузерные заголовки `sec-ch-*`, `sec-fetch-*` из RRC не переносились. Где RRC смотрит на конечный адрес после редиректов (`url_effective`), cii запрашивает страницу без перехода (`NoRedirect`) и читает `Location`: движок не отдаёт конечный URL, а переход на чужой домен всё равно заблокировала бы сетевая политика. Незнакомый редирект → `unknown` с адресом в `reason`, а не «да».

«Проверено вживую» — один GET 9 ноября 2026 года из дата-центра в США (AS396982, Сан-Франциско) с UA `cii/…`; так проверялись только запросы уровня A. Ответы прогнаны через функции `Eval`, результат указан в таблице. Для уровня B живых запросов не было: логика взята из RRC и закреплена тестами на синтетических ответах.

## Включено

| Сервис | Уровень | Запрос | Логика | Проверено вживую |
|---|---|---|---|---|
| Paramount+ | A | `GET www.paramountplus.com/` (с редиректами) | `pageProps.region` в `__NEXT_DATA__`: код страны → `yes` со страной; `intl` → `no`; иначе `unknown` | да: `yes (US)` |
| Acorn TV | A | `GET acorn.tv/` | «not yet available in your»/«unavailable in your» → `no`; ссылка `signup.acorn.tv` при 200 → `yes` | да: `yes` |
| BritBox | A | `GET www.britbox.com/` без редиректа | `Location` с `locationnotsupported`/`locationnotvalidated`/`britbox.co.uk` → `no`; 200 со словом BritBox → `yes`; другой редирект → `unknown`. Ссылка на `britbox.co.uk` есть и в теле американской страницы, поэтому признак ищется только в `Location` | да: `yes` |
| Shudder | A | `GET www.shudder.com/` | «not available»/«not yet available»/«403 ERROR» → `no`; 200 со словом Shudder → `yes` | да: `yes` |
| Fubo TV | A | `GET api.fubo.tv/v3/location` | `NO_SERVICE_IN_COUNTRY` → `no`; `network_allowed` true → `yes`, false → `no`; страна — `country_code2`. RRC шлёт `Origin`/`Referer` сайта, эндпоинт отвечает и без них | да: `yes (US)` |
| Tubi TV | A | `GET tubitv.com/` | «not currently available in your area» → `no`; `manifest` при 200 → `yes`. RRC запрашивает `/home`, который теперь 301 на `/` | да: `yes` |
| Pluto TV | A | `GET pluto.tv/` без редиректа | `Location` с `plutotv-is-not-available` → `no`; 200 со словом «Pluto TV» → `yes`, страна из `"region"`; другой редирект → `unknown` | да: `yes (US)` |
| KOCOWA | A | `GET www.kocowa.com/` | 403 → `no`; 200 со словом KOCOWA → `yes` | да: `yes` |
| AMC+ | A | `GET www.amcplus.com/` без редиректа | `Location` с `geographic-restriction` или 403 → `no`; 200 со словом «AMC+» → `yes` | да: `yes` |
| NFL+ | A | `GET www.nfl.com/plus` без редиректа | `Location` с `nfl-game-pass`/`gpi.nfl.com` → `no`; 200 со словом «NFL+» → `yes`. Адрес без завершающего `/`: `/plus/` отвечает 308 на `/plus` | да: `yes` |
| Philo | A | `GET content-us-east-2-fastly-b.www.philo.com/geo` | `status` SUCCESS → `yes`, FAIL → `no`; страна — `country` | да: `yes (US)` |
| FXNOW | A | `GET fxnow.fxnetworks.com/` | «is not accessible» → `no`; «FX Movies» при 200 → `yes` | да: `yes` |
| CW TV | A | `GET www.cwtv.com/` | 403/451 → `no`; 200 со словом «The CW» → `yes` | да: `yes` |
| A&E TV | A | `GET play.aetv.com/` | страна из заголовка `aetn-country-code` (или cookie `AETN-Country-Code`, как в RRC): US/CA → `yes`, другая → `no`, нет → `unknown`. Первый запрос RRC к `link.theplatform.com` с идентификатором медиа из плеера не переносился: страна сайта видна и без него | да: `yes (US)` |
| Sling TV | A | `GET www.sling.com/` без редиректа | `Location` с `geo-block` → `no`; 200 со словом Sling → `yes` | да: `yes` |
| Peacock TV | A | `GET www.peacocktv.com/` без редиректа | `Location` с `unavailable` → `no`; 200 со словом Peacock → `yes`, страна из `"territory"`. Слово `unavailable` есть и в теле обычной страницы, поэтому ищется только в `Location` | да: `yes (US)` |
| DirecTV Stream | A | `GET stream.directv.com/watchnow` | 403 → `no`; 200 со словом DIRECTV → `yes` | да: `yes` |
| Hotstar | A | `GET www.hotstar.com/` без редиректа | 403/475 → `no`; страна из cookie `geo=`; US → `no` (сервис закрыт в США); совпадает с регионом в `Location` (`/ca`) → `yes`; иначе `unknown` | да: `geo=US`, `Location: /us` → `no (US)` |
| CBC Gem | A | `GET www.cbc.ca/g/stats/js/cbc-stats-top.js` | `"country"` CA → `yes`, другая → `no`, нет → `unknown` | нет: `www.cbc.ca` из среды разработки не ответил (сброс потока HTTP/2, затем таймаут) |
| HBO Max | A | общая проверка (`shared.go`), `GET www.hbomax.com/` с честным UA | страна из cookie `countryCode=`: US или есть в списке `"url":"/xx/yy"` → `yes`; нет в списке → `no`; 403 → `ipblock`; иначе `unknown`. В RRC адрес `www.max.com`, сервис вернулся к имени HBO Max | частично: из дата-центра 403 Akamai → `ipblock` |
| NBA TV | A | общая проверка (`shared.go`), `GET www.nba.com/watch/` с честным UA | «Service is not available in your region» → `no`; 403 → `ipblock`; 200 → `yes`. В RRC отсутствие фразы = «да», в cii нужен ответ 200 | частично: из дата-центра 403 Akamai → `ipblock` |
| NBC TV | B | `POST geolocation.digitalsvc.apps.nbcuni.com/geolocation/live/usa` с `Authorization: NBC-Basic key="usa_live"…`, `client: oneapp`, `Origin`/`Referer` `www.nbc.com`, JSON-телом веб-клиента | `restricted` false → `yes`, true → `no`. `app-session-id` — случайный UUID при каждом запуске, как в RRC | нет |
| encoreTVB | B | `GET edge.api.brightcove.com/playback/v1/accounts/5324042807001/videos/6005570109001` с policy key Brightcove (`Accept: application/json;pk=…`) и `Origin: www.encoretvb.com` | `error_subcode` `CLIENT_GEO` → `no`; 200 с `sources` → `yes`; другой `error_subcode` → `unknown`. В RRC отсутствие ошибки = «да», в cii нужен список источников | нет |
| Crave | B | `GET capi.9c9media.com/destinations/crave_atexace/…/manifest.mpd?…` с `Origin`/`Referer` `www.crave.ca` | «Geo Constraint Restrictions» → `no`; `video.9c9media.com` при 200 → `yes` | нет |

Почему уровень B: NBC TV, encoreTVB и Crave используют ключи, тела или идентификаторы контента, взятые из веб-клиента сервиса, и заголовки `Origin`/`Referer` его сайта. HBO Max и NBA TV остаются в уровне A с честным User-Agent: из дата-центра Akamai отвечает им `403 Access Denied`, и cii показывает это как `ipblock`, а не подменяет UA. Отличить блокировку по UA от блокировки адреса дата-центра можно только запросом с браузерным UA, который в среде разработки не отправлялся; с домашнего адреса ожидается обычный ответ.

NBA TV и Fubo TV есть также в блоке Sport RRC; ESPN+ — тоже, но исключён (см. ниже).

## Не включено

| Сервис (функция RRC) | Причина |
|---|---|
| Hulu (`HuluUS`) | уровень C: вход в чужую учётную запись — в RRC зашиты e-mail и пароль, cookie сессии и токен reCAPTCHA Enterprise |
| ESPN+ (`ESPNPlus`) | уровень C: `subject_token` чужой сессии устройства из файла `cookies`, который RRC скачивает с GitHub при каждом запуске; затем цепочка из двух запросов |
| FOX (`Fox`) | запрос фрагмента видео (`.ts`) по зашитому адресу с идентификатором чужой сессии воспроизведения (`pbs=`): это скачивание контента по чужой сессии, а не проверка страницы |
| Discovery+ (`DiscoveryPlus`) | цепочка из трёх запросов (`bootstrapInfo` → анонимный токен → каталог с cookie токена). Движок `probe` выполняет только заранее заданные запросы и не передаёт значения из одного ответа в другой |
| TLC GO (`TLCGO`) | цепочка: анонимный токен из первого ответа передаётся во второй |
| MGM+ (`EPIX`) | цепочка: `session_token` из `POST /v2/sessions` (с `apikey` веб-клиента) передаётся в GraphQL `PlayFlow` |
| Starz (`Starz`) | цепочка: значение из первого ответа передаётся во второй как `AuthTokenAuthorization` |
| SonyLIV (`SonyLiv`) | цепочка из трёх запросов с JWT со страницы. Страница сама по себе ненадёжна: она рендерится на сервере и содержит геоданные сервера рендеринга (вживую — IP 35.187.x, Чикаго, а не адрес клиента), поэтому упрощённая проверка дала бы ложное «да» |
| MathsSpot Roblox (`GameTest_MathsSpot`) | путь API и версия фронтенда берутся со страницы, затем `startSession` облачного гейминга now.gg со случайными идентификаторами — цепочка и создание игровой сессии |
| Meta AI (`WebTest_MetaAI`) | `www.meta.ai` отвечает 403 со страницей JS-проверки (`__rd_verify_…?challenge=3`); прохождение такой проверки — обход антибот-защиты (уровень C) |
| Crunchyroll (`Crunchyroll`) | RRC проверяет не Crunchyroll, а сторонний геосервис `c.evidon.com/geo/country.js` (страна = US → «да»); о доступности Crunchyroll ответ ничего не говорит |
| Crackle (`Crackle`) | сервис закрыт: `prod-api.crackle.com` не разрешается в DNS, у `www.crackle.com` CNAME на CloudFront без адреса (проверено 9 ноября 2026) |
| Popcornflix (`Popcornflix`) | эндпоинт RRC `popcornflix-prod.cloud.seachange.com` — NXDOMAIN; сайт `popcornflix.com` жив, но признака геоблокировки на нём не найдено |
| KBS America (`KBSAmerican`) | закомментирован в самом RRC |

## Ограничения и открытые вопросы

- Hotstar проверен только из США (сервис там закрыт); путь `yes` для Канады взят из RRC (`Location` с `/ca` и `geo=CA`).
- Pluto TV, BritBox, AMC+, NFL+, Sling и Peacock проверены только на «да» из США; формат редиректа «нет» взят из RRC. Если вне США первым редиректом окажется промежуточный адрес, проверка вернёт `unknown` с адресом редиректа, а не ложный ответ.
- HBO Max, Paramount+, Hotstar, NBA TV, Fubo TV, Acorn TV, BritBox, Shudder и AMC+ входят и в другие каталоги; реализация у них одна (`internal/services/shared.go`), и при `--catalog all` каждый запрос уходит один раз.
- Проверки уровня B вживую не запускались; при смене ключей или API они дают `unknown`/`error`, а не ложное «да».
