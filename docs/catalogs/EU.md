# Каталог EU — Европа

Перенос блока `EU_UnlockTest` из [RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck) (RRC). Код — `internal/services/region_eu.go`, тесты — `region_eu_test.go`, идентификаторы уровня B — `internal/clientids/region_eoss.go`. Общие правила — в [NETWORK_POLICY.md](../NETWORK_POLICY.md) и [MODULES.md](../MODULES.md).

Одна проверка — один запрос с честным User-Agent (браузерный UA, `sec-ch-*` и прочие заголовки браузера из RRC не переносились). Там, где RRC смотрит на конечный адрес после редиректов, cii запрашивает страницу без перехода по редиректу (`NoRedirect`) и читает заголовок `Location`: движок не отдаёт конечный URL, а переход на другой домен всё равно заблокировала бы сетевая политика.

«Проверено вживую» — один GET 9 ноября 2026 года из дата-центра в США (AS396982) с UA `cii/…`; так проверялись только запросы уровня A. Для уровня B живых запросов не было, логика взята из RRC и закреплена тестами на синтетических ответах.

## Включено

| Сервис | Уровень | Запрос | Логика | Проверено вживую |
|---|---|---|---|---|
| Paramount+ | A | `GET www.paramountplus.com/` (с редиректами) | `pageProps.region` в `__NEXT_DATA__`: код страны → `yes` со страной; `INTL` → `no`; иначе `unknown` | да: `yes (US)` |
| HBO Max | A | `GET www.hbomax.com/` (с редиректами) | страна — из cookie `countryCode`; 403 → `ipblock`; страна US или есть в списке `"url":"/xx/yy"` на странице → `yes`; нет в списке → `no`; нет страны или списка → `unknown`. В RRC адрес `www.max.com`, сервис вернулся к имени HBO Max | частично: 403 Akamai с `countryCode=US` → `ipblock (US)`; путь с телом страницы не наблюдался |
| SkyShowTime | A | `GET www.skyshowtime.com/` | 403 или ссылка `where-can-i-stream` → `no`; `"territory":"XX"` → `no`; `"territory":"PL"` или cookie `activeTerritory` → `yes` со страной. Признак `"territory"` добавлен по живому ответу | да: `"territory":"XX"` → `no` |
| BritBox | A | `GET www.britbox.com/` без редиректа | `Location` с `locationnotsupported`/`locationnotvalidated`/`britbox.co.uk` → `no`; 200 → `yes`; другой редирект → `unknown` | да: 200 (BritBox US) → `yes` |
| Megogo | A | `GET megogo.net/en` | слово `VPN` на странице → `ipblock`; страна из `data-geo` → `yes`; иначе `unknown`. В RRC «нет VPN» = «да», в cii нужен ещё `data-geo` | да: `yes (US)` |
| Setanta Sports | B | `GET dce-frontoffice.imggaming.com/api/v2/consent-prompt` с заголовками `Realm` и `x-api-key` веб-клиента | `outsideAllowedTerritories` false → `yes`, true → `no` | нет |
| Hotstar | A | `GET www.hotstar.com/` без редиректа | 403/475 → `no`; страна из cookie `geo=`; US → `no` (сервис закрыт в США); совпадает с регионом в `Location` (`/sg`) → `yes`; иначе `unknown` | да: `geo=US`, `Location: /us` → `no (US)` |
| Channel 4 | A | `GET www.channel4.com/simulcast/channels/C4` | 200 → `yes`, 403 → `no` | да: 403 JSON → `no` |
| BBC iPlayer | A | `GET open.live.bbc.co.uk/mediaselector/6/…/bbc_one_london/…` | `geolocation` → `no`; `vs-hls-push-uk` → `yes` | да: `"result":"geolocation"` → `no` |
| Acorn TV | A | `GET acorn.tv/` | «not yet available in your»/«unavailable in your» → `no`; ссылка `signup.acorn.tv` при 200 → `yes` | да: `yes` |
| Shudder | A | `GET www.shudder.com/` | «not available»/«not yet available»/«403 ERROR» → `no`; `movies` при 200 → `yes` | да: `yes` |
| Canal+ | A | `GET boutique-tunnel.canalplus.com/` без редиректа | `Location` с `other-country-blocking` → `no`; 200 → `yes`; иначе `error`/`unknown` | частично: 403 «Unexpected Request» → `error` (геоблок или антибот — не различить) |
| Molotov | A | `GET fapi.molotov.tv/v1/open-europe/is-france` | `is_france` true → `yes`, false → `no` | да: `no` |
| ZDF | A | `GET ssl.zdf.de/geo/de/geo.txt/` | 404 → `yes` (так отвечает внутри Германии), 403 → `no`. RRC шлёт Android-UA, cii — честный | да: 403 Akamai → `no` |
| Rai Play | A | `GET mediapolisvod.rai.it/relinker/relinkerServlet.htm?cont=…` | `video_no_available` или `<geoprotection>N` → `no`; `Y` → `yes`; без тега → `unknown` | да: `no` |
| Sky CH | A | `GET www.sky.ch/` без редиректа | 403 или `Location` с `out-of-country` → `no`; 200 → `yes`. RRC запрашивает `sky.ch`, который редиректит на `www.sky.ch` | да: 403 CloudFront `FW_ERROR` → `no` |
| Rakuten TV | B | `POST gizmo.rakuten.tv/v3/me/start` с JSON-описанием веб-устройства, `Origin`/`Referer` `www.rakuten.tv` | «is not available» → `no`; `VPN`/`forbidden` → `ipblock`; `iso3166_code` + `streaming_drm_types` → `yes` со страной | нет |
| Sky Go | B | `GET skyid.sky.com/authorise/skygo?…` с `client_id=sky` и `redirect_uri=skygo://auth` из приложения | форма входа (`Sign in</h3>`, `skygoSignin`) → `yes`; страница Akamai «Access Denied» → `no`. Вход не выполняется, страница только открывается | нет |
| ITVX | B | `POST magni.itv.com/playlist/itvonline/ITV/10_4782_0001.001` с JSON-описанием клиента, `Origin`/`Referer` `www.itv.com` | «Outside Of Allowed Geographic» → `no`; `Playlist` при 200 → `yes` | нет |
| Channel 5 | B | `GET cassie.channel5.com/api/v2/live_media/my5desktopng/C5.json?timestamp=…&auth=…` | `code` 3000 → `no`, 4003 → `yes` (так в RRC: доступ есть, нужна авторизация). `auth` — константа веб-клиента, `timestamp` — время запуска cii | нет |
| Sky DE | B | `GET edge.api.brightcove.com/playback/v1/accounts/…/videos/…` с policy key Brightcove (`Accept: application/json;pk=…`) и `Origin: www.sky.de` | `error_subcode` `CLIENT_GEO` → `no`; 200 с `sources` → `yes`; другой `error_subcode` → `unknown`. В RRC отсутствие ошибки = «да», в cii нужен список источников | нет |
| Videoland | B | `POST api.videoland.com/subscribe/videoland-account/graphql`, запрос `IsOnboardingGeoBlocked`, заголовок `apollographql-client-name` и `Origin` веб-клиента | `isOnboardingGeoBlocked` false → `yes`, true → `no` | нет |

Почему уровень B: Setanta, Rakuten TV, ITVX, Videoland, Sky DE и Channel 5 используют ключи, тела запросов или заголовки `Origin`/`Referer`, взятые из веб-клиента сервиса; Sky Go — OAuth-адрес с `client_id` приложения. User-Agent во всех проверках B честный.

## Не включено

| Сервис (функция RRC) | Причина |
|---|---|
| Discovery+ (`DiscoveryPlus`) | цепочка из трёх запросов: `bootstrapInfo` → анонимный токен → каталог с cookie токена. Движок `probe` выполняет только заранее заданные запросы и не передаёт значения из одного ответа в другой; к тому же лимит — один-два запроса |
| SonyLIV (`SonyLiv`) | JWT `securityToken` со страницы передаётся в API, затем страна из второго ответа — в третий запрос. Цепочка с динамическим токеном; страница сама по себе может сказать только «нет» |
| MathsSpot Roblox (`GameTest_MathsSpot`) | путь API и версия фронтенда берутся со страницы, затем `startSession` облачного гейминга now.gg со случайными идентификаторами сессии — цепочка и создание игровой сессии |
| Joyn (`Joyn`) | анонимный вход (`auth/anonymous`) → bearer-токен → запрос entitlement с `x-api-key`: цепочка с токеном из первого ответа |
| NLZIET (`NLZIET`) | уровень C: в RRC зашит bearer-токен чужой учётной записи (в нём e-mail и userId пользователя), токен к тому же истёк в 2024 году |
| NPO Start Plus (`NPO_Start_Plus`) | токен плеера из первого ответа передаётся во второй запрос — цепочка |
| Movistar+ (`MoviStarPlus`) | признак ненадёжен: `contratar.movistarplus.es` отвечает 200 из США, хотя сервис работает только в Испании — логика RRC «200 = да» дала бы ложное «да» |
| Amediateka (`Amediateka`) | признак ненадёжен: `www.amediateka.ru` отвечает 200 обычной главной страницей из США, ни редиректа на `unavailable`, ни 503; отличить доступность от недоступности по этому ответу нельзя |

## Ограничения и открытые вопросы

- Диагностика без честного UA (сравнение ответа Canal+, HBO Max и ZDF с браузерным User-Agent) в среде разработки была запрещена политикой сессии и не проводилась. Поэтому для Canal+ 403 остаётся `error`, а для HBO Max — `ipblock`: неясно, отказ это по адресу дата-центра или по User-Agent.
- SkyShowTime, Hotstar и Paramount+ проверены только на ответе из страны, где сервис недоступен или является «домашним»; формат ответа из европейской страны с сервисом взят из RRC и не наблюдался.
- Проверки уровня B вживую не запускались; при смене ключей или API они дают `unknown`/`error`, а не ложное «да».
