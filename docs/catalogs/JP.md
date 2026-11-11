# Каталог JP — Япония

Перенос блока `JP_UnlockTest` из [RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck) (RRC). Код — `internal/services/region_jp.go`, тесты — `region_jp_test.go`, идентификаторы уровня B — `internal/clientids/region_jkht.go`. Общие правила — в [NETWORK_POLICY.md](../NETWORK_POLICY.md) и [MODULES.md](../MODULES.md). Общие помощники `jkht*` (оценка по коду ответа, по маркерам, по коду в JSON, по `Location`) лежат в `region_jp.go` и используются также каталогами KR, HK и TW.

Одна проверка — один запрос. User-Agent честный (`cii/…`); браузерный UA, `sec-ch-*` и прочие заголовки браузера из RRC не переносились. Исключение — две игры уровня B, чей API отвечает только UA приложения (см. таблицу). Там, где RRC смотрит на конечный адрес после редиректов, cii запрашивает страницу без перехода по редиректу (`NoRedirect`) и читает `Location`: движок не отдаёт конечный URL, а переход на другой домен всё равно заблокирует сетевая политика. Любой ответ без ожидаемого признака даёт `unknown`, HTTP-ошибка без признака — `error`; «да» без положительного признака не выдаётся.

«Проверено вживую» — один GET 9 ноября 2026 года из дата-центра в США с UA `cii/…`; так проверялись только запросы уровня A (и один GET без заголовков к Telasa, чтобы определить уровень). Для уровня B живых запросов не было: логика взята из RRC и закреплена тестами на синтетических ответах. Из США проверяется только ветка «нет»; ветка «да» везде построена по RRC.

## Включено

| Сервис | Уровень | Запрос | Логика | Проверено вживую |
|---|---|---|---|---|
| DMM TV | B | `POST api.beacon.dmm.com/v1/streaming/start` с JSON веб-плеера (`player_name: dmmtv_browser`, `content_id`) | `FOREIGN` → `no`; `UNAUTHORIZED` (геопроверка пройдена, нужен вход) → `yes` | нет |
| ABEMA | A | `GET api.abema.io/v1/ip/check?device=android` | `isoCountryCode` JP → `yes (JP)`; другая страна → `partial` («overseas only», в RRC «Oversea Only»); нет страны → `unknown`. RRC шлёт Android-UA, честный UA отвечает так же | да: `US` → `partial` |
| Niconico | A | `GET www.nicovideo.jp/watch/so23017073` | в `server-response` страницы: `code` OK → `yes`; `reasonCode` `DOMESTIC_VIDEO` или текст «同じ地域» → `no`. Маркер «同じ地域» из RRC на странице больше не встречается, признак взят из живого ответа. Вторая часть RRC (поиск и открытие официальной трансляции, ещё два запроса) не переносилась | да: `FORBIDDEN`/`DOMESTIC_VIDEO` → `no` |
| Telasa | B | `GET api-videopass-anon.kddi-video.com/v1/playback/system_status` с `X-Device-ID` | `IPLocationNotAllowed` → `no`; `status.type` OK → `yes`. Без `X-Device-ID` API отвечает 400 `InvalidDeviceID` (проверено), поэтому уровень B | только без заголовка: 400 |
| U-NEXT | B | `POST cc.unext.jp` — GraphQL `cosmo_getPlaylistUrl` веб-клиента | `resultStatus` 200/475 → `yes`, 467 → `no`. Набор запрашиваемых полей сокращён до `resultStatus` и `result` | нет |
| Hulu Japan | A | `GET id.hulu.jp/` без редиректа | `Location` с `restrict` → `no`; 403 → `no`; 200 → `yes`; другой редирект → `unknown` | да: 403 Akamai → `no` |
| Lemino | B | `POST if.lemino.docomo.ne.jp/v1/user/delivery/watch/ready` с `X-Service-Token`, `X-Trace-Id`, `Origin`/`Referer` веб-клиента и JSON запроса воспроизведения | 200 → `yes`, 403 → `no` | нет |
| AnimeFesta | B | `GET api-animefesta.iowl.jp/v1/titles/1560` с `Anime-User-Tracking-Id`, `Origin`/`Referer` | 200 → `yes`, 403 → `no` | нет (B). Справочно: GET без заголовков из США — 403 |
| d Anime Store | A | `GET animestore.docomo.ne.jp/animestore/reg_pc` | страница «海外からのアクセス» / `overseas_warn` → `no`; 200 со словом «dアニメストア» → `yes`. RRC требует для этого хоста `UnsafeLegacyServerConnect` в OpenSSL; живой запрос прошёл и без него | да: `no` |
| FOD | A | `GET geocontrol1.stream.ne.jp/fod-geo/check.xml` | `<FLAG TYPE="true">` → `yes`, `false` → `no` | да: `no` |
| Radiko | A | `GET radiko.jp/area` | `class="OUT"` → `no`; `class="JP…"` → `yes (JP)`; название области — в `Detail` | да: `OUT` → `no` |
| Karaoke@DAM | A | `GET http://cds1.clubdam.com/…/sample_1.mp4.m3u8` | 200 → `yes`, 403 → `no` | да: 403 → `no` |
| J:COM On Demand | A | `GET auth.id2.zaq.ne.jp/login` (страница входа только открывается) | 200 → `yes`, 403 → `no` | да: 403 Cloudflare «you have been blocked» → `no` (геоблок или антибот-правило — не различить) |
| WATCHA | A | `GET watcha.com/` (редирект внутри домена) | 200 → `yes`, 451 → `no`. Та же проверка, что в каталоге KR | да: 200 → `yes` |
| Rakuten TV JP | A | `GET api-live.tv.rakuten.co.jp/v1/contents/387878/playinfo?device_id=2` | `IS_FOREIGN` → `no`; `in_vod` → `yes`. Второй запрос RRC (`webapi.nba.rakuten.co.jp`, доступность NBA) не переносился: это другой продукт, а хост из США не отвечал | да: `IS_FOREIGN` → `no` |
| KanColle | A | `GET http://203.104.209.7/kcscontents/twitter/maintenance_info.html` | 200 → `yes`, 403 → `no` | нет: таймаут соединения |
| Uma Musume | A | `GET api-umamusume.cygames.jp/` | 404 → `yes` (так отвечает API внутри Японии), 403 → `no`. RRC шлёт Android-UA, cii — честный | нет: хост не отвечал |
| Princess Connect! Re:Dive | A | `GET api-priconne-redive.cygames.jp/` | 404 → `yes`, 403 → `no`. RRC шлёт Android-UA, cii — честный | нет: обрыв HTTP/2 |
| Konosuba Fantastic Days | B | `POST api.konosubafd.jp/api/masterlist` с UA iOS-приложения | 200 → `yes`, 403 → `no`. UA приложения нужен потому, что это API игрового клиента, браузеру и `cii/…` он не предназначен. Возможно, игра закрыта — тогда проверка вернёт `error` | нет: хост не отвечал |
| Project Sekai | B | `GET game-version.sekai.colorfulpalette.org/1.8.1/<id>` с UA iOS-приложения | 200 → `yes`, 403 → `no`. Причина UA — как у Konosuba | нет |
| mora | A | `GET mora.jp/buy?…` (редиректы внутри домена) | 200 → `yes`; 403/500 → `no` (как в RRC) | да: 302 → `/error` 500 → `no` |
| music.jp | A | `GET overseaauth.music-book.jp/globalIpcheck.js` | 403 или пустой ответ → `no`; `checkIp` → `yes` | да: 403 → `no` |
| EroGameScape | A | `GET erogamescape.org/` | 200 со строкой «18歳» → `yes`; 403 → `no`. В RRC любой другой ответ — «нет», в cii — `unknown` | нет: сброс соединения |

## Исключено

| Сервис (RRC) | Причина |
|---|---|
| DMM (`bitcoin.dmm.com`) | сервис мёртв: биржа DMM Bitcoin прекратила работу в 2025 году (клиенты переведены в SBI VC Trade); хост из среды проверки не отвечал |
| TVer | цепочка из пяти запросов: создание «пользователя платформы», выбор текущего эпизода, загрузка JS плеера Brightcove ради `policyKey`; статический вариант быстро устаревает, а один-два запроса не дают ответа |
| WOWOW | цепочка из четырёх запросов с поиском бесплатного эпизода и `meta_id` на страницах; зашитый `meta_id` устареет |
| VideoMarket | уровень C: Bearer-JWT и cookie (`_ga`, `_td`, сессионные ID) скопированы из чужой браузерной сессии |
