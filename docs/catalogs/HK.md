# Каталог HK — Гонконг и Макао

Перенос блока `HK_UnlockTest` из [RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck) (RRC). Код — `internal/services/region_hk.go`, тесты — `region_hk_test.go`, идентификаторы уровня B — `internal/clientids/region_jkht.go`. Общие правила — в [NETWORK_POLICY.md](../NETWORK_POLICY.md) и [MODULES.md](../MODULES.md); общие соглашения переноса (честный UA, `NoRedirect` вместо конечного URL, `unknown` вместо «да» без признака) — в [JP.md](JP.md).

«Проверено вживую» — один GET 9 ноября 2026 года из дата-центра в США с UA `cii/…`, только для уровня A. Для уровня B живых запросов не было.

## Включено

| Сервис | Уровень | Запрос | Логика | Проверено вживую |
|---|---|---|---|---|
| Now E | B | `POST webtvapi.nowe.com/16/1/getVodURL` с JSON веб-плеера (`deviceId`, `callerReferenceNo`, `trackId`, `sessionId`) и `Origin`/`Referer` `www.nowe.com` | `OTTAPI_ResponseCode` `SUCCESS` → `yes`, `GEO_CHECK_FAIL` → `no`; другой код → `unknown` | нет |
| Viu | A | `GET www.viu.com/` без редиректа | `Location` `/ott/no-service` → `no`; `/ott/<код страны>` → `yes` со страной; иначе `unknown` | да: `/ott/no-service/` → `no` |
| Viu.TV | B | `POST api.viu.now.com/p8/3/getLiveURL` с JSON Android-веб-клиента (`deviceId`, канал 099) | `responseCode` `SUCCESS` → `yes`, `GEO_CHECK_FAIL` → `no` | нет |
| myTV SUPER | A | `GET www.mytvsuper.com/api/auth/getSession/self/` | `country_code` HK → `yes (HK)`; другая страна → `no` со страной; нет страны → `unknown` | да: `US` → `no (US)` |
| HBO Max | A | общая проверка (`internal/services/shared.go`), `GET www.hbomax.com/` | см. [EU.md](EU.md); 403 Akamai → `ipblock` | да: 403 Akamai (честный UA) |
| Bilibili HK/MO/TW | A | `GET api.bilibili.com/pgc/player/web/playurl?avid=18281381&cid=29892777&ep_id=183799&…` | `code` 0 → `yes`, -10403 → `no`; другой код → `unknown`. Случайный `session` из RRC не передаётся | да: -10403 → `no` |

## Исключено

| Сервис (RRC) | Причина |
|---|---|
| SonyLiv | RRC делает три запроса: главная страница → JWT `securityToken` → API `ULD` (страна) → проверка воспроизведения; движок не передаёт значения между запросами. Упростить до одной страницы нельзя: она кешируется на CDN — в живом ответе были страна, штат и IP другого посетителя |
| Bahamut Anime | три запроса с cookie-сессией (`getdeviceid` → `token.php` с `deviceid` → главная ради `data-geo`); главная `ani.gamer.com.tw` честному UA отвечает 403 «系統異常回報». Повтор с браузерным UA среда проверки отклонила как обход антибот-защиты |
