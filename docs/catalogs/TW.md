# Каталог TW — Тайвань

Перенос блока `TW_UnlockTest` из [RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck) (RRC). Код — `internal/services/region_tw.go`, тесты — `region_tw_test.go`, идентификаторы уровня B — `internal/clientids/region_jkht.go`. Общие правила — в [NETWORK_POLICY.md](../NETWORK_POLICY.md) и [MODULES.md](../MODULES.md); общие соглашения переноса (честный UA, `NoRedirect` вместо конечного URL, `unknown` вместо «да» без признака) — в [JP.md](JP.md).

«Проверено вживую» — один GET 9 ноября 2026 года из дата-центра в США с UA `cii/…`, только для уровня A. Для уровня B живых запросов не было (кроме справочного GET к 4GTV без заголовков, см. ниже).

## Включено

| Сервис | Уровень | Запрос | Логика | Проверено вживую |
|---|---|---|---|---|
| KKTV | A | `GET api.kktv.me/v3/ipcheck` | `data.is_allowed` true → `yes`, false → `no`; страна из `data.country`; без `is_allowed` — TW → `yes`, другая → `no` (как в RRC) | да: `US`, `is_allowed: false` → `no (US)` |
| LiTV | B | `POST www.litv.tv/api/get-urls-no-auth` с JSON веб-плеера (`AssetId`, случайный `puid` на каждый запуск) и `Origin`/`Referer` `www.litv.tv` | `AssetURLs` → `yes`; код 42000087 → `no`; 42000075 («эпизод не найден», геопроверка пройдена) → `yes` | нет |
| MyVideo | A | `GET www.myvideo.net.tw/login.do` без редиректа | `Location` с `serviceAreaBlock` → `no`; 403 → `no`; 200 → `yes`; другой редирект → `unknown` | да: `serviceAreaBlock.do` → `no` |
| 4GTV | B | `GET api2.4gtv.tv/Web/IsTaiwanArea` с `Origin`/`Referer` `www.4gtv.tv` | `Data` `Y` → `yes`, `N` → `no` | нет. Справочно: GET без `Origin` из США — 403 со страницей ошибки, поэтому уровень B |
| LINE TV | B | `GET www.linetv.tw/api/part/11829/eps/1/part?appId=…` | `countryCode` 228 → `yes`; другое число → `no`; нет → `unknown`. RRC каждый раз скачивает главную и `main-*.js` (~2 МБ) ради `appId`; cii хранит `appId` в `clientids` (снят 9 ноября 2026 из публичного `main-dbbbf7a8-prod.js`) и делает один запрос | нет |
| Hami Video | A | `GET hamivideo.hinet.net/api/play.do?id=OTT_VOD_0000249064&freeProduct=1` | `code` `06001-107` → `yes`, `06001-106` → `no` | да: `06001-106` → `no` |
| CatchPlay+ | B | `GET sunapi.catchplay.com/geo` с `Authorization: Basic` веб-клиента | `code` `0` → `yes`, `100016` → `no` | нет |
| HBO Max | A | общая проверка (`internal/services/shared.go`), `GET www.hbomax.com/` | см. [EU.md](EU.md) | да: 403 Akamai (честный UA) |
| Bilibili TW | A | `GET api.bilibili.com/pgc/player/web/playurl?avid=50762638&cid=100279344&ep_id=268176&…` | `code` 0 → `yes`, -10403 → `no` | да: -10403 → `no` |

## Исключено

| Сервис (RRC) | Причина |
|---|---|
| Bahamut Anime | см. [HK.md](HK.md): три запроса с cookie-сессией, главная отвечает 403 честному UA |
| SonyLiv | см. [HK.md](HK.md): цепочка из трёх запросов с JWT, страница кешируется на CDN с данными другого посетителя |
