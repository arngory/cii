# Каталог IN — Индия

Перенос блока `IN_UnlockTest` из [RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck) (RRC). Код — `internal/services/region_in.go` (Hotstar и NBA TV — общие проверки из `shared.go`), тесты — `region_in_test.go`. Общие правила — в [NETWORK_POLICY.md](../NETWORK_POLICY.md) и [MODULES.md](../MODULES.md); принципы переноса — в [NA.md](NA.md).

«Проверено вживую» — один GET 9 ноября 2026 года из дата-центра в США с UA `cii/…`, только для уровня A. Из Индии ответы не наблюдались.

## Включено

| Сервис | Уровень | Запрос | Логика | Проверено вживую |
|---|---|---|---|---|
| Hotstar | A | `GET www.hotstar.com/` без редиректа | 403/475 → `no`; страна из cookie `geo=`; US → `no`; совпадает с регионом в `Location` (`/in`) → `yes`; `geo=IN` и редирект на `jiohotstar.com` → `yes` (сервис объединён с JioCinema в JioHotstar; этот путь добавлен в cii и не наблюдался); иначе `unknown` | из США: `no (US)` |
| MX Player | A | `GET www.mxplayer.in/` | «403 ERROR»/«not available in your» → `no`; 200 с заголовком `Set-Cookie` → `yes` (признак RRC); иначе `unknown` | да: «We are currently not available in your region» → `no` |
| NBA TV | B | `GET www.nba.com/watch/` с браузерным User-Agent | «Service is not available in your region» → `no`; 200 со словом NBA → `yes` | частично: честный UA → 403 Akamai → `error`; причина уровня B — в [NA.md](NA.md) |
| Zee5 | A | `GET www.zee5.com/` с честным UA | 200 и страна из `country=` (cookie или страница) → `yes` со страной; иначе `unknown`/`error`. Как и в RRC, «нет» не выводится: Zee5 работает в большинстве стран | частично: из дата-центра 403 Akamai → `error` |

Zee5 остаётся в уровне A с честным User-Agent: подмена UA ради обхода Akamai по политике не делается, из дата-центра результат будет `error`.

## Не включено

| Сервис (функция RRC) | Причина |
|---|---|
| SonyLIV (`SonyLiv`) | цепочка из трёх запросов с JWT со страницы; страница содержит геоданные сервера рендеринга, а не клиента (подробно — в [NA.md](NA.md)) |
| JioCinema (`JioCinema`) | сервис в феврале 2025 года объединён с Disney+ Hotstar в JioHotstar (покрывается проверкой Hotstar); `www.jiocinema.com` отдаёт пустую оболочку SPA. Проверка RRC к тому же использует `Origin`/`Referer` сайта и CORS-preflight `OPTIONS` |
