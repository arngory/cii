# Каталог KR — Корея

Перенос блока `KR_UnlockTest` из [RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck) (RRC). Код — `internal/services/region_kr.go`, тесты — `region_kr_test.go`, идентификаторы уровня B — `internal/clientids/region_jkht.go`. Общие правила — в [NETWORK_POLICY.md](../NETWORK_POLICY.md) и [MODULES.md](../MODULES.md); общие соглашения переноса (честный UA, `NoRedirect` вместо конечного URL, `unknown` вместо «да» без признака) — в [JP.md](JP.md).

«Проверено вживую» — один GET 9 ноября 2026 года из дата-центра в США с UA `cii/…`, только для уровня A. Для уровня B живых запросов не было: логика взята из RRC и закреплена тестами на синтетических ответах.

## Включено

| Сервис | Уровень | Запрос | Логика | Проверено вживую |
|---|---|---|---|---|
| Wavve | B | `GET apis.wavve.com/fz/streaming?…` с `apikey` веб-клиента | 200 → `yes`; 403/550 → `no` | нет |
| TVING | B | `GET api.tving.com/v2a/media/stream/info` с `apiKey` веб-клиента | «available in South Korea» → `no`; `vod_type` → `yes` | нет |
| WATCHA | A | `GET watcha.com/` (редирект внутри домена на `/ko/browse/all`) | 200 → `yes`, 451 → `no` | да: 200 → `yes` (из США сервис открывается) |
| Coupang Play | A | `GET www.coupangplay.com/` без редиректа | `Location` с `not-available` → `no`; 403 → `no` (как в RRC); 200 → `yes`; другой редирект → `unknown` | да: 403 Akamai «Access Denied» → `no` |
| SPOTV NOW | B | `GET edge.api.brightcove.com/playback/v1/accounts/5764318566001/videos/6349973203112` с `policyKey` веб-плеера в `Accept` и `Origin`/`Referer` `www.spotvnow.co.kr` | `error_subcode` `CLIENT_GEO` → `no`; 200 без ошибки → `yes`; другой код → `unknown`/`error` | нет |
| KBS Domestic | A | `GET vod.kbs.co.kr/index.html?…` | `Domestic` в объекте `ipck` на странице: true → `yes`, false → `no` | да: `Domestic: false` → `no` |

## Исключено

| Сервис (RRC) | Причина |
|---|---|
| Naver TV | уровень C: запрос подписывается HMAC-SHA1 с ключом, извлечённым из JS веб-клиента, и меткой времени — это подделка подписи клиента, то есть обход защиты API, а не публичный client ID |
| Afreeca TV | сервис переименован в SOOP; `vod.afreecatv.com` сбрасывает соединение, `vod.sooplive.co.kr` перенаправляет на глобальный `vod.sooplive.com`, где страница открывается; маркер RRC (`document.location.href='https://vod.afreecatv.com'`) больше не встречается, надёжного признака региона не найдено |
