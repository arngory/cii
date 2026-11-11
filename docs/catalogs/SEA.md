# Каталог SEA — Юго-Восточная Азия

Перенос блока `SEA_UnlockTest` из [RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck) (RRC). Код — `internal/services/region_sea.go`, тесты — `region_sea_test.go`. Проверки Hotstar и HBO Max общие с каталогом EU и описаны в [EU.md](EU.md).

Все включённые проверки — уровня A, один запрос, честный User-Agent. «Проверено вживую» — один GET 9 ноября 2026 года из дата-центра в США (AS396982).

## Включено

| Сервис | Уровень | Запрос | Логика | Проверено вживую |
|---|---|---|---|---|
| Viu | A | `GET www.viu.com/` без редиректа | `Location` `/ott/no-service/` → `no`; `/ott/sg/…` → `yes` со страной; иначе `unknown` | да: `/ott/no-service/` → `no` |
| Hotstar | A | см. [EU.md](EU.md) | | да |
| HBO Max | A | см. [EU.md](EU.md) | | частично |
| B-Global (Southeast Asia) | A | `GET api.bilibili.tv/intl/gateway/web/playurl?s_locale=en_US&platform=web&ep_id=347666` | `code` 0 → `yes`; 10003003/10004001 → `no`; другой код → `unknown` с кодом | да: 10004001 → `no` |
| B-Global (Thailand) | A | то же, `ep_id=10077726` (тайтл только для Таиланда) | то же | да: `no` |
| B-Global (Indonesia) | A | то же, `ep_id=11130043` (только Индонезия) | то же | да: `no` |
| B-Global (Vietnam) | A | то же, `ep_id=11405745` (только Вьетнам) | то же | да: `no` |
| meWATCH | A | `GET cdn.mewatch.sg/api/items/97098/videos?…` | числовой `code` в ответе → `no`; `Stream` при 200 → `yes` | да: `{"code":8002,…}` → `no` |

Идентификаторы эпизодов B-Global и материала meWATCH — публичные идентификаторы контента из адресов страниц, а не ключи клиента, поэтому уровень A.

## Не включено

| Сервис (функция RRC) | Причина |
|---|---|
| SonyLIV (`SonyLiv`) | цепочка с JWT со страницы, см. [EU.md](EU.md) |
| AIS Play (`AISPlay`) | уровень C: вход с зашитыми логином и паролем (`user=…&pass=…`) и цепочка из четырёх запросов (вход → шаблон → метаданные → поток) |
| TrueID (`trueID`) | цепочка: `channelId` и `buildId` со страницы, из `buildId` собирается Basic-авторизация для второго запроса |
