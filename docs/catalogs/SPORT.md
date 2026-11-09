# Каталог SPORT — спорт

Перенос блока `Sport_UnlockTest` из [RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck) (RRC). Код — `internal/services/region_sport.go`, тесты — `region_sport_test.go`, идентификаторы уровня B — `internal/clientids/region_eoss.go`. У каталога нет списка стран: он выбирается явно. NBA TV и Setanta Sports — общие проверки с каталогами OC и EU.

«Проверено вживую» — один GET 9 ноября 2026 года из дата-центра в США (AS396982) с UA `cii/…`, только уровень A.

## Включено

| Сервис | Уровень | Запрос | Логика | Проверено вживую |
|---|---|---|---|---|
| NBA TV | A | `GET www.nba.com/watch/` | см. [OC.md](OC.md) | частично: 403 Akamai → `ipblock` |
| Fubo TV | A | `GET api.fubo.tv/v3/location` | `NO_SERVICE_IN_COUNTRY` → `no`; `"network_allowed":false` → `ipblock`; `"network_allowed":true` → `yes`; страна — `country_code2`. RRC шлёт `Origin`/`Referer` `www.fubo.tv`, но эндпоинт отвечает и без них, поэтому уровень A | да: `yes (US)` |
| Setanta Sports | B | см. [EU.md](EU.md) | | нет |

## Не включено

| Сервис (функция RRC) | Причина |
|---|---|
| DAZN (`Dazn`) | уже есть в мультирегиональном наборе (`DAZN`, уровень B) |
| Star+ | только подпись в списке RRC, функция не вызывается; сервис влит в Disney+ |
| ESPN+ (`ESPNPlus`) | уровень C: device-токен чужой сессии и тело запроса из удалённого файла `cookies` RRC, плюс цепочка token → refresh_token → GraphQL |
| Mola TV (`MolaTV`) | `mola.tv` больше не разрешается в DNS — сервис закрыт |
| Optus Sport (`OptusSports`) | эндпоинт проверки учётной записи с чужим e-mail, см. [OC.md](OC.md) |
| beIN Sports Connect (`BeinConnect`) | эндпоинт изменился: на `GET …/proxy/availableOffers` из США приходит 200 `{"error":{"code":-11,"message":"Method not supported"}}`, а логика RRC опирается на 500 (= да) и 451 (= нет); воспроизвести её нельзя |
| Eurosport RO (`EurosportRO`) | цепочка: анонимный токен из первого ответа передаётся во второй запрос (`playback/v2/videoPlaybackInfo`) |
