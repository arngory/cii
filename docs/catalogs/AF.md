# Каталог AF — Африка

Перенос блока `AF_UnlockTest` из [RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck) (RRC). Код — `internal/services/region_af.go`, тесты — `region_af_test.go`. Общие правила — в [NETWORK_POLICY.md](../NETWORK_POLICY.md) и [MODULES.md](../MODULES.md); принципы переноса — в [NA.md](NA.md).

«Проверено вживую» — один GET 9 ноября 2026 года из дата-центра в США с UA `cii/…`. Из Африки ответы не наблюдались.

## Включено

| Сервис | Уровень | Запрос | Логика | Проверено вживую |
|---|---|---|---|---|
| DStv | A | `GET authentication.dstv.com/favicon.ico` | 404 → `yes`; 403/451 → `no` (геоограничение CloudFront); другие ответы → `unknown`/`error`. Это признак RRC: он показывает, пускает ли CloudFront к сайту авторизации DStv, а не доступность каталога | да: 404 (`x-cache: Error from cloudfront`) → `yes` — то есть из США геоограничение сайта авторизации не срабатывает |
| Viu | A | `GET www.viu.com/` без редиректа | `Location` `/ott/no-service/` → `no`; `/ott/<cc>/…` → `yes` со страной; другой редирект → `unknown` | да: `Location: /ott/no-service/` → `no` |

## Не включено

| Сервис (функция RRC) | Причина |
|---|---|
| Showmax (`Showmax`) | сервис не отвечает: `showmax.com` и `www.showmax.com` не разрешаются в DNS (серверы имён Akamai отвечают REFUSED, «lame delegation», 9 ноября 2026). Кроме того, RRC подставлял браузерный UA и считал «нет» любой ответ без cookie `activeTerritory`, включая сбой |
| Paramount+ | закомментирован в блоке AF самого RRC |
