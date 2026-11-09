# Каталог SA — Латинская Америка

Перенос блока `SA_UnlockTest` из [RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck) (RRC). Код — `internal/services/region_sa.go` (проверки общие с каталогом NA, реализация — в `region_na.go`), тесты — `region_sa_test.go`. Общие правила — в [NETWORK_POLICY.md](../NETWORK_POLICY.md) и [MODULES.md](../MODULES.md); принципы переноса — в [NA.md](NA.md).

«Проверено вживую» — один GET 9 ноября 2026 года из дата-центра в США с UA `cii/…`, только для уровня A. Из Латинской Америки ответы не наблюдались.

## Включено

| Сервис | Уровень | Запрос | Логика | Проверено вживую |
|---|---|---|---|---|
| Paramount+ | A | `GET www.paramountplus.com/` (с редиректами) | `pageProps.region`: код страны → `yes` со страной; `intl` → `no`; иначе `unknown` | да, из США: `yes (US)`; латиноамериканский ответ не наблюдался |
| HBO Max | B | `GET www.hbomax.com/` с браузерным User-Agent | 200 и страна из `countryCode=`: US или есть в списке `"url":"/xx/yy"` → `yes`; нет в списке → `no`; нет страны или списка → `unknown` | частично: честный UA → 403 Akamai → `error`; причина уровня B — в [NA.md](NA.md) |

## Не включено

| Сервис (функция RRC) | Причина |
|---|---|
| DirecTV Go (`DirecTVGO`) | признак RRC больше не работает: `www.directvgo.com/registrarse` отвечает 301 на `/co/registrarse`, а тот — 404; главная из США редиректит на `/ar/home` (200). Регион из адреса, по которому RRC ставит «да», не связан с доступностью — из США это дало бы ложное «да (AR)». Сервис переименован в DGO, надёжного признака не найдено |
| Star+ | в массиве подписей RRC есть, функции нет; сервис в 2024 году влит в Disney+ (проверяется в мультирегиональном наборе) |
