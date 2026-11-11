# Каталог OC — Океания (Австралия, Новая Зеландия)

Перенос блока `OA_UnlockTest` из [RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck) (RRC). Код — `internal/services/region_oc.go`, тесты — `region_oc_test.go`, идентификаторы уровня B — `internal/clientids/region_eoss.go`. Проверки NBA TV, Acorn TV, BritBox и Paramount+ общие с каталогами EU и SPORT и описаны в [EU.md](EU.md) и [SPORT.md](SPORT.md).

Одна проверка — один запрос с честным User-Agent. Где RRC смотрит на конечный адрес после редиректов, cii не следует за редиректом и читает `Location`.

«Проверено вживую» — один GET 9 ноября 2026 года из дата-центра в США (AS396982) с UA `cii/…`, только уровень A.

## Включено

| Сервис | Уровень | Запрос | Логика | Проверено вживую |
|---|---|---|---|---|
| NBA TV | A | `GET www.nba.com/watch/` | 403 → `ipblock`; 200 с «Service is not available in your region» → `no`; другой 200 → `yes`. В RRC «Access Denied» Akamai давал ложное «да» — в cii это `ipblock` | частично: 403 Akamai → `ipblock` |
| Acorn TV | A | см. [EU.md](EU.md) | | да |
| BritBox | A | см. [EU.md](EU.md) | | да |
| Paramount+ | A | см. [EU.md](EU.md) | | да |
| AMC+ | A | `GET www.amcplus.com/` без редиректа | `Location` с `geographic-restriction` или 403 → `no`; 200 → `yes`; другой редирект → `unknown` | да: 200 → `yes` |
| DocPlay | A | `GET www.docplay.com/subscribe` без редиректа | `Location` с `geoblocked` или 403 → `no`; 200 со страницей «hasn't launched in your part of the world» (фон `background-geoblocked`) → `no`; другой 200 со словом DocPlay → `yes`. Признак страницы-заглушки добавлен: из США она отдаётся с кодом 200, и логика RRC «200 = да» ошибалась | да: заглушка → `no` |
| ABC iview | A | `GET api.iview.abc.net.au/v2/show/abc-kids-live-stream/video/LS1604H001S00?…` | «unavailable outside Australia» → `no`; `"playable":true` при 200 → `yes` | да: `no` |
| 9Now | A | `GET login.nine.com.au/` | «Geoblock» (заголовок страницы «Geoblocked») → `no`; «Log in to» при 200 → `yes` | да: 403 «Geoblocked» → `no` |
| 10 Play | A | `GET e410fasadvz.global.ssl.fastly.net/geo` (гео-эндпоинт 10 Play) | `allow` true → `yes`, false → `no` | да: `{"state":"WA","allow":false}` → `no` |
| SBS On Demand | A | `GET www.sbs.com.au/api/v3/network?context=odwebsite` | `get.response.country_code` AU → `yes (AU)`, другая страна → `no` со страной | да: `no (US)` |
| Sky Go NZ | B | `GET login.sky.co.nz/authorize?…` — адрес Auth0 с `client_id`, `state`, `nonce`, PKCE-challenge веб-клиента Sky Go | 200 → `yes`, 403 → `no`. Вход не выполняется | нет |

## Не включено

| Сервис (функция RRC) | Причина |
|---|---|
| SonyLIV (`SonyLiv`) | цепочка с JWT со страницы, см. [EU.md](EU.md) |
| Binge (`Binge`) | `auth.streamotion.com.au` из США отвечает 302 на `streamotion.com.au`; RRC идёт по редиректу и считает 200 за «да» — ложное «да» вне Австралии, другого признака нет |
| 7plus (`7plus`) | в адресе зашит подписанный `akamai_token` с `exp=1672500385` (декабрь 2022): токен истёк, любой ответ кроме 200 RRC считает «нет», то есть проверка всегда отвечает «нет»; подписанная ссылка из чужой сессии — уровень C |
| Optus Sport (`OptusSports`) | эндпоинт проверки существования учётной записи (`userauth/validate/…/username/<e-mail>`) с чужим адресом почты: запросы к функциям учётных записей с чужими данными не делаем |
| Kayo Sports (`KayoSports`) | `billingapi.streamotion.com.au/v2/offers/kayo/` отвечает 200 со списком тарифов из США (проверено простым GET без `Origin`); логика «200 = да» дала бы ложное «да» |
| Neon TV (`NeonTV`) | уровень C: заголовок и тело берутся из удалённого файла `cookies` RRC — bearer-токен чужой сессии и GraphQL-мутация `UpdateAccount` с e-mail и паролем |
| ThreeNow (`ThreeNow`) | хост `bravo-livestream.fullscreen.nz` больше не разрешается в DNS — сервис/поток закрыт |
| Māori+ (`MaoriTV`) | цепочка из четырёх запросов: страница → JS-бандл → плеер Brightcove → policy key → API воспроизведения |

## Ограничения

- Проверки AMC+, DocPlay и BritBox при редиректе на неизвестный адрес дают `unknown`, а не догадку о стране.
- Sky Go NZ (уровень B) вживую не запускался.
