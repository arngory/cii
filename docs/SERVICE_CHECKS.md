# Проверки доступности сервисов

Модуль `services` проверяет, доступны ли сервисы с вашего адреса. Источники идей: [RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck) (мультирегиональный блок), [IPQuality](https://github.com/xykt/IPQuality) и [ipregion](https://github.com/vernette/ipregion); пересечения между ними сведены в одну проверку. Реализация своя, один-два запроса на сервис за запуск, честный User-Agent. `--quick` отключает модуль, `--plan` показывает его хосты.

Статусы: `yes` (доступно, при возможности со страной, которую определил сервис), `no` (недоступно в этом регионе), `partial` (например, Netflix — только собственные сериалы), `blocked` (сервис отказал именно этому адресу), `?` (ответ без признаков), `error` (сбой, лимит, HTTP-ошибка; причина — в «Failed checks»).

## Уровень A — по умолчанию

| Сервис | Группа | Запрос | Логика |
|---|---|---|---|
| Netflix | Streaming | две страницы тайтлов (не-оригинальные), как в RegionRestrictionCheck | оба есть или один есть → `yes`; оба «Oh no!»/404 → `partial` (только Originals); страна — из `requestCountry` страницы |
| Prime Video | Streaming | `www.primevideo.com` | `currentTerritory` → `yes`; `isServiceRestricted` → `no` |
| Reddit | Web | `www.reddit.com` | 200 → `yes`; 403 → `blocked` |
| Wikipedia editing | Web | официальный MediaWiki API `meta=userinfo&uiprop=blockinfo` | есть `blockid` → `blocked` (адрес заблокирован для правок, типично для прокси и VPN) |
| OpenAI, Anthropic, Grok API | AI | `GET /v1/models` без ключа | 401 → `yes`; 403 с маркером региона → `no`; другой 403 → `blocked` |
| Mistral, Groq, Cohere, DeepSeek, Qwen, Kimi, GLM, MiniMax, Doubao, SiliconFlow API (международные и китайские эндпоинты) | AI | `GET …/models` без ключа | 401 → `yes` (API доступен и отвечает); 403 → `blocked` |

## Уровень B — только с `--extended`

Используют идентификаторы из `internal/clientids/clientids.go`; риски те же, что описаны в [REGION_CHECKS.md](REGION_CHECKS.md#уровень-b--только-с---extended). Вживую в среде разработки не запускались.

| Сервис | Запрос | Логика |
|---|---|---|
| Disney+ | GraphQL `registerDevice` на `disney.api.edge.bamgrid.com` | `inSupportedLocation` true/false; «Forbidden location» → `no` |
| Spotify signup | `spclient.wg.spotify.com/signup/public/v1/account` | `is_country_launched`; статусы 120/320 → `no` |
| YouTube Premium | `POST www.youtube.com/youtubei/v1/browse` (`SPunlimited`) | есть кнопка покупки → `yes`, иначе `no` |
| DAZN | `POST startup.core.indazn.com/misl/v5/Startup` | `isAllowed`; «Security policy has been breached» → `blocked` |

## Не включено и почему

| Что | Причина |
|---|---|
| Google Search (капча), Bing (регион из выдачи) | автоматические запросы к поисковой выдаче прямо запрещены условиями поисковиков |
| страница `youtube.com/premium` | фраза «Premium is not available in your country» присутствует и там, где сервис доступен — признак ненадёжен |
| главная `disneyplus.com` | слово «unavailable» есть на любой странице; надёжный признак — только в API (уровень B) |
| `claude.ai` (веб) | честному User-Agent отдаётся 403 проверки на бота; доступность Anthropic видна по `Anthropic API` |
| `gemini.google.com`, `play.google.com` | маркеры из RegionRestrictionCheck не воспроизводятся; Gemini API без ключа не отвечает о регионе |
| Instagram Music | в RegionRestrictionCheck — закрытый бинарник |
| региональные каталоги RegionRestrictionCheck (HK, TW, JP, NA, SA, EU, OC, KR, SEA, AF) | следующий шаг, переносятся по регионам |
