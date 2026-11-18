# Service availability checks

[Русская версия](../SERVICE_CHECKS.md)

The `services` module checks whether services are available from your address. Sources of ideas: [RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck) (the multi-region block), [IPQuality](https://github.com/xykt/IPQuality) and [ipregion](https://github.com/vernette/ipregion); the overlaps between them are merged into one check. The implementation is cii's own, one or two requests per service per run, an honest User-Agent. `--quick` disables the module, `--plan` shows its hosts.

Statuses: `yes` (available, where possible with the country that the service determined), `no` (not available in this region), `partial` (for example, Netflix — its own series only), `blocked` (the service refused this particular address), `?` (a response with no indicators), `error` (failure, limit, HTTP error; the reason is in "Failed checks").

## Tier A — by default

| Service | Group | Request | Logic |
|---|---|---|---|
| Netflix | Streaming | two title pages (non-originals), as in RegionRestrictionCheck | both exist or one exists → `yes`; both "Oh no!"/404 → `partial` (Originals only); the country comes from the page's `requestCountry` |
| Prime Video | Streaming | `www.primevideo.com` | `currentTerritory` → `yes`; `isServiceRestricted` → `no` |
| Reddit | Web | `www.reddit.com` | 200 → `yes`; 403 → `blocked` |
| Wikipedia editing | Web | the official MediaWiki API `meta=userinfo&uiprop=blockinfo` | `blockid` present → `blocked` (the address is blocked from editing, typical of proxies and VPNs) |
| OpenAI, Anthropic, Grok API | AI | `GET /v1/models` without a key | 401 → `yes`; 403 with a region marker → `no`; another 403 → `blocked` |
| Mistral, Groq, Cohere, DeepSeek, Qwen, Kimi, GLM, MiniMax, Doubao, SiliconFlow API (international and Chinese endpoints) | AI | `GET …/models` without a key | 401 → `yes` (the API is reachable and responds); 403 → `blocked` |
| ChatGPT app | AI | `GET ios.chat.openai.com` — the host the mobile app works with | "disallowed ISP" → `blocked`; `unsupported_country` → `no`; a response below 400 → `yes`. A 403 with the JSON `cf_details` (`"type":"dc"`) — `?`: such a response comes both from data centre addresses and from residential providers, that is, the host refuses any client except the app itself and says nothing about the network |
| NotebookLM | AI | `GET notebooklm.google.com` following redirects (`notebook.google.com`, `accounts.google.com` are declared) | a final address with `location=unsupported` → `no`; the service page or the Google account sign-in → `yes`; another address → `?` |
| Gemini API | AI | `GET generativelanguage.googleapis.com/v1beta/models`, only with your `gemini_api_key` (the `X-Goog-Api-Key` header) | 200 → `yes`; "User location is not supported" → `no`; an invalid key → error. Without a key Google reports nothing about the region, so the check is off |

If the response is a Cloudflare challenge page (403, 429 or 503 with the header `cf-mitigated: challenge`, `_cf_chl_opt` or the title "Just a moment..."), any check gets `?` "Cloudflare challenge, availability not tested": the service did not refuse, the request simply did not reach the check. A Cloudflare WAF block page ("Sorry, you have been blocked") remains a block by address.

## Tier B — only with `--extended`

They use identifiers from `internal/clientids/clientids.go`; the risks are the same as described in [REGION_CHECKS.md](REGION_CHECKS.md#tier-b--only-with---extended). They were not run live in the development environment.

| Service | Request | Logic |
|---|---|---|
| Disney+ | GraphQL `registerDevice` on `disney.api.edge.bamgrid.com` | `inSupportedLocation` true/false; "Forbidden location" → `no` |
| Spotify signup | `spclient.wg.spotify.com/signup/public/v1/account` | `is_country_launched`; statuses 120/320 → `no` |
| YouTube Premium | `POST www.youtube.com/youtubei/v1/browse` (`SPunlimited`) | a purchase button is present → `yes`, otherwise `no` |
| DAZN | `POST startup.core.indazn.com/misl/v5/Startup` | `isAllowed`; "Security policy has been breached" → `blocked` |

## Not included, and why

| What | Reason |
|---|---|
| Google Search (CAPTCHA), Bing (region from the results) | automated requests to search results are expressly forbidden by the search engines' terms |
| the `youtube.com/premium` page | the phrase "Premium is not available in your country" is also present where the service is available — the indicator is unreliable |
| the `disneyplus.com` home page | the word "unavailable" is on every page; a reliable indicator exists only in the API (tier B) |
| `claude.ai` (web) | an honest User-Agent gets a bot-check 403; Anthropic availability is visible from `Anthropic API` |
| `gemini.google.com`, `play.google.com` | the markers from RegionRestrictionCheck cannot be reproduced; the Gemini API without a key says nothing about the region |
| Instagram Music | in RegionRestrictionCheck — a closed-source binary |
| the regional catalogues of RegionRestrictionCheck (HK, TW, JP, NA, SA, EU, OC, KR, SEA, AF) | the next step, ported region by region |

## Your own checks

The `services` section of the config ([CONFIG.md](CONFIG.md#services)) adds checks of your own addresses. Each is one `GET` request without keys or special headers, separately for each stack (IPv4 and IPv6). The host from `url` becomes a network policy rule of the `services` module and is visible in `--plan` and in the network ledger, like the built-in ones.

The response is read in order:

1. the body contains the `blocked` string — `no` ("blocked marker found");
2. the status code does not fit (not in `expect`, or without `expect` — 400 and above) — `no` with the code; for 429 and 5xx — `error`, because such a response says nothing about availability;
3. a `contains` string is set and the body lacks it — `no` ("marker not found");
4. otherwise — `yes`.

Redirects are not followed: a 301 or 302 is the answer itself, and no request goes to another host. To check the final page, give its address. A Cloudflare challenge page gives `?`, as with the built-in checks. In JSON such results are marked `"custom": true` and carry the checked host in the `host` field (an internationalised name in its punycode form).

`--mask` hides the hosts of your own checks in the network ledger and reduces an error reason to a short category ("no such host", "certificate", "timeout", "request failed"): the original error text may hold names from a certificate or addresses. A label set in `name` stays; a label that looks like a host (including the one taken from `url` by default) is replaced with `check N`.
