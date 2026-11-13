# Region checks

[Русская версия](../REGION_CHECKS.md)

The `region` module asks GeoIP providers and the services themselves which country they "see" your address in, and produces an overall verdict. The idea and the set of sources come from [vernette/ipregion](https://github.com/vernette/ipregion); the implementation is cii's own. Each check is one request per address per run, with an honest User-Agent. `--quick` disables the module, `--plan` shows all its hosts.

## Groups and verdict

| Group | What it is | Counts towards the verdict |
|---|---|---|
| **GeoIP** | geolocation databases: online providers that are given the address, and local `.mmdb` files (`local:<id>`) | yes |
| **Registry** | the country where the address block is registered, according to the RDAP of the regional registries (RIRs) | no: shown next to the verdict as `registered XX` with the mark `geo-consistent` (matches the verdict) or `geo-discrepant` (does not match) |
| **Platforms** | the country that the service determined from the incoming connection | yes |
| **CDN** | the location (IATA code) through which the service serves traffic; the country is taken from the built-in airport reference | no |

Verdict: each of the GeoIP and Platforms groups carries the same total weight, regardless of the number of checks in it; the country with the largest weight wins, and on a tie all of them are printed. Results from GeoIP and Platforms that differ from the verdict are listed separately ("Disagrees with the verdict").

Statuses: `ok` (country obtained), `unknown` (a response without a country or with `ZZ`), `ipblock` (the service refused this address), `error` (network failure, limit, HTTP error; the reason is printed in "Failed checks").

## Tier A — enabled by default

### GeoIP (the address is passed explicitly)

| Service | Request | Key | Notes |
|---|---|---|---|
| ipinfo.io | `ipinfo.io/{ip}/json` | `ipinfo_token` — optional | without a token the anonymous access limits apply |
| ipapi.co | `ipapi.co/{ip}/json/` | — | free limit without a key |
| ifconfig.co | `ifconfig.co/country-iso?ip=` | — | open echoip service, rate limiting |
| ip2location.io | `api.ip2location.io/?ip=` | `ip2location_key` — optional | without a key — a daily limit (the service reports it in the response); the same response carries a proxy flag |
| country.is | `api.country.is/{ip}` | — | open service |
| geojs.io | `get.geojs.io/v1/ip/country.json?ip=` | — | |
| ipbase.com | `api.ipbase.com/v2/info?ip=` | — | free limit without a key |
| ipquery.io | `api.ipquery.io/{ip}` | — | the same response carries the VPN, Tor, proxy, data centre and mobile network flags and a risk score (see [RISK_CHECKS.md](RISK_CHECKS.md#address-profile)) |
| ipwho.is | `ipwho.is/{ip}` | — | free for non-commercial use |
| DB-IP | `api.db-ip.com/v2/free/{ip}` | — | DB-IP's free API without a key, with a daily limit |
| ip-api.com | `http://ip-api.com/json/{ip}?fields=status,countryCode,proxy,hosting,mobile` | — | free for non-commercial use, HTTP only and IPv4 only; for an IPv6 address the request goes over IPv4; the same response carries the proxy, hosting and mobile network flags |
| ipregistry.co | `api.ipregistry.co/{ip}` | `ipregistry_key` — **required** | does not run without your key; the same response carries the connection type and company type, and security flags |
| geoapify.com | `api.geoapify.com/v1/ipinfo?ip=` | `geoapify_key` — **required** | does not run without your key |
| MaxMind GeoLite | `geolite.info/geoip/v2.1/country/{ip}` | `maxmind_account_id` + `maxmind_license_key` — **required** | the free GeoLite web service of your account |

### Registry (the address is passed explicitly)

| Service | Request | Key | Notes |
|---|---|---|---|
| RIPEstat | `stat.ripe.net/data/rir-stats-country` and `…/prefix-overview` (`?resource={ip}&sourceapp=cii`) | — | the public Data API of RIPE NCC. The country comes from the statistics of all five RIRs; the second request gives the announced prefix and ASN, which are shown in the `Route` line of the "IP quality" panel (with `--mask` the line is not shown). If the address is not announced, the output says so |
| RDAP (RIR) | `rdap.db.ripe.net/ip/{ip}` with a redirect to the right RIR | — | the country of registration, not geolocation; for ARIN — from the registrant's address. RIPE, ARIN, APNIC, LACNIC, registro.br and AFRINIC are allowed; a redirect to other NIRs is blocked by the policy |

### Platforms (by incoming connection)

| Service | Request | Where the country comes from |
|---|---|---|
| Cloudflare | `www.cloudflare.com/cdn-cgi/trace` | `loc=`; `colo=` for the CDN group is taken from the same response |
| Google | `accounts.google.com/v3/signin/identifier` | the hidden `region` field (`ZZ` = not determined) |
| YouTube | `www.youtube.com/sw.js_data` | service worker data |
| Reddit | `www.reddit.com/api/v1/not-found` | the text of the 404 page; 403 = `ipblock` |
| Deezer | `www.deezer.com/en/offers` | `'country': 'XX'` in the code of the plans page |
| TikTok | `www.tiktok.com/api/v1/web-cookie-privacy/config` | `body.appProps.region` |
| Apple | `gspe1-ssl.ls.apple.com/pep/gcc` | the response body |
| Steam | `HEAD store.steampowered.com` | the `steamCountry` cookie |
| Microsoft | `login.live.com` | `sRequestCountry` in the page |
| Ookla | `www.speedtest.net/api/js/config-sdk` | `location.countryCode` |
| JetBrains | `data.services.jetbrains.com/geo` | `code` |
| PlayStation | `HEAD www.playstation.com` (without following the redirect) | the `country` cookie |

### CDN

| Service | Request | Location |
|---|---|---|
| Cloudflare | the same `cdn-cgi/trace` | `colo=` |
| YouTube | `redirector.googlevideo.com/report_mapping?di=no` | the code from the node name (`yyz10s25` → YYZ) |
| Fastly | `HEAD www.fastly.com/robots.txt` | the last node in the `X-Served-By` header (`cache-fra-…-FRA` → FRA) |

## Tier B — only with `--extended`

These checks call the services' internal APIs with identifiers that the services themselves embed in their official web and mobile clients. All such identifiers are collected in one file — `internal/clientids/clientids.go`. By default the checks are off, and their hosts do not enter the policy or `--plan`. In the report they are marked with `*`, and in JSON with the field `"extended": true`.

| Service | Request | What is used |
|---|---|---|
| Twitch | `POST gql.twitch.tv/gql` | the public `Client-Id` of the Twitch web client, a persisted query |
| ChatGPT | `POST ab.chatgpt.com/v1/initialize` | the Statsig client key from the web client |
| Claude | `GET claude.ai/api/bootstrap` | the User-Agent and the platform header of the Android app |
| Netflix | `GET api.fast.com/netflix/speedtest/v2` | a token from the fast.com page; the same response gives the Netflix CDN node |
| Spotify | `GET spclient.wg.spotify.com/signup/public/v1/account` | the key and `X-Client-Id` of the sign-up page |
| Disney+ | `POST disney.api.edge.bamgrid.com/graph/v1/device/graphql` | the public API key of the Android device |

Risks you accept by enabling the flag:
- such requests most likely go against these services' terms of use, even at one request per run;
- the services change identifiers and internal APIs without notice — then the check returns `unknown` or `error`, and the fix has to be made in `clientids.go`;
- the tier B checks are written after the working ipregion implementation and are covered by tests on recorded responses, but **were not run live in the development environment**: the automatic safety check of that environment forbids such requests.

## Excluded

| What | Why |
|---|---|
| the MaxMind demo token from the demo page, `demo.ip-api.com` | a permanent demo key of the site and a demo endpoint of a paid API (tier C). `ipinfo.io/widget/demo` is not used in the region check; the risk module calls it only with `--extended` (see [RISK_CHECKS.md](RISK_CHECKS.md)) |
| the embedded keys of ipregistry, geoapify, air-port-codes | other people's keys (tier C); ipregistry and geoapify are available with your own keys, the airport reference is built in |
| `speed.cloudflare.com/meta` | answers 403 without a forged `Referer`; the same information is in `cdn-cgi/trace` |
