# Address reputation, DNSBL and mail

[Русская версия](../RISK_CHECKS.md)

The `risk` module answers the question "what does this address look like from the outside": whether it is considered a VPN, a proxy or a data centre, whether it is on mail blocklists, whether outbound port 25 is open, whether it falls within known Tor and cloud ranges. The ideas come from [xykt/IPQuality](https://github.com/xykt/IPQuality) and its DNSBL list; unlike the original, nothing goes through the author's servers, and the paid databases work only with your keys. It is disabled with the `--no-risk` flag; in `--offline` mode only the offline part remains.

Statuses: `yes` — clean, `no` — there are flags or the address is listed, `partial` — the address is in a cloud or CDN range (this is not bad, but for many services such an address is a "server" one), `?` — the source is unavailable or gave no substantive answer, `!` — error.

## Reputation (the Reputation group)

| Service | Key | Request | How it is read |
|---|---|---|---|
| proxycheck.io | not needed; `proxycheck_key` lifts the daily limit | `GET proxycheck.io/v3/{ip}?tag=0` (API v3; `tag=0` — the request is not saved in the account history) | `detections`: VPN, Tor, proxy, `compromised` or `risk ≥ 67` → `no`; details: the VPN operator (`operator.name`), network type, risk and the detection period `first_seen…last_seen`; the hosting flag comes from `detections.hosting` |
| ipapi.is | `ipapi_is_key` is **required**: without a key the API returns only geo, without flags | `GET api.ipapi.is/?q={ip}` | `is_vpn`, `is_proxy`, `is_tor`, `is_abuser` → `no`; notes: data centre, company type |
| AbuseIPDB | `abuseipdb_key` is **required** | `GET api.abuseipdb.com/api/v2/check` (the key is in the `Key` header) | `isTor` or `abuseConfidenceScore ≥ 25` → `no`; notes: the number of reports in 90 days, usage type |
| IPQualityScore | `ipqs_key` is **required** | `GET ipqualityscore.com/api/json/ip/<key>/{ip}` | VPN, Tor, proxy, `recent_abuse`, `bot_status`, `fraud_score ≥ 75` → `no` |
| ipdata | `ipdata_key` is **required** | `GET api.ipdata.co/{ip}?fields=…&api-key=` | `threat.*`: Tor, proxy, known attacker/abuser → `no`; notes: data centre, iCloud Private Relay, blocklists |

The IPQS key sits in the request path, not in the query string; to keep it out of the network ledger and errors, cii does not print the URL of this request in full. The other keys are stripped by the standard `StripSecrets`.

## Tier B: service pages without a key (`--extended`)

An experimental mode for those who have no keys. cii takes the data the same way a site visitor sees it: one request per service per run, an honest User-Agent, no CAPTCHA bypass and no one else's keys. These are not public APIs: the sites' terms are usually not meant for automated requests, and the format may change without notice. In that case the check shows `?` or `!`, and the other results are not affected. The checks are marked with `*`, like the rest of tier B.

| Service | Request | What is taken |
|---|---|---|
| ipinfo.io | `GET ipinfo.io/widget/demo/{ip}` — the JSON of the demo widget from the site | the `privacy` flags (VPN, proxy, Tor, hosting, relay), ASN type and company type, mobile network |
| Scamalytics | `GET scamalytics.com/ip/{ip}` — the address lookup page (HTML) | Fraud Score and risk level, the lines VPN, Tor, Server, Public/Web/Residential Proxy, Search Engine Robot, external lists (Firehol, IP2ProxyLite, IPsum, Spamhaus, X4Bnet) |
| ip2location.com | `GET www.ip2location.com/`, then `POST api.ip2location.io/query/` | the home page shows the visitor their own address: cii takes the page's one-time token from it and queries the same way the page's script does (without the `Origin` and `Referer` headers: the service answers without them too), only for the address being checked (if the page shows a different one, the check gives `?`). Usage Type, Fraud Score, Is Proxy and the proxy type (VPN, TOR, DCH — data centre, SES — search engine robot, the rest — proxy), Security Threat. The path has been verified only against the page markup, not by a run against the site; if the service does not accept a request without browser headers, the check gives `?` |

Not included: AbuseIPDB and DB-IP (the pages are behind a Cloudflare check), IPQualityScore (the lookup page is behind a CAPTCHA), ipdata and ipregistry (the demo on the sites works through a key embedded in the page — that is someone else's key).

## Address profile

Sections 1–4 of the IPQuality report (country of registration and whether it matches the geolocation, address type, risk scores, risk factors) are assembled by cii from responses it receives anyway: those of the GeoIP providers from the `region` module and of the reputation sources above. The profile makes no separate requests.

| Source | Key | Type | Score | Flags |
|---|---|---|---|---|
| RDAP (RIR) | — | — | — | country of registration |
| ipquery.io | — | mobile network | `risk_score` | proxy, VPN, Tor, hosting |
| ip2location.io | optional | — | — | proxy |
| ip-api.com | — | mobile network | — | proxy, hosting |
| proxycheck.io | optional | the type from the response (Residential, Business, Wireless, Hosting) | `risk` | proxy, VPN, Tor, hosting |
| ipapi.is | required | `asn.type`, company type | `abuser_score` × 100 | proxy, VPN, Tor, hosting, abuser, bot |
| AbuseIPDB | required | `usageType` | `abuseConfidenceScore` | Tor, abuser (score ≥ 25) |
| IPQualityScore | required | `connection_type` | `fraud_score` | proxy, VPN, Tor, abuser (`recent_abuse`), bot |
| ipdata | required | `asn.type` | `threat_score`, if present in the response | proxy, VPN (if present in the response), Tor, hosting, abuser |
| ipregistry.co | required | connection type, company type | — | proxy, VPN, Tor, cloud, abuser |
| ipinfo.io (tier B) | — | ASN type and company type, mobile network | — | proxy, VPN, Tor, hosting |
| Scamalytics (tier B) | — | connection type | Fraud Score | proxy, VPN, Tor, hosting, abuser (external lists), bot |
| ip2location.com (tier B) | — | Usage Type | Fraud Score | proxy, VPN, Tor, hosting, bot, abuser (Security Threat) |

The types are reduced to one set: ISP, mobile, hosting, business, education, government, CDN. The scores range from 0 to 100; the higher, the worse. The level (very low … very high) is specific to each database: where the database names it itself, its name is used (Scamalytics: `risk`, ipapi.is: the label in `abuser_score`); where it publishes thresholds, its thresholds are used (proxycheck.io: 34 and 67; IPQualityScore: 75 "suspicious", 85 "high", 90; AbuseIPDB: 25, 75, 100); for the rest, the common scale 10/25/50/75 is used. That is why IPQS 62 is low, while proxycheck 62 is medium. A flag is credited to a source only if the source actually reported on it: "proxy 1/4" means that four sources gave an opinion on proxy and one of them found it.

The country of registration is taken from RDAP and is not part of the country verdict. If it matches the verdict, the address is marked `geo-consistent`, otherwise `geo-discrepant` (in IPQuality — "原生IP" and "广播IP"): this is what addresses usually look like when they are registered in one country but announced and used in another.

On screen the profile occupies the left panel, "IP quality": the address, ASN and location, the country of registration with its mark, and three sections by source — **Type** (coloured labels ISP, MOB, BIZ, EDU, GOV, HOST, CDN for the address type and the company type), **Score** (the score, a bar of five segments and the level on that database's scale) and **Factors** (the country according to the source, and the flags). Below the table only those reputation sources remain that found something, gave no substantive answer or returned an error; clean answers are already counted in the table. The table for each source is in `--debug` ("IP profile"); in JSON it is the `profile` field of the address and `facts` of each check.

Without keys the profile is built from ipquery.io, ip2location.io, ip-api.com, proxycheck.io and RDAP: the country of registration, the address type from proxycheck.io (and "mobile" from ipquery.io and ip-api.com), two scores and the proxy, VPN, Tor and hosting flags. The company type and the abuser and bot flags come only from sources with keys.

## DNSBL

Queries go through the system resolver (`netx.LookupHost`), each zone is a single lookup of `reversed-ip.<zone>`; IPv6 is in nibble format for the zones that support it. Concurrency is limited to eight. The list of zones is short and consists only of those whose terms allow free queries:

| Zone | What it catches | Specifics |
|---|---|---|
| `zen.spamhaus.org` | SBL, CSS, XBL, PBL | **not queried through public resolvers** (8.8.8.8, 1.1.1.1, 9.9.9.9 and the like — Spamhaus answers such queries with the stub `127.255.255.x` and treats them as a violation). cii reads `/etc/resolv.conf`; if the resolver is public, the zone is marked `?` with an explanation |
| `bl.spamcop.net` | SpamCop user reports | |
| `psbl.surriel.com` | PSBL | |
| `bl.mailspike.net` | Mailspike reputation | the codes `127.0.0.10–14` are reputation levels and are not counted as a listing |
| `dnsbl.dronebl.org` | bots, proxies, compromised hosts | the details spell out the type (`SOCKS proxy`, `botnet`, …) |
| `dnsbl-1.uceprotect.net` | UCEPROTECT level 1 | |
| `all.s5h.net` | s5h.net | |

The answer `NXDOMAIN` means "not listed" (`yes`), `127.0.0.2+` means "listed" (`no`) with the code decoded, `127.255.255.x` is a refusal by the operator (`?`, never "clean"), a timeout is `!`. The large IPQuality list (400+ zones) is deliberately not ported: most of those zones are dead, some have paid terms, and mass querying violates the FUP.

## Reverse DNS (the Network group)

`Reverse DNS`: the PTR record of the address being checked, via the system resolver (`netx.LookupAddr`, the rules `*.in-addr.arpa` and `*.ip6.arpa`; only the pattern goes into the network ledger, not the address). The host name is shown in the `PTR` line of the "IP quality" panel: it often reveals the address type (`dsl-…`, `pool-…`, `static-…`, cloud names). No record — `?` "no PTR record". With `--mask` the name is hidden entirely, because the address itself is often written in it. With a proxy the query is not made.

## Mail (the Mail group)

`Outbound SMTP (25)`: a TCP connection to `gmail-smtp-in.l.google.com:25` (the target is configurable), reading the banner, `QUIT`. A `220` banner → `yes`; a refusal, a reset or a timeout → `no` with the reason. This answers the question "can this host send mail directly", and nothing more.

## Known ranges (the Network group, offline)

The data is downloaded only by the `cii data update` command (by default together with the DB-IP databases) and only from the original sources; during a check cii does not go to the network for it. The storage format is `data/risk/<id>.txt`: one `CIDR<TAB>label` entry per line, plus a `manifest.json` with the date, size, sha256 and number of prefixes. Identifiers for `cii data update`: `risk:tor-exits`, `risk:aws`, `risk:gcp`, `risk:oracle`, `risk:cloudflare`, `risk:digitalocean`, `risk:spamhaus-drop`, `risk:peeringdb`. PeeringDB has a different format: a line is `AS<number><TAB>network types`.

| Source | What | Licence/terms |
|---|---|---|
| `check.torproject.org/torbulkexitlist` | Tor exit nodes | public data of the Tor Project |
| `ip-ranges.amazonaws.com/ip-ranges.json` | AWS by service and region | published by AWS for allow-lists |
| `www.gstatic.com/ipranges/cloud.json` | Google Cloud by region | published by Google |
| `docs.oracle.com/…/public_ip_ranges.json` | Oracle Cloud | published by Oracle |
| `www.cloudflare.com/ips-v4`, `ips-v6` | Cloudflare | published by Cloudflare |
| `www.digitalocean.com/geo/google.csv` | DigitalOcean (RFC 8805 geofeed) | published by DigitalOcean |
| `www.spamhaus.org/drop/drop_v4.json`, `drop_v6.json` | Spamhaus DROP: networks that were hijacked or handed over to spam or cybercrime | free under the Spamhaus DROP terms |
| `www.peeringdb.com/api/net?fields=asn,info_types` | network type by ASN (Cable/DSL/ISP, NSP, Content, Enterprise, Educational/Research, Government…) | PeeringDB rules: for your own purposes (diagnostics, network research), the data may not be passed on to others in bulk — so cii only downloads it at your command and does not embed it in builds |

A hit in Tor or Spamhaus DROP → `no`, in a cloud or CDN → `partial` with a label (for example, `AWS EC2 eu-central-1`), otherwise `yes`. Only the lists that are present in `manifest.json` and whose files are in place are checked; in a clean result they are listed ("not in: tor-exits, aws, …"). If no list has been downloaded, the line is not shown.

PeeringDB works differently: the network type is looked up by the address's ASN from a local database (DB-IP ASN or IPinfo Lite), and it appears as the `PeeringDB` line in the Type section of the "IP quality" panel (Cable/DSL/ISP and NSP → ISP, Content and Network Services → HOST, Enterprise and Non-Profit → BIZ, Educational/Research → EDU, Government → GOV). This is the only address type that cii knows without the network and without keys. If the line cannot be computed, it is still printed, with a `?` sign and the reason: the list has not been downloaded (`cii data update risk:peeringdb`), the ASN is unknown (there is no DB-IP ASN database) or this AS is not registered in PeeringDB — which is the case for many residential providers. The `Known ranges` line likewise lists the lists that have not been downloaded. FireHOL is not included: its sets are assembled from lists with different, in places incompatible, terms; the most useful of them in substance, Spamhaus DROP, is taken directly from Spamhaus.

## Proxy

With `--proxy`, DNS queries and direct TCP connections are forbidden (they would reveal the real address), so DNSBL and SMTP give `?` with the reason; the HTTP reputation checks work through the proxy as usual.
