# Configuration

[Русская версия](../CONFIG.md)

The config is optional. By default it is looked up at `<config dir>/cii/config.yaml`: on Linux this is `~/.config/cii/config.yaml`; the path can be overridden with `CII_CONFIG_DIR` or `--config`. Data directory: `~/.local/share/cii` on Linux, `~/Library/Application Support/cii` on macOS, `%LOCALAPPDATA%\cii` on Windows; it is overridden with `CII_DATA_DIR` or `--data-dir`.

```yaml
ip_echo:
  - name: my-echo
    url4: https://echo4.example.org/
    url6: https://echo6.example.org/
    format: plain

keys:
  ipinfo_token: ""
  maxmind_account_id: ""
  maxmind_license_key: ""
  ipregistry_key: ""
  geoapify_key: ""
  ip2location_key: ""
  ipapi_is_key: ""
  proxycheck_key: ""
  abuseipdb_key: ""
  ipqs_key: ""
  ipdata_key: ""
  gemini_api_key: ""

data:
  sources: [dbip-country-lite, dbip-asn-lite, ipinfo-lite]

route:
  targets:
    - home=vps.example.org@64500

dns: system

services:
  - name: Shop
    url: https://shop.example.org/
    expect: 200
    contains: "Add to cart"
    blocked: "not available in your country"
    group: Work
```

## `ip_echo`

Replaces the built-in list of echo services (Cloudflare `cdn-cgi/trace`, ipify, icanhazip). The services are queried in parallel. An address is accepted as soon as two services have reported it; if only one answered, its answer is used. If the services reported different addresses, the address with the majority wins, and the others are shown in an "Also seen" line in the IP quality panel and in `disagree[]` in JSON. This makes split routing or load balancing across several exits visible. Response formats:

| `format` | Response |
|---|---|
| `plain` | the response body is the address |
| `trace` | `key=value` lines, the address is in `ip=` |
| `json:field` | a JSON object, the address is in the given field |

To depend on no one, run your own echo service. One line of nginx is enough: `return 200 $remote_addr;`.

## `keys`

Only **your own** keys. The environment variables `CII_IPINFO_TOKEN`, `CII_MAXMIND_ACCOUNT_ID`, `CII_MAXMIND_LICENSE_KEY`, `CII_IPREGISTRY_KEY`, `CII_GEOAPIFY_KEY`, `CII_IP2LOCATION_KEY`, `CII_IPAPI_IS_KEY`, `CII_PROXYCHECK_KEY`, `CII_ABUSEIPDB_KEY`, `CII_IPQS_KEY`, `CII_IPDATA_KEY` and `CII_GEMINI_API_KEY` take precedence over the file. Keys never end up in reports, errors or `manifest.json`.

| Key | Where it is used |
|---|---|
| `ipinfo_token` | downloading IPinfo Lite; requests to ipinfo.io without the anonymous limits |
| `maxmind_account_id`, `maxmind_license_key` | downloading GeoLite2; the GeoLite web service in the region checks |
| `ipregistry_key`, `geoapify_key` | enable the corresponding region checks |
| `ip2location_key` | lifts the daily limit on anonymous requests to ip2location.io |
| `proxycheck_key` | lifts the daily limit on anonymous requests to proxycheck.io |
| `ipapi_is_key`, `abuseipdb_key`, `ipqs_key`, `ipdata_key` | enable the corresponding reputation checks (see [RISK_CHECKS.md](RISK_CHECKS.md)) |
| `gemini_api_key` | enables the Gemini API region check (see [SERVICE_CHECKS.md](SERVICE_CHECKS.md)) |

## `data.sources`

Which databases `cii data update` downloads when no IDs are given on the command line. The default is `dbip-country-lite` and `dbip-asn-lite`. Full list: `cii data sources`.

Any other `.mmdb` placed in the data directory (for example, a commercial database) is used as well: in the report it is labelled with its file name.

## `dns`

Which resolver the checks use to look up names. By default it is the system one (`/etc/resolv.conf` on Linux and macOS, the adapter settings on Windows). The `--dns` flag takes priority; `--dns system` brings back the system resolver even when the config names another.

```yaml
dns: quad9
```

| Value | What it is |
|---|---|
| `quad9` | Quad9: 9.9.9.9, 149.112.112.112, 2620:fe::fe, 2620:fe::9, DNS-over-TLS `dns.quad9.net` |
| `cznic` | CZ.NIC ODVR: 193.17.47.1, 185.43.135.1, 2001:148f:ffff::1, 2001:148f:fffe::1, DNS-over-TLS `odvr.nic.cz` |
| `cloudflare` | Cloudflare: 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001, DNS-over-TLS `cloudflare-dns.com` |
| `google` | Google: 8.8.8.8, 8.8.4.4, 2001:4860:4860::8888, 2001:4860:4860::8844, DNS-over-TLS `dns.google` |
| `adguard` | AdGuard: 94.140.14.14, 94.140.15.15, 2a10:50c0::ad1:ff, 2a10:50c0::ad2:ff, DNS-over-TLS `dns.adguard-dns.com` |
| `192.0.2.53`, `[2001:db8::53]:5353` | plain DNS (UDP, TCP for long answers) to this address; the default port is 53 |
| `tls://192.0.2.53#dns.example` | your own DNS-over-TLS: an address, an optional port (853 by default) and the name in the certificate |

The server is given as an address, not a name: finding a resolver by name would need another resolver. For the presets the IPv4 addresses are tried first, then IPv6 — lookups for the IPv6 checks also go over IPv4 when it works. The DNS-over-TLS certificate is verified against the system root certificates.

Every server address is a network policy rule of the `dns` module: it shows in `--plan`, and every connection to it in the network ledger. The footer of the screen names the resolver the lookups went through. What changes:

- all names of the checks go through the chosen server: echo services, region, services, reputation, DNSBL, routes, the benchmark, `cii data update`, the DPI and geoblock checks;
- the censorship checks that examine the system resolver itself (`System resolver spoofing`, the DNS exit) still ask the system one;
- with a proxy the proxy resolves names, and `--dns` is not used;
- Spamhaus ZEN is not queried when the chosen server is public (all presets are): Spamhaus does not answer public resolvers. ZEN needs your own recursive resolver — give it as an address.

DNS-over-HTTPS is not supported yet.

## `route`

`targets` lists your own targets for `cii route` and `cii --route` as `[name=]host[@asn]`; they are added to the built-in list. Details are in [ROUTE.md](ROUTE.md).

## `services`

Your own availability checks: one `GET` request per address, the result goes to the "Region & services" panel next to the built-in ones. Up to 32 checks. How the response is read is in [SERVICE_CHECKS.md](SERVICE_CHECKS.md#your-own-checks).

| Field | Meaning |
|---|---|
| `url` | required; `https://` or `http://`, without a login and password in the address |
| `name` | the label in the report; by default, the host from `url`. No semicolon, and not the name of a built-in check |
| `expect` | the expected status code or a list: `200`, `[401, 403]`; by default any code below 400 fits |
| `contains` | a string that must be in the response body |
| `blocked` | a string that identifies a refusal: if it is in the body, the result is `no` |
| `group` | the group heading; `Streaming`, `AI` and `Web` add the check to the built-in group, without the field the group is `Custom` |
