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

## `route`

`targets` lists your own targets for `cii route` and `cii --route` as `[name=]host[@asn]`; they are added to the built-in list. Details are in [ROUTE.md](ROUTE.md).
