# cii

[Русская версия](README.md)

**cii — complete information about current IP.** A single static Go binary that puts into one report what usually takes several scripts: where different databases think your IP is, who owns the network, which services are reachable from this point, whether there is censorship or DPI, and how fast the link is.

The main principle is **independence from its authors**. cii only contacts destinations its modules declared in advance. It sends no reports anywhere, keeps no run counters or telemetry, downloads and runs no code, and uses no third-party proxies, keys or accounts. See [docs/NETWORK_POLICY.md](docs/NETWORK_POLICY.md) (in Russian).

> Status: the first release is being prepared. Address detection, IP quality and reputation, region, services with regional catalogs, censorship, benchmarks, the live screen, run comparison and several exits through proxies all work. The plan is in [docs/ROADMAP.md](docs/ROADMAP.md).

The detailed documentation under `docs/` is in Russian; this page covers installation and everyday use.

## Quick start

```bash
make build
```

```bash
./cii data update
```

```bash
./cii
```

The first command builds the binary, the second downloads the DB-IP Lite offline databases straight from DB-IP once, and the third detects your public IPv4/IPv6, describes it with the local databases and asks GeoIP providers and services which country they see you in.

## Installation

Ready binaries for Linux (amd64, arm64, armv7, 386, mips/mipsle softfloat, riscv64), macOS and Windows are on the release page together with `SHA256SUMS`. They are built by GitHub Actions from this repository, and every file carries a provenance attestation you can check without trusting anyone but GitHub.

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

```bash
gh attestation verify cii-linux-amd64 --repo arngory/cii
```

The release also has `deb`, `rpm` and `apk` packages for Linux and ready manifests for package managers: a Homebrew formula (`cii.rb`), a Scoop manifest (`cii.json`) and an AUR `PKGBUILD` (`cii-bin`) to put into your own tap, bucket or AUR package. Nothing needs `curl | bash`.

On routers the binary is about 10 MB, almost all of it the Go runtime, TLS and HTTP; the benchmark and censorship modules add only a few percent, so there is no separate "lite" build. Keep it in `/tmp` (RAM) and run `cii --quick` or `cii --no-censor` when time and traffic matter.

## Commands

| Command | What it does | Network |
|---|---|---|
| `cii` | detects public addresses, describes them with local databases, checks region, service availability, reputation and censorship over DNS and Telegram | only hosts listed by `--plan` |
| `cii --extended` | adds tier-B checks: vendors' internal APIs and keyless risk data from the ipinfo.io, Scamalytics and ip2location.com lookup pages, plus the DPI and geoblock lists | hosts listed by `--plan --extended` |
| `cii --bench` | runs the benchmark with default settings after the checks: disk, CPU, speed, iperf3 (minutes, 1 GiB on disk, iperf3 traffic); combines with `--extended` | plus `speed.cloudflare.com` and iperf3 servers |
| `cii --no-censor` | skips censorship checks | — |
| `cii --proxy URL1,URL2,…` | several exits at once: each proxy is checked on its own (IPv4 address, IP quality, region, services, reputation), shown as a panel per exit and a column of marks per exit. Proxy credentials never reach the report. Censorship and the benchmark are not run in this mode | `--plan` hosts through each proxy |
| `cii --quick` | skips region, service, reputation and censorship checks | echo services only |
| `cii --no-risk` | skips reputation, DNSBL and mail checks | — |
| `cii --plan` | prints every destination cii may contact and exits | none |
| `cii --offline` | takes addresses from local interfaces and looks them up locally | none |
| `cii lookup IP...` | describes the given addresses with local databases, one panel per address | none |
| `cii diff [OLD NEW]` | what changed between two runs: address, verdict, registry country, source opinions, services, risk flags and scores, censorship, speed. Without arguments it compares the last two local logs; it accepts logs and `--json` files; `--json` prints the changes | none |
| `cii data update [ID...]` | downloads databases from their publishers | publishers' hosts only |
| `cii data status` | shows local databases, dates and sha256 | none |
| `cii data sources` | lists supported databases and their licenses | none |
| `cii censor` | censorship only, all modes, full grid: resolvers and DNS spoofing, DPI and geoblocks, Telegram, your own domain lists | resolvers, checked domains, Telegram DCs |
| `cii bench` | benchmark only, with its own options: system info, disk, CPU, Cloudflare speed, iperf3 with cii's own client | `speed.cloudflare.com`, chosen iperf3 servers |

Common flags: `-4`, `-6`, `--iface`, `--source`, `--proxy`, `--timeout`, `--quick`, `--extended`, `--catalog`, `--no-risk`, `--json`, `--debug`, `--no-log`, `--mask`, `--no-color`, `--lang`, `--config`, `--data-dir`.

Screen language: `--lang auto|en|ru`; by default it follows `LC_ALL`/`LC_MESSAGES`/`LANG`. The `--debug` report, JSON and service names stay in English so logs and scripts do not depend on the language.

## Output

In a terminal cii shows a live full-window screen: panels fill in as answers arrive (`◌` means a check is still running), and the header counts finished checks and time. Ctrl+C stops the checks and shows what has arrived. When the run ends the screen closes and the last frame stays in the terminal as plain text. When writing to a file or a pipe, and with `--json` or `--debug`, only the result is printed.

The layout follows the window width: one column below 110 characters, two from 110, three from 200. The example is made up: the address is from the documentation range and the other values only illustrate the format.

```
cii 0.1.0
┌─ IP quality · IPv4 ──────────────────────────────────────┐ ┌─ Region & services ───────────────────────────────────────────────────────────────────┐
│ Address  203.0.113.7                                     │ │ Region  DE Germany · GeoIP 3/3 · platforms 1/2 · ChatGPT* says NL                     │
│ ASN      AS3320 Deutsche Telekom AG                      │ │ CDN     Cloudflare FRA DE · Fastly FRA DE                                             │
│ Place    DE Germany, Frankfurt am Main                   │ │                                                                                       │
│ Route    203.0.112.0/20 · AS3320 DTAG Deutsche Telekom A… │ │ Streaming  ✓ Netflix             ✗ Disney+*                                           │
│ PTR      p203007.dip0.example.net                        │ │            ✓ Prime Video         ✓ YouTube Premium*                                   │
│ Registry DE  ✓ geo-consistent                            │ │ Web        ✓ Reddit              ⊘ Wikipedia editing                                  │
│                                                          │ │ AI         ✓ OpenAI API          ✓ Grok API                                           │
│ Type ─────────────────────────────────────────────────── │ │            ✓ Anthropic API       ? Mistral API                                        │
│                   usage  company                         │ └───────────────────────────────────────────────────────────────────────────────────────┘
│ proxycheck.io    [BIZ ]  —                               │ ┌─ Reputation lists & mail ─────────────────────────────────────────────────────────────┐
│ ipinfo.io*       [ISP ] [ISP ]                           │ │ DNSBL  ✓ bl.spamcop.net                                                               │
│ ip2location.com* [ISP ]  —                               │ │        ✓ psbl.surriel.com                                                             │
│ IPQualityScore   [MOB ]  —                               │ │        ? zen.spamhaus.org refused: public resolver                                    │
│ AbuseIPDB        [ISP ]  —                               │ │ Mail   ✗ Outbound SMTP (25) port 25 filtered                                          │
│                                                          │ └───────────────────────────────────────────────────────────────────────────────────────┘
│ Score ────────────────────────────────────────────────── │ ┌─ Censorship ──────────────────────────────────────────────────────────────────────────┐
│ ipquery.io         0 ■□□□□ very low                      │ │ DNS       ✓ 2                                                                         │
│ proxycheck.io      0 ■□□□□ very low                      │ │ Telegram  ✗ 1                                                                         │
│ Scamalytics*       4 ■■□□□ low                           │ │                                                                                       │
│ ip2location.com*   0 ■□□□□ very low                      │ │ ✗ Telegram: DC2 reset                                                                 │
│ IPQualityScore    62 ■■□□□ low                           │ └───────────────────────────────────────────────────────────────────────────────────────┘
│ AbuseIPDB          0 ■□□□□ very low                      │
│                                                          │
│ Factors ──────────────────────────────────────────────── │
│                   cc proxy   VPN   Tor  host abuse   bot │
│ ipquery.io        DE     ✓     ✓     ✓     ✓     ·     · │
│ ip-api.com        DE     ✓     ·     ·     ✓     ·     · │
│ proxycheck.io     DE     ✓     ✓     ✓     ✓     ·     · │
│ ipinfo.io*        DE     ✓     ✓     ✓     ✓     ·     · │
│ Scamalytics*      DE     ✓     ✓     ✓     ✓     ✓     ✓ │
│ ip2location.com*  DE     ✓     ✓     ✓     ✓     ✓     ✓ │
│ IPQualityScore    NL     ✓     ✗     ✓     ·     ✓     ✓ │
│ AbuseIPDB         DE     ·     ·     ✓     ·     ✓     · │
│ ✓ clean, ✗ detected, · not reported                      │
│                                                          │
│ ✗ IPQualityScore: VPN; fraud score 62                    │
└──────────────────────────────────────────────────────────┘
✓ yes, ✗ no · 50 hosts contacted · * --extended check
```
- **IP quality** (left, after sections 1–4 of IPQuality): address, ASN and place from local databases, `Route` with the announced prefix and origin AS from RIPEstat, `PTR` with the reverse name, and the registry country marked `✓ geo-consistent` or `⚠ geo-discrepant`. Then three sections per source. **Type**: coloured badges for the address and company type — `ISP` and `MOB` green, `BIZ`, `EDU`, `GOV` yellow, `HOST` and `CDN` red. **Score**: a tier list of 0–100 scores with a five-step bar and the level on that source's own scale. **Factors**: the source's country (yellow when it disagrees with the verdict) and proxy, VPN, Tor, hosting, abuser and bot flags — green `✓` clean, red `✗` detected, `·` not reported. Findings and errors of reputation sources follow the table. The profile is built from answers cii already has, with no extra requests.
- **Region & services**: the country verdict on one line (how many sources agree, and only the ones that do not), CDN edges, and services in a grid by section. A country next to a service is shown only when it differs from the verdict. With two stacks each service has two marks, IPv4 first.
- **Reputation lists & mail**: DNSBL, outbound port 25, Tor, cloud and Spamhaus DROP ranges.
- **Censorship**: one line of counts per group (DNS, Telegram; DPI and geoblocks with `--extended`) and up to eight findings; the full grid is in `cii censor`, `--debug` and the log.
- **Benchmark** (with `--bench`): system, disk, CPU, speed and iperf3 as in `cii bench`; the current step shows in the header while it runs.
- Marks: `✓` yes, `✗` no, `◐` partial, `⊘` the service blocks this address, `?` no answer, `!` error, `◌` still running; without UTF-8 they become `+ - ~ x ? ! o` and frames use `+-|`.
- The regional service catalog follows the verdict country (`--catalog auto`); set it by hand with `--catalog JP,EU`, `all` or `none`.

`--debug` prints full tables per source, reasons for failed checks, local database details and the network ledger: every host, request count, purpose, attempts blocked by the policy (`BLOCKED`) and raw connections skipped because of a proxy (`skipped (proxy)`). Every run also writes a local log with the same frame at 160 columns, the detailed report and JSON: `~/.local/state/cii/logs` on Linux, `~/Library/Logs/cii` on macOS, `%LOCALAPPDATA%\cii\logs` on Windows. The file mode is 0600 and the last 20 runs are kept. The log contains your address (unless `--mask` is used) and is never sent anywhere. Disable it with `--no-log`, move it with `CII_LOG_DIR`.

## JSON

`cii --json` prints a report that follows [`schema/report.schema.json`](schema/report.schema.json) (JSON Schema 2020-12; the format version is in the `schema` field). The schema is generated from the report types (`make schema`) and a test keeps the file in step with the code.

## Credits and license

Ideas come from lmc999/RegionRestrictionCheck, xykt/IPQuality, vernette/censorcheck, vernette/ipregion, masonr/yet-another-bench-script and teddysun/across; everything is reimplemented in Go. See [CREDITS.md](CREDITS.md).

[AGPL-3.0](LICENSE).
