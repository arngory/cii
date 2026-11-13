# cii

[Русская версия](README.md)

**cii — complete information about current IP.** One static binary that puts into a single report what usually takes several scripts: where databases and services think your IP is, who owns the network, how clean the address is, which services work from here, whether there is censorship, DPI or DNS tampering, how traffic is routed and how fast the link is.

cii only contacts destinations its modules declare up front (`cii --plan` prints all of them). It sends no reports to anyone, keeps no counters or telemetry, downloads and runs no code, and uses no one else's proxies or keys. See [docs/NETWORK_POLICY.md](docs/en/NETWORK_POLICY.md).

## Run in one line

Linux and macOS (the architecture is picked automatically):

```bash
curl -fsSLo cii "https://github.com/arngory/cii/releases/latest/download/cii-$(uname -s | tr A-Z a-z)-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/;s/armv7l/arm-7/;s/i[3-6]86/386/')" && chmod +x cii && ./cii
```

Windows (PowerShell):

```powershell
iwr https://github.com/arngory/cii/releases/latest/download/cii-windows-amd64.exe -OutFile cii.exe; .\cii.exe
```

This downloads the latest release binary from GitHub into the current directory and runs it. Without arguments cii shows a menu of modes and waits for a number:

```
   1  Standard check        address, IP quality, region, services, reputation, censorship
   2  Extended check        standard + vendors' internal APIs, risk pages, DPI and geoblock lists
   3  Everything            extended + routes + benchmark (minutes, 1 GiB on disk)
   4  Quick                 address and local databases only
   5  Censorship only       DNS, DPI, geoblocking, Telegram, connectivity checks
   6  Routes only           paths to major networks (hops need root)
   7  Benchmark only        system, disk, CPU, speed, iperf3
   8  Show the last run     from the local log, no network
   9  Analyse the last run  conclusions from the local log, no network
  10  Update databases      DB-IP Lite and range lists from their publishers
```

An `m` after the number (`2m`) hides addresses and the provider, for a screenshot. Enter alone runs the standard check, `0` exits.

To pick a mode up front, append the number or flags to the command, for example `./cii 2m` or `./cii --extended --mask`. `./cii ip` runs the standard check without asking. In scripts and pipes (when input or output is not a terminal) there is no menu and the standard check runs.

On a router, run the command from `/tmp` so the binary only lives in memory. For mips/mipsle and other targets, pick the file name from the [release page](https://github.com/arngory/cii/releases/latest).

Local DB-IP databases (country and ASN without asking services, hop labels in `cii route`) are fetched once:

```bash
./cii data update
```

See what the report looks like without a single network request:

```bash
./cii --demo
```

## What it shows

- **IP quality**: address, ASN, place, announced prefix, PTR, registration country. Address type per source (ISP, MOB, BIZ, HOST…), risk scores with levels, and a flag table for proxy, VPN, Tor, hosting, abuser and bot.
- **Region & services**: which country GeoIP databases and platforms (Google, YouTube, Netflix, Cloudflare, Apple, Steam…) see you in, CDN nodes, access to streaming, AI services and sites, and regional catalogues for your country.
- **Reputation lists & mail**: DNSBL, outbound port 25, PeeringDB, Tor and cloud ranges.
- **Censorship**: resolvers over UDP, DoH and DoT, DNS spoofing, port-53 interception, OS connectivity checks (captive portal, rewriting proxy, TLS interception), Telegram, a tunnel on the default route. With `--extended`, DPI and geoblocking lists as well.
- **Routes** (`--route`): paths to Google, Meta, Telegram, CDNs, AI services and DNS: direct, via transit, or a detour.
- **Benchmark** (`--bench`): system, disk, CPU, Cloudflare speed, iperf3.

Example on invented data (`cii --demo --lang en`, 150-column window):

```
┌─ IP quality · IPv4 ──────────────────────────────────────┐ ┌─ Region & services ───────────────────────────────────────────────────────────────────┐
│ Address  203.0.113.7                                     │ │ Region  DE Germany · GeoIP 4/4 · platforms 3/3                                        │
│ ASN      AS3320 Deutsche Telekom AG                      │ │ CDN     Cloudflare FRA DE                                                             │
│ Place    DE Germany                                      │ │                                                                                       │
│ Route    203.0.113.0/24 · AS3320 DTAG                    │ │ Streaming  ✓ Netflix             ✓ Disney+*                                           │
│ PTR      p203-0-113-7.dip0.example.net                   │ │            ✓ Prime Video         ✓ YouTube Premium*                                   │
│ Registry DE  ✓ geo-consistent                            │ │ Web        ✓ Reddit              ✓ Wikipedia editing                                  │
│                                                          │ │ AI         ✓ OpenAI API          ✓ ChatGPT app         ✓ DeepSeek API                 │
│ Type ─────────────────────────────────────────────────── │ │            ✓ Anthropic API       ✓ NotebookLM          ✗ Kimi API (CN)                │
│                 usage  company                           │ └───────────────────────────────────────────────────────────────────────────────────────┘
│ ipquery.io     [ISP ]  —                                 │ ┌─ Reputation lists & mail ─────────────────────────────────────────────────────────────┐
│ ip-api.com     [ISP ]  —                                 │ │ DNSBL    ✓ bl.spamcop.net      ✓ psbl.surriel.com    ✓ dnsbl.dronebl.org              │
│ ip2location.io [ISP ]  —                                 │ │ Mail     ✗ Outbound SMTP (25) connection timed out, port 25 likely filtered           │
│ proxycheck.io  [ISP ]  —                                 │ │ Network  ✓ PeeringDB AS3320 Cable/DSL/ISP                                             │
│                                                          │ │          ✓ Known ranges not in: tor-exits, aws, gcp, oracle, cloudflare               │
│ Score ────────────────────────────────────────────────── │ └───────────────────────────────────────────────────────────────────────────────────────┘
│ ipquery.io       0 ■□□□□ very low                        │ ┌─ Censorship ──────────────────────────────────────────────────────────────────────────┐
│ proxycheck.io    0 ■□□□□ very low                        │ │ DNS       ✓ 3                                                                         │
│                                                          │ │ Telegram  ✓ 2                                                                         │
│ Factors ──────────────────────────────────────────────── │ │ Portal    ✓ 3                                                                         │
│                 cc proxy   VPN   Tor  host abuse   bot   │ └───────────────────────────────────────────────────────────────────────────────────────┘
│ ipquery.io      DE     ✓     ✓     ✓     ✓     ·     ·   │
│ ip-api.com      DE     ✓     ✓     ✓     ✓     ·     ·   │
│ ip2location.io  DE     ✓     ·     ·     ·     ·     ·   │
│ proxycheck.io   DE     ✓     ✓     ✓     ✓     ·     ·   │
│ ✓ clean, ✗ detected, · not reported                      │
└──────────────────────────────────────────────────────────┘
┌─ IP quality · IPv6 ──────────────────────────────────────┐
│ unavailable                                              │
└──────────────────────────────────────────────────────────┘
┌─ Benchmark ──────────────────────────────────────────────┐
│ System  Debian GNU/Linux 13 · linux 6.12.0 · amd64       │
│         2 × Example CPU @ 2.10GHz, AES-NI                │
│         2.0 GiB RAM, 1.0 GiB free · virt kvm · up 3d 0h  │
│         load 0.12 0.00 0.00                              │
│ CPU     single 180 · multi 350 (2 threads)               │
│         sha256 280 MB/s · aes-gcm 1.30 GB/s              │
│         deflate 60 MB/s                                  │
│ Speed   Cloudflare FRA · 4.2 ms · ↓ 930 Mbit/s           │
│         ↑ 610 Mbit/s                                     │
│ iperf3  Example Frankfurt, DE ↑ 880 Mbit/s ↓ 910 Mbit/s  │
└──────────────────────────────────────────────────────────┘
✓ yes, ✗ no · 1 host contacted · * --extended check · details: --debug
```

The layout follows the window width: one column below 110 characters, two from 110, three from 200. While checks run the screen updates in place and `◌` marks a check still in progress; Ctrl+C shows what has arrived.

Marks: `✓` yes, `✗` no, `◐` partial, `⊘` the service blocks this address, `?` no answer, `!` error, `*` an `--extended` check.

## Commands

| Command | What it does |
|---|---|
| `cii` | the full check: address, IP quality, region, services, reputation, censorship (DNS, Telegram, connectivity checks) |
| `cii lookup IP…` | describe given addresses from local databases, no network |
| `cii censor` | censorship only, every mode and the full grid ([docs/CENSOR_CHECKS.md](docs/en/CENSOR_CHECKS.md)) |
| `cii route` | routes only ([docs/ROUTE.md](docs/en/ROUTE.md)) |
| `cii bench` | the benchmark only, with its own options ([docs/BENCH.md](docs/en/BENCH.md)) |
| `cii show [LOG\|JSON\|-]` | print a past run again: the latest local log by default, or a log file, a `--json` file or `-` for standard input. `--mask`, `--json`, `--debug`, `--svg` and `--lang` apply; the title names the file and when the run was taken |
| `cii analyze [LOG\|JSON\|-]` | conclusions from a finished run, checking nothing again: DNS interception and what follows from it, blocking, altered HTTP or TLS, a tunnel, address type and risk flags, blocklists, route detours. The latest log by default; `--mask`, `--json` and `--lang` apply. The `cii` report itself stays as is, without interpretation |
| `cii stats [LOG…]` | which checks did not always answer, across all local logs: this shows a check that broke because the service changed |
| `cii diff [OLD NEW]` | what changed between two runs; without arguments, the last two logs |
| `cii compare A B [C…]` | reports from different machines side by side (two to six logs or JSON files): an IP quality panel per point and one service grid with a mark for each; for two points the list of differences follows. `--mask`, `--json` and `--svg` apply |
| `cii watch` | repeat the check every `--every` (30 minutes by default, no more often than 5) and print what changed: address, verdict, service access, blocking, scores. The first run shows the full report. `--count N` stops after N runs, `--prom-file` refreshes a metrics file. Takes the flags of `cii` (`--extended`, `--route`, `--mask`…); with `--mask` an address change is not visible |
| `cii data update [ID…]` | fetch offline databases from their publishers; `status` shows what is installed, `sources` what is available |
| `cii version` | version |

## Flags

| Flag | Meaning |
|---|---|
| `--extended` | also tier-B checks: vendors' internal APIs, public lookup pages of risk services, DPI and geoblocking lists |
| `--route` | add path analysis |
| `--bench` | add the benchmark (minutes, 1 GiB on disk, iperf3 traffic) |
| `--quick` | address and local databases only, no service checks |
| `--no-censor`, `--no-risk` | skip censorship; skip reputation, DNSBL and mail |
| `-4`, `-6` | IPv4 only or IPv6 only |
| `--proxy URL[,URL…]` | check through a proxy (`http://`, `https://`, `socks5://`); several URLs give several exits side by side |
| `--iface NAME`, `--source ADDR` | leave through this interface or local address |
| `--catalog LIST` | regional service catalogues: `auto` (by country), `all`, `none` or codes like `JP,EU` |
| `--timeout DUR` | per-request timeout, `10s` by default |
| `--offline` | no network: interface addresses and local databases |
| `--plan` | print every destination cii may contact, then exit |
| `--json` | machine-readable output following [`schema/report.schema.json`](schema/report.schema.json) |
| `--debug` | full tables, failure reasons and the log of every connection |
| `--mask` | hide addresses, prefixes, AS numbers and holders, PTR — for screenshots |
| `--svg FILE` | save the final screen as an SVG image |
| `--prom`, `--prom-file FILE` | print the report as Prometheus metrics instead of the screen; write them to a file (for example for the node_exporter textfile collector) |
| `--demo` | show the report on invented data, no network |
| `--lang auto\|en\|ru` | screen language; `--debug` and JSON stay in English |
| `--no-color`, `--no-log` | no colours; no local log |
| `--config FILE`, `--data-dir DIR` | your config (keys, your own echo service) and database directory |

Your own keys (ipinfo, IPQS, AbuseIPDB, Gemini and others) enable extra checks — see [docs/CONFIG.md](docs/en/CONFIG.md). Everything works without them.

**Log.** Every run saves the frame, the detailed report and JSON to a local log: `~/.local/state/cii/logs` on Linux, `~/Library/Logs/cii` on macOS, `%LOCALAPPDATA%\cii\logs` on Windows. Mode 0600, the last 20 runs are kept, nothing is sent anywhere. `cii show` and `cii diff` work from these logs: `cii show --mask`, for example, prints the latest run without addresses or provider even if it ran without `--mask`.

**`--mask`** replaces with `•••` everything that identifies the address or network: addresses and prefixes in any form, AS numbers and holders, PTR, hop addresses, CDN node names (an ISP-hosted cache is often named after the ISP), VPN and datacenter names in answers. Country, city and all check results stay.

## Install and verify

Homebrew (macOS and Linux):

```bash
brew tap arngory/cii https://github.com/arngory/cii
```

```bash
brew install cii
```

Scoop (Windows):

```powershell
scoop bucket add cii https://github.com/arngory/cii; scoop install cii
```

The formula and manifest live in this repository (`Formula/`, `bucket/`) and are updated by the release workflow.

Binaries for Linux (amd64, arm64, armv7, 386, mips/mipsle softfloat, riscv64), macOS and Windows, `deb`, `rpm` and `apk` packages, a Homebrew formula (`cii.rb`), a Scoop manifest (`cii.json`) and an AUR `PKGBUILD` are on the [release page](https://github.com/arngory/cii/releases/latest). Everything is built by GitHub Actions from this repository, and every file carries a provenance attestation:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

```bash
gh attestation verify cii-linux-amd64 --repo arngory/cii
```

From source: `make build` (needs the Go version from `go.mod`).

## Documentation

The user documentation is available in English under `docs/en/`; the developer documents (architecture, development, roadmap) are in Russian.

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — design, modules, report format
- [docs/NETWORK_POLICY.md](docs/en/NETWORK_POLICY.md) — network policy and ToS/FUP rules
- [docs/CONFIG.md](docs/en/CONFIG.md) — configuration and your own keys
- [docs/REGION_CHECKS.md](docs/en/REGION_CHECKS.md), [docs/SERVICE_CHECKS.md](docs/en/SERVICE_CHECKS.md), [docs/catalogs/](docs/catalogs/) — region and services
- [docs/RISK_CHECKS.md](docs/en/RISK_CHECKS.md) — reputation, DNSBL, mail, known ranges
- [docs/CENSOR_CHECKS.md](docs/en/CENSOR_CHECKS.md) — DNS, connectivity checks, DPI, geoblocking, Telegram
- [docs/ROUTE.md](docs/en/ROUTE.md) — routes
- [docs/BENCH.md](docs/en/BENCH.md) — benchmark
- [docs/DATA_SOURCES.md](docs/en/DATA_SOURCES.md) — offline databases and licences
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — build, tests, releases
- [docs/ROADMAP.md](docs/ROADMAP.md) — roadmap
- [CREDITS.md](CREDITS.md) — credits and the origin of ideas

## Licence

[AGPL-3.0](LICENSE). DB-IP data is CC BY 4.0, IPinfo Lite is CC BY-SA 4.0 (see [docs/DATA_SOURCES.md](docs/en/DATA_SOURCES.md)).
