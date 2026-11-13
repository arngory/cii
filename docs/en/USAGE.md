# Usage

[Русская версия](../USAGE.md)

## Menu

`cii` without arguments in a terminal shows the modes and waits for a number:

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

An `m` after the number (`2m`) hides addresses and the provider. Enter alone runs the standard check, `0` exits. The number can be given as an argument right away: `cii 2m`. `cii ip` runs the standard check without the menu. When input or output is not a terminal (a script, a pipe), there is no menu and the standard check runs. In a terminal narrower than about 100 columns the menu is shown without hints, as titles only.

## Commands

| Command | What it does |
|---|---|
| `cii` | the full check: address, IP quality, region, services, reputation, censorship (DNS, Telegram, connectivity checks) |
| `cii lookup IP…` | describe given addresses from local databases, no network |
| `cii censor` | censorship only, every mode and the full grid ([CENSOR_CHECKS.md](CENSOR_CHECKS.md)) |
| `cii route` | routes only; `--targets` sets your own targets, `-6` traces over IPv6 ([ROUTE.md](ROUTE.md)) |
| `cii bench` | the benchmark only, with its own options ([BENCH.md](BENCH.md)) |
| `cii show [LOG\|JSON\|-]` | print a past run again: the latest local log by default, or a log file, a `--json` file or `-` for standard input. `--mask`, `--json`, `--debug`, `--svg` and `--lang` apply; the title names the file and when the run was taken |
| `cii analyze [LOG\|JSON\|-]` | conclusions from a finished run, checking nothing again: DNS interception and what follows from it, a DNS exit in another country (a leak), blocking, altered HTTP or TLS, a tunnel, address type and risk flags, blocklists, route detours. The latest log by default; `--mask`, `--json` and `--lang` apply. The `cii` report itself stays as is, without interpretation |
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
| `--json` | machine-readable output following [`schema/report.schema.json`](../../schema/report.schema.json) |
| `--debug` | full tables, failure reasons and the log of every connection |
| `--mask` | hide addresses, prefixes, AS numbers and holders, PTR — for screenshots |
| `--svg FILE` | save the final screen as an SVG image |
| `--prom`, `--prom-file FILE` | print the report as Prometheus metrics instead of the screen; write them to a file (for example for the node_exporter textfile collector) |
| `--demo` | show the report on invented data, no network |
| `--lang auto\|en\|ru` | screen language; `--debug` and JSON stay in English |
| `--no-color`, `--no-log` | no colours; no local log |
| `--config FILE`, `--data-dir DIR` | your config (keys, your own echo service) and database directory |

Your own keys (ipinfo, IPQS, AbuseIPDB, Gemini and others) enable extra checks — see [CONFIG.md](CONFIG.md). Everything works without them.

## Screen

The layout follows the window width: one column below 110 characters, two from 110, three from 200. It is designed for terminals from 50 columns and 24 rows (a 500×500 or 640×480 window): tables narrow down and long lines wrap. While checks run the screen updates in place and `◌` marks a check still in progress. If the frame is taller than the window, the bottom line says how many lines are hidden, and the full report is printed at the end. Ctrl+C shows what has arrived.

Marks: `✓` yes, `✗` no, `◐` partial, `⊘` the service blocks this address, `?` no answer, `!` error, `*` an `--extended` check.

## Log and `--mask`

Every run saves the frame, the detailed report and JSON to a local log: `~/.local/state/cii/logs` on Linux, `~/Library/Logs/cii` on macOS, `%LOCALAPPDATA%\cii\logs` on Windows. Mode 0600, the last 20 runs are kept, nothing is sent anywhere. `cii show`, `cii analyze`, `cii stats` and `cii diff` work from these logs.

`--mask` replaces with `•••` everything that identifies the address or network: addresses and prefixes in any form, AS numbers and holders, PTR, hop addresses, CDN node names, the names of VPNs, data centres and transit networks, the hosts of your own route targets and of your own service checks. Country, city and all check results stay. `cii show --mask` also masks a past run that was taken without `--mask`.
