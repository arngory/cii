# Network policy

[Русская версия](../NETWORK_POLICY.md)

## What cii guarantees

1. **Deny by default.** Every module declares in advance the hosts it needs to contact and why (`netx.Rule`). Any other host, including a redirect target, is rejected before the first byte is sent. Rules are bound to the module: module A cannot use module B's hosts.
2. **Network ledger.** Every request — allowed, failed or blocked — is recorded in the `ledger` and printed in the report (`network` in JSON).
3. **`--plan` tells the truth.** It prints exactly the rules the policy works by. The code has no other way to the network: all HTTP and all raw sockets go through `internal/netx`. When a module connects to an address that has already been resolved (TCP measurements and ICMP in `cii route`), netx lets through only an address that it returned itself when resolving that declared name for that module, or an address that is itself declared as a host. A module is not given a raw ICMP socket: it gets a wrapper that sends packets only to such addresses.
4. **`--offline` sends nothing.** The policy stays empty, addresses are taken from the interfaces, lookups use the local databases.
5. **No sending of results.** There is no "share the report" feature, no run counters, no telemetry, no auto-update, no upload of debug logs.
6. **No remote code.** cii downloads nothing for execution: no scripts, no binaries, no "ad blocks".
7. **Data comes only from the original source.** `cii data update` downloads databases directly from the publishers (DB-IP, IPinfo, MaxMind), not from servers of the cii authors. It runs only when invoked explicitly.
8. **The proxy is not bypassed.** All HTTP goes through the proxy if one is set with the `--proxy` flag or the environment variables `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` (honouring `NO_PROXY`). In both cases raw connections and DNS queries (DNSBL, the SMTP probe, iperf3, censorship checks, the ICMP and TCP measurements of `cii route`) are forbidden and shown as "unknown" with the reason: otherwise they would go past the proxy and reveal the real address. The decision "the proxy is in effect" is made once at startup and is the same for all modules.
9. **Secrets do not leak.** Tokens are stripped from URLs in errors, logs and `manifest.json`.

cii accepts incoming connections in one case: `cii watch --listen HOST:PORT` opens an HTTP `/metrics` address on the address you give and serves only the metrics of the latest run there. Without this flag cii listens on nothing.

An unavoidable caveat: the availability of a service can only be checked by sending a request to it. So the check targets and the echo services see your IP — just as on an ordinary visit with a browser. The list of echo services can be replaced with your own, see [CONFIG.md](CONFIG.md).

## Check admissibility tiers (ToS/FUP)

| Tier | What it is | Mode |
|---|---|---|
| **A** | An anonymous request to a public page or endpoint; parsing of the response code, the redirect and the region in the response | by default |
| **B** | Internal APIs with public client IDs that the service itself embeds in its web or mobile client, together with that client's headers (including the `Origin`/`Referer` of the site of the same service whose API the request goes to); address lookup pages of risk services: the demo widget `ipinfo.io/widget/demo/{ip}`, the page `scamalytics.com/ip/{ip}` and the ip2location.com home page in the form in which a site visitor receives them, including the one-time token that the page issues to the visitor for their own address (a decision of the project owner, details in [RISK_CHECKS.md](RISK_CHECKS.md)) | only with `--extended` |
| **C** | Other people's accounts, other people's API keys, permanent demo keys and demo tokens from pages (valid for any address), the `Origin`/`Referer` of someone else's site, and also demo endpoints through which a service shows data from its paid API (except the three risk pages explicitly listed in tier B), bypassing CAPTCHA and anti-bot protection, closed-source binaries, remote code execution | never |

How tier B works:

- the check is marked as tier B in the catalogue; without `--extended` it is not selected, its hosts do not enter the policy, and the network layer does not let requests through to them even if the code has a bug;
- `cii --plan --extended` shows which hosts will be added, without sending anything;
- all third-party identifiers live in one file, `internal/clientids/clientids.go`, so that they are easy to review or replace;
- results are marked with `*` in text and `"extended": true` in JSON;
- a refusal, or a change of API or key on the service side, turns into `unknown`/`error`, not into a false "available".

Additional rules:

- **Rate.** One request per check per run, bounded concurrency, `429` and `Retry-After` are honoured, no retry storms.
- **User-Agent.** Honest by default: `cii/<version> (+https://github.com/arngory/cii)`. A module can request a browser UA only explicitly and with a stated reason: some sites answer a non-browser differently, and a check without it gives a false result.
- **Paid risk databases** (IPQS, AbuseIPDB, Scamalytics, ipdata and the like): their APIs are called only with **your** key from the config; without a key such a check is disabled. The tier B exception (`--extended`) is the publicly available lookup pages of ipinfo.io, Scamalytics and ip2location.com, as a visitor sees them; pages behind a CAPTCHA or a Cloudflare check, and demos that work through the site's key, are not used.
- **DNSBL.** Queried only through your own or a local resolver. Stub answers `127.255.255.x` (query through a public resolver, limit exceeded) count as "unavailable", not "clean". Only lists that allow free access are used.
- **Benchmarks** do not call anything that sends results on its own (Geekbench is excluded). cii does not accept the licences of third-party programs (for example, Ookla) on the user's behalf.

This is an engineering policy, not a legal guarantee: the terms of particular services change, and responsibility for the frequency and purpose of runs remains with the user.
