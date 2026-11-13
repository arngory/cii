# Routes: `cii route`

[Русская версия](../ROUTE.md)

The module shows how traffic reaches the major networks: directly, via peering, via transit or with a detour. The idea and the thresholds come from [remnawave/geocheck](https://github.com/remnawave/geocheck); the implementation is cii's own.

```
cii route              # routes only
cii route --tcp        # no ICMP: TCP connect time only
cii --route            # routes together with the main report
```

Flags: `--tcp` — do not trace with ICMP; `--rounds N` — the number of ICMP rounds (1–15, default 3); `--max-hops N` — the maximum number of hops (1–31, default 24). The common flags `-4`/`-6`, `--iface`, `--source`, `--timeout`, `--json`, `--debug`, `--mask`, `--plan`, `--svg` work.

## Targets

| Group | Targets and expected AS |
|---|---|
| Google | Google, YouTube (AS15169) |
| Social | Facebook, Instagram, WhatsApp (AS32934), X (AS13414) |
| Messaging | Telegram DC2 and DC4 (AS62041), Discord (AS13335) |
| CDN | Cloudflare (AS13335), Fastly (AS54113), Akamai, Amazon CloudFront (AS16509) |
| AI | OpenAI API (AS13335), Claude |
| Dev | GitHub (AS36459) |
| DNS | 1.1.1.1 (AS13335), 8.8.8.8 (AS15169), 9.9.9.9 (AS19281) |

All hosts are declared in the policy of the `route` module (`cii route --plan`). Names are resolved by the system resolver through netx.

**Your own targets.** `--targets LIST` replaces the built-in list, and with a leading plus (`--targets +…`) extends it. An entry is `[name=]host[@asn]`, comma-separated: `cii route --targets +home=vps.example.org@64500,192.0.2.9`. The host is a name or an IP address, `@asn` is the expected AS (optional). The same can go into the config, and then the targets are added to `cii --route` as well:

```yaml
route:
  targets:
    - home=vps.example.org@64500
```

Own targets go into the `Custom` group and count as single-location targets. There can be at most 64 targets in total. With `--mask` the host of an own target is hidden both in the report and in the network ledger; a name you gave yourself stays, and a target without a name is called `target N`.

## How it is measured

**ICMP.** If raw socket privileges are available (root or `CAP_NET_RAW`), cii sends echo requests with all TTLs from 1 to `--max-hops` at once to all targets, in several rounds. "TTL exceeded" replies give the hops, the echo reply gives the distance to the target. For each hop the minimum time across the rounds is taken. Sending to a target stops at the TTL at which it replied.

**TCP.** Targets that did not answer ICMP (many CDNs stay silent), and all targets when there are no raw socket privileges, are measured by the time of a TCP connection to port 443: four attempts with a 50 ms pause, the minimum is taken. There are no hops in this case.

**IPv6.** With `-6` tracing runs over ICMPv6 in the same way. Targets given as IPv4 addresses (resolvers, Telegram) have their IPv6 addresses recorded for this.

The ASNs of the hops and of the target are taken from the local DB-IP ASN Lite database (`cii data update`). cii does not go to the network for this. Without the database the hops are not labelled, and transit is not detected. Your own AS is taken from the main report, and in `cii route` — from the first public hop.

With a proxy (`--proxy` or environment variables) the ICMP and TCP measurements are not run: they would go past the proxy.

## Verdicts

The "fastest path" is the minimum latency among the targets, or, if four or more answered, the second fastest, so that a single outlier does not shift the scale. The excess is counted from it.

| Verdict | Icon | Condition |
|---|---|---|
| `direct` | ✓ | an excess of no more than 5 ms |
| `near` | ✓ | an excess of up to 25 ms |
| `distant` | ✓ | a target with a single location (Telegram DC, GitHub) further than 25 ms: this is distance, not a route problem. For such targets the `regional` and `detour` verdicts are not given, and latency jumps are not taken into account |
| `regional` | ◐ | an excess of up to 60 ms |
| `transit` | ◐ | on the path to the target's network there is a transit AS from the list (Cogent, Arelion, Lumen, GTT, NTT, Tata, Hurricane Electric, RETN, TransTelecom and others), which is neither yours nor the target's network |
| `detour` | ✗ | an excess of more than 60 ms, or one segment of the path adds more than 40 ms |
| `intercepted` | ✗ | an ICMP reply faster than 1 ms with no intermediate hops; or six or more targets from four or more different networks answered faster than 2 ms while the trace showed no real hops (three or more different addresses on the path) — in that case the connections are terminated by a local proxy, a tunnel or a sandbox. In a well-connected data centre all CDNs answer within 1 ms, but the hops are visible, and this rule does not fire |
| `unreachable` | ! | neither ICMP nor TCP gave an answer |
| `absent` | ? | the service has no address of the required IP version: for example, with `-6`, GitHub, X and Discord, which publish no AAAA records. This is a property of the service, not a network problem |

**Hop latencies.** Routers answer an expired TTL more slowly than they forward traffic, and they rate-limit such replies. So a hop may show 20 ms, and the one after it 1 ms. To keep this from looking like a detour, the jump is computed from the "effective" latency: for each hop the minimum of its own time and the times of all the following hops and of the target itself is taken. Probes are sent with a 0.5 ms pause, target by target: first all TTLs to one target, then to the next, and the order of targets shifts in each round. This way the same router receives a probe once every few milliseconds, not a burst at once, and stays silent less often because of ICMP rate limiting (which is mandatory for IPv6). A hop that answered in no round is shown as an asterisk; this does not affect the verdict.

If the reply came from a different AS than expected (for example, Google from a cache at the provider), the explanation says "served from ASn …". If that AS is your own, it says "served from a cache inside your network": this is a good sign, not a problem.

`--debug` prints, for each target, the address, the AS, the measurement method and the list of hops with latencies and ASes. In JSON — the `route` object with the fields `method`, `floor_ms`, `own_asn`, `note` and `paths[]` (`target`, `addr`, `asn`, `org`, `rtt_ms`, `timing`, `hops[]`, `transit[]`, `jump_ms`, `verdict`, `reason`). With `--mask` the addresses of the hops and of the target, the AS numbers and the organisation names are hidden.
