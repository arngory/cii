# Censorship checks: `cii censor`

[Русская версия](../CENSOR_CHECKS.md)

A port of [vernette/censorcheck](https://github.com/vernette/censorcheck) (MIT) to Go inside cii's common network policy. The module answers not the question "where is my address" but "what is being blocked from this vantage point". A normal `cii` run checks the `dns`, `telegram` and `portal` modes (seconds), `cii --extended` adds `dpi` and `geoblock`, `--no-censor` and `--quick` disable the checks; on screen this is the "Censorship" panel with counters and findings. `cii censor` is censorship only, with all modes, the full grid and custom lists. `--plan` shows all addresses that the checks may contact.

```bash
cii censor
```

```bash
cii censor --mode dns,telegram
```

```bash
cii censor --domains my-list.txt --protocol https
```

Modes (`--mode`, comma-separated, default `all`): `dns`, `dpi`, `geoblock`, `telegram` (`tg`), `portal`, `transport`. In the main `cii` run without `--extended`, `dns`, `telegram`, `portal` and `transport` are run; with `--extended` — all of them. The `--domains FILE` and `--domain HOST` flags replace the built-in lists with your own; `--protocol` is `http`, `https` or `both` (any other value is an error); `--retries N` is the number of extra attempts per target (default 0: one attempt). The common cii flags (`-4`/`-6`, `--iface`, `--source`, `--timeout`, `--json`, `--debug`, `--mask`) work as usual.

## DNS

For each of the 12 resolvers (Cloudflare, Google, Quad9, AdGuard, NextDNS, Yandex — two addresses each), `rutracker.org` is queried over three transports. Each resolver has an IPv4 and an IPv6 address; with `-6` the latter are used and the AAAA record is queried. For Telegram with `-6`, the IPv6 addresses of the data centres are used (one per DC):

| Transport | How | Statuses |
|---|---|---|
| UDP/53 | cii's own DNS packet via `netx.Dial("udp")`, the response ID is checked against the query | response received → `yes`; timeout/refusal → `no` |
| DoH | `POST https://…/dns-query` with `application/dns-message` via `netx.HTTPClient` | an address in the response → `yes`; HTTP error or empty response → `?`; unreachable → `no` |
| DoT | TLS on 853 with the certificate verified against the system roots | as DoH; an invalid certificate → `?` with a detail |

**DNS spoofing.** The first available DoH (or DoT) becomes the reference. For the domains `rutracker.org`, `linkedin.com`, `flibusta.is` the reference answer is compared with the answers of the same 12 resolvers over plain UDP: a match of at least one address — `clean`; `NXDOMAIN` or addresses with no overlap — `spoofed`; a private/local address in the answer is marked as "bogus". As in censorcheck, the check stops at the first domain where spoofing is found and gives the result in a separate "DNS hijacking" line. Without an available DoH/DoT the result is `?`.

Lines in the output: `Name IP` (UDP), `Name IP DoH`, `Name IP DoT`, then `DNS hijacking` and one line per resolver with the result of the comparison.

**Port 53 interception.** The comparison with DoH catches only forged answers. It does not see transparent redirection of port 53 to someone else's resolver that answers correctly. For that there are two separate checks (the idea comes from [remnawave/geocheck](https://github.com/remnawave/geocheck)):

- `Port 53 interception (OpenDNS)` — a TXT query for `which.opendns.com` to 208.67.222.222 (over IPv6 — 2620:119:35::35). A genuine OpenDNS resolver answers with the name of its server. Any other resolver gets the record from the authoritative servers, and that record says "I am not an OpenDNS resolver". Such an answer means that the query was intercepted on the way: `✗`.
- `Port 53 interception (Google)` — a CHAOS-class query for `id.server` to 8.8.8.8 (over IPv6 — 2001:4860:4860::8888). Google does not support such queries. Any TXT answer did not come from Google: `✗`.

No answer or a timeout — `?`: unreachability is not yet interception. With a proxy neither check is run, like all plain DNS.

**DNS exit.** Which resolver your queries really leave to the internet through: the address in the system settings (the router, 127.0.0.53) does not show that. The system resolver is asked for two names whose authoritative servers answer with the address of whoever asked them:

- `Resolver exit (Akamai)` — the A record of `whoami.akamai.net`;
- `Resolver exit (Google)` — the TXT record of `o-o.myaddr.l.google.com`; if the resolver passes the client subnet on (EDNS Client Subnet), Google returns it too, and "ECS" appears in the reason.

The country and network of the address found come from the local databases, without asking services. On screen this is the "DNS exit" line in the censorship panel; details are in `--debug`. The report itself gives no judgement; `cii analyze` notes when the resolver is in a different country from the address: behind a VPN or proxy this is a DNS leak, without one it is just a resolver abroad. An address from 198.18.0.0/15 means a local fake-IP resolver answered: `?`. With a proxy the check is not run: the proxy resolves names. `--mask` hides the resolver's address and network; the country stays.

## Local

Two checks that make no network requests. They show that the results of the other checks describe something other than a direct connection:

- `Default route` — the interface through which the kernel would send traffic to the internet. To find this out, a UDP socket is created to the documentation address 192.0.2.1 (2001:db8::1 for IPv6): no packets leave in the process. A point-to-point interface or a name `tun*`, `utun*`, `tap*`, `ppp*`, `wg*`, `ipsec*`, `gpd*`, `nordlynx*`, `tailscale*`, `zt*` — `partial`: traffic goes through a tunnel, and the results describe its exit. If `--source` or `--iface` is set, the line is called `Source interface` and checks the interface of that address. With a proxy — `?`: the path starts at the proxy, not at this machine.
- `System resolver` — the `nameserver` addresses from `/etc/resolv.conf`. An address from 198.18.0.0/15 (a range for benchmarks, not found in real networks) — `partial`: DNS is answered by a local proxy in fake-IP mode, as in Clash or sing-box. If the file does not exist (Windows), the line is not printed.


## Portal

The connectivity checks that operating systems use to determine whether there is internet access and whether there is a captive portal (the idea and the references come from [remnawave/geocheck](https://github.com/remnawave/geocheck)). Each address answers with a code and a body known in advance. The response is compared with the reference; redirects are not followed:

| Line | Address | Reference |
|---|---|---|
| Google, Google HTTPS | `connectivitycheck.gstatic.com/generate_204` over HTTP and HTTPS | 204, empty body |
| Cloudflare, Cloudflare HTTPS | `cp.cloudflare.com/generate_204` over HTTP and HTTPS | 204 |
| Apple | `http://captive.apple.com/hotspot-detect.html` | 200, `<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>` |
| Microsoft NCSI | `http://www.msftconnecttest.com/connecttest.txt` | 200, `Microsoft Connect Test` |
| Microsoft Edge | `http://edge-http.microsoft.com/captiveportal/generate_204` | 204 |
| Firefox | `http://detectportal.firefox.com/success.txt` | 200, `success` |
| Ubuntu | `http://connectivity-check.ubuntu.com/` | 204 |
| Arch Linux | `http://ping.archlinux.org/` | 200, a phrase about the connectivity check |

The addresses belong to different networks (Google, Cloudflare, Apple, Akamai, Microsoft, Fastly, Canonical, Hetzner), so a failure of one CDN does not look like a problem of the whole network. The body is compared ignoring leading and trailing whitespace.

Verdicts:
- a match — `✓`;
- a 3xx redirect — `✗` "captive portal or filter page", with the host the redirect leads to;
- 200 instead of 204 — `✗`: the response was rewritten by a proxy;
- another code or another body — `✗` with the beginning of the received body;
- an invalid certificate on HTTPS — `✗` "TLS interception";
- 5xx and network errors — `?` or `✗` depending on the type of error, as in DPI.

If the HTTP checks fail while the HTTPS pair matches, the path rewrites unencrypted HTTP. If it is HTTPS that fails while HTTP matches, this is a sign of TLS interception. With a proxy (`--proxy`), the path from the proxy is checked, not the path from this machine.

## DPI and geoblocking

The domain lists are carried over from censorcheck unchanged: 18 "DPI" (YouTube, Discord, Instagram, Facebook, X, LinkedIn, rutracker, DigitalOcean, Amnezia, Outline, Mailfence, Flibusta, rezka, `api.telegram.org`, Google Play, GitHub…) and 10 "geoblock" (Spotify, Netflix, Patreon, Swagger, Snyk, MongoDB, Autodesk, Graylog, Redis, Copilot). For each domain a `GET` is made over HTTP (without following redirects) and over HTTPS (following redirects within the same site) with an honest User-Agent.

Classification:

| Result | Condition |
|---|---|
| `yes` available | 2xx, or a redirect within the same site |
| `no` redirected to block page | a redirect to known block pages (`warning.rt.ru`, `zapret-info.gov.ru`, `*.rkn.gov.ru`), to a private address or to a host with the markers `block`, `zapret`, `warning`, `forbidden`, `restrict`, `censor`, `rkn` |
| `no` denied / legal | 403 or 451 |
| `no` TLS handshake … (likely DPI) | a drop or a timeout at the TLS stage — the characteristic signature of DPI |
| `no` blocked by SNI | TLS broke off, but the same address answers a handshake without the server name: the block looks at the name (SNI), not the address |
| `no` blocked by Host header | HTTP broke off after the request, but the same address answers a request whose `Host` is the address itself: the block looks at the `Host` header |
| `no` invalid certificate | certificate substitution (MITM or a stub page) |
| `no` blocked by port | the connection to the port was not established |
| `⊘` blocked by IP | both 80 and 443 are unreachable — the address is probably on a blocklist |
| `?` | a redirect to a different site, another response code, the domain did not resolve |

The phase at which the request broke off is determined via `httptrace`, not from the error text.

The control requests without the name are sent only after the main request has already broken off, and only to the address obtained for that same domain; if the connection that broke off was to a subdomain after a redirect, there is no control request. The TLS handshake simply carries no SNI extension, and the HTTP request has the address itself in `Host`; no other site's name is put anywhere, and no data follows the handshake. If the address does not answer without the name either, the reason says so: the block is then by address or port, or the server itself requires the name. With a proxy the control requests are not run.

## Transport

The `transport` mode shows what happens to UDP: without it calls, WireGuard, QUIC and peer-to-peer connections do not work.

| Check | How |
|---|---|
| `NAT (STUN)` | a STUN Binding request (RFC 5389) from one local port to `stun.cloudflare.com:3478` and `stun.l.google.com:19302`; the servers answer with the address and port the request came from |
| `QUIC www.google.com`, `QUIC www.cloudflare.com` | a QUIC v1 handshake on UDP 443 with ALPN `h3` and the usual certificate check; after the handshake the connection is closed, there are no HTTP/3 requests |

| NAT result | Meaning |
|---|---|
| `yes` no NAT | the local address matched the external one |
| `yes` one mapping for every destination | both servers saw the same address and port: peer-to-peer connections are possible |
| `partial` symmetric NAT | the servers saw different ports: each destination gets its own mapping, peer-to-peer connections need a relay |
| `yes` mapping type is unknown | one server answered, there is nothing to compare with |
| `no` | none answered: UDP is blocked or filtered |
| `?` | no request went to any server (the name did not resolve, the run was interrupted): this says nothing about UDP |

The `carrier-grade NAT` note is added when the local address is from 100.64.0.0/10. An operator's NAT behind a home router is not visible this way: the machine has the router's local address. The details hold the local and the external address with the port; `--mask` hides them.

`QUIC` is `yes` if the handshake completed; `no` with the reason: no answer (UDP 443 is closed or QUIC is filtered), the certificate failed the check, another error. With a proxy the mode is not run: UDP does not go through an HTTP proxy.

In the Local group, next to the default route, `Interface MTU` shows the MTU of the interface the traffic leaves through. This is a local value, not the path MTU: measuring that with probes that forbid fragmentation is not done yet.

## Telegram

For seven addresses of five data centres (DC1–DC5, addresses from censorcheck) a real MTProto handshake is performed over the obfuscated transport of the official clients: a random 64-byte header with HTTP/TLS signatures disallowed, the tag `ee ee ee ee` and the DC number, AES-256-CTR with the key and IV from the header, `req_pq_multi` with a random nonce, verification of `res_pq` and of the nonce in the decrypted response. The algorithm has been checked against censorcheck byte for byte: the test `TestMTProtoHelloMatchesReference` compares the result with a ciphertext computed independently with `openssl`.

| Result | Condition |
|---|---|
| `yes` MTProto handshake OK | a correct `res_pq` |
| `no` TCP connect failed | port 443 of the DC is unreachable |
| `no` handshake dropped (likely DPI) | TCP opened, there is no response or the connection was reset |
| `no` unexpected MTProto reply | there is a response, but it is not MTProto (substitution) |

## Differences from censorcheck

- All addresses are declared in the network policy and go into the network ledger; custom domain lists are added to the policy at startup.
- No SOCKS5 support of its own for Telegram: with any proxy (flag or environment) raw connections and UDP/DoT are forbidden by the policy, and the DNS/Telegram lines show `?` with the reason; DPI/geoblock over HTTP work through the proxy.
- One attempt per target by default (censorcheck has 2 retries), so as not to create extra traffic; `--retries` brings the retries back.
- Classification with `httptrace` distinguishes a drop at TLS from a drop at connection more precisely than parsing curl codes.
- The dependencies curl, dig, jq, column and openssl are not needed — everything is in the binary.
