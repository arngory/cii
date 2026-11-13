# Benchmarks: `cii bench`

[Русская версия](../BENCH.md)

The benchmark answers the question "what kind of machine is this and what is its link like". It is run either as the separate `cii bench` command with the settings below, or with the `cii --bench` flag after the other checks, with the default settings (the "Benchmark" panel on the common screen, the current step is shown in the title). The ideas are taken from [masonr/yet-another-bench-script](https://github.com/masonr/yet-another-bench-script) and [teddysun/across](https://github.com/teddysun/across) (bench.sh), but everything is reimplemented in Go inside cii's network policy: nothing is downloaded, the results are not sent anywhere, every address is declared in advance and is visible in `--plan`.

```bash
cii bench
```

```bash
cii bench --servers ru --duration 10s
```

```bash
cii bench --no-disk --no-cpu --servers "iperf.example.net:5201-5209:MyISP:Frankfurt"
```

```bash
cii bench --system
```

Command flags: `--no-disk`, `--no-cpu`, `--no-speed`, `--no-iperf` disable parts; `--disk-dir DIR` and `--disk-size SIZE` (default: a temporary directory and `1G`, minimum 64 MiB) set the file of the disk test; `--duration DUR` (default 5s; a whole number of seconds from 1s to 1m) is the duration of each network measurement; `--servers LIST` selects the iperf3 servers; `--system` additionally runs the installed iperf3 and fio. The common cii flags (`-4`/`-6`, `--iface`, `--source`, `--proxy`, `--timeout`, `--offline`, `--json`, `--debug`, `--mask`, `--no-log`) work as usual; `--offline` leaves only the system, the disk and the CPU; `--mask` hides addresses in the error texts of the network measurements as well. Without `-4` and `-6` the network measurements go over IPv4, so that the numbers of different runs are comparable; on an IPv6-only machine `-6` is needed.

## System information

On Linux, `/proc/cpuinfo` (the model, the `aes`, `vmx`/`svm` flags), `/proc/meminfo`, `/proc/uptime`, `/proc/loadavg`, `/proc/sys/kernel/osrelease`, `/etc/os-release` and the DMI in `/sys/class/dmi/id` are read, the latter to detect virtualisation (KVM, VMware, VirtualBox, Hyper-V, Xen, GCE, EC2, OpenStack, Parallels, bhyve, a container by `/proc/1/cgroup`, OpenVZ). On other systems — only the OS, the architecture and the number of processors.

## Disk

The file `.cii-bench-<random suffix>` is created in `--disk-dir` only as a new file (`O_EXCL`, on Windows `CREATE_NEW`): an existing file or a symbolic link with that name is not used. After the test the file is deleted. Twice as much free space as the file size is needed. The file is opened with direct I/O: `O_DIRECT` on Linux, `F_NOCACHE` on macOS, `FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH` on Windows; if that fails, the test goes through the cache and is marked "buffered" in the output. Measurements:

| Test | How | What is shown |
|---|---|---|
| seq | a sequential write of the file in 1 MiB blocks, `fsync`, then a sequential read | MB/s for read and write |
| 4k, 64k, 512k, 1m | 4 seconds of random reads and writes in equal shares, 8 parallel threads, each with its own xorshift offset generator | MB/s and IOPS for read and write |

A read or write error in any of the measurements stops the disk test: instead of numbers, a `disk: …` line appears in the notes.

The numbers are comparable between cii runs on different machines, but not directly with fio: the queue and the load model are different. For comparison with the familiar figures there is `--system`.

## CPU

Three workloads on real primitives from the Go standard library, each for 1.5 s on a 1 MiB buffer: SHA-256, AES-256-GCM and deflate (the default level). The buffer is filled with pseudo-random text from a 512-word dictionary: it compresses roughly like ordinary text, so deflate does real work rather than collapsing a repeating pattern. First one thread, then as many as there are processors visible to Go. The throughputs in MB/s and a composite score are shown: `(sha256 + aes_gcm + 4·deflate) / 1000 MB/s · 100`. The score is cii's own and is not comparable with other benchmarks; AES without hardware support will be noticeably slower, which is visible in the output next to the AES-NI flag.

## Speed via Cloudflare

Cloudflare's public speed test at `speed.cloudflare.com` is used: five `/cdn-cgi/trace` requests give the latency (the best of five) and the data centre code, then `--duration` seconds of downloading `/__down?bytes=N` with the size doubling from 1 MiB to 50 MiB, and the same amount of time of uploading zeros to `/__up` (from 256 KiB to 25 MiB). The block grows only while the previous one fitted into a quarter of the remaining time. The download is cut off exactly when `--duration` expires, and the received part of the last block is counted; for the upload only the blocks that the server accepted in full are counted, and up to 10 seconds beyond `--duration` are allowed for the last one to finish. The speed is the bytes transferred divided by the time of the transfers themselves: for the download, from the first byte of the response body; for the upload, the whole request.

Cloudflare limits the volume per address and answers with HTTP 403 when it is exceeded. After such a refusal cii no longer requests blocks of that size (the ceiling is halved), pauses for 250 ms to 1 s and continues; the refused requests are not included in the speed. An error is shown only if not a single block got through during the whole time. The requests go through `netx.HTTPClient` with cii's usual User-Agent, and through the proxy if one is set.

## iperf3

cii's own client for the iperf3 protocol (control stream, cookie, exchange of parameters and results in JSON, four parallel streams by default). First sending, and a second later receiving (`reverse`). The ports of the range are tried in turn: a busy server (`server busy`, codes 10 and 11), an access denial and a rejected connection (connection refused) move on to the next port; any other error, including a connection timeout and silence from the server in the first 5 seconds after the connection, stops the attempts for that server, so that an unreachable host does not take up time on every port of the range. The duration of the test is `--duration`.

With a proxy (flag or environment) iperf3 is skipped with a note: otherwise the raw TCP would go past the proxy. With `-6` only the servers with IPv6 are used.

Server lists (`--servers`, comma-separated):

| Set | Servers |
|---|---|
| `global` (default) | Clouvider London and Los Angeles, Eranium Amsterdam, Uztelecom Tashkent, Leaseweb Singapore and New York — public servers from the YABS list, all with IPv6 |
| `ru` | Hostkey Moscow; Dom.ru (Ertelecom): Saint Petersburg, Nizhny Novgorod, Kazan, Rostov-on-Don, Yekaterinburg, Novosibirsk, Irkutsk |
| `all` | both sets |
| `host:ports[:provider[:location]]` | your own server, for example `iperf.example.net:5201-5209:MyISP:Frankfurt`; an IPv6 address is written in brackets: `[2001:db8::1]:5201` |

Sets and your own servers can be mixed (`ru,iperf.example.net:5201`); duplicates are removed. Ports are a number or a range within 1–65535. An entry that could not be parsed is an error: `cii bench` exits before the measurements start. Your own server is considered reachable over both IPv4 and IPv6, so with `-6` it is tested too.

The Russian set is compiled by hand: it takes operators' speedtest sites that have kept public iperf3 ports open for years, one per major city and federal district. The list [itdoginfo/russian-iperf3-servers](https://github.com/itdoginfo/russian-iperf3-servers) was used as a hint about which sites are alive and which ports they have (some Dom.ru servers have part of their ports closed, hence ranges like `5202-5209`). If an operator closes a server, it will drop out of the list at the next update; your own server can always be given explicitly.

## Installed programs: `--system`

With the `--system` flag cii additionally runs the already installed `iperf3` and `fio` and shows their results next to its own (the `[iperf3]` and `fio` lines). cii downloads nothing: if a program is missing, the notes show the install command for your system (`apt`, `dnf`, `apk`, `pacman`, `opkg`, `zypper`, `pkg`, `brew`, `winget`). The system iperf3 is invoked with the same servers, ports, number of streams, duration, address family and source address; before the run the host passes the same network policy (`netx.LookupHost`), and each run is recorded in the network ledger (a failed one — as an error). fio gets the same four profiles (`seq-1m`, `rand-4k`, `rand-64k`, `rand-512k`; `direct=1`, queue depth 64, two jobs) on the file `.cii-fio-<random suffix>` in `--disk-dir`, which cii itself creates as a new file and deletes after the test.

Ookla Speedtest CLI is not included: cii cannot accept its licence agreement on the user's behalf. Geekbench and similar tools that send results on their own are excluded by the policy.

## Output

On screen — the "Benchmark" panel with the lines `System`, `Disk`, `fio`, `CPU`, `Speed`, `iperf3` and the notes (for `cii bench` it takes the full width while the measurements are running, and the title shows the current step); in `--debug` — tables for each section and the network ledger; in JSON — the `bench` object with all the numbers (bytes, MB/s, IOPS, ms), the duration and the notes. Like the other commands, `cii bench` writes a local log.
