# Installation

[Русская версия](../INSTALL.md)

## In one line

Linux and macOS (the architecture is picked automatically):

```bash
curl -fsSLo cii "https://github.com/arngory/cii/releases/latest/download/cii-$(uname -s | tr A-Z a-z)-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/;s/armv7l/arm-7/;s/i[3-6]86/386/')" && chmod +x cii && ./cii
```

Windows (PowerShell):

```powershell
iwr https://github.com/arngory/cii/releases/latest/download/cii-windows-amd64.exe -OutFile cii.exe; .\cii.exe
```

The command downloads the latest release binary from GitHub into the current directory and runs it. On a router, run it from `/tmp` so the binary only lives in memory. For mips/mipsle and other targets, pick the file name from the [release page](https://github.com/arngory/cii/releases/latest).

Local DB-IP databases (country and ASN without asking services, hop labels in `cii route`) are fetched once:

```bash
./cii data update
```

## Package managers and Docker

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

Docker (image `ghcr.io/arngory/cii`, amd64 and arm64, built from the same binaries):

```bash
docker run --rm -it --network host ghcr.io/arngory/cii
```

`--network host` makes cii check the machine's network instead of the container's; `-it` is for the menu. Add `--cap-add NET_RAW` for hops in `cii route` and a volume `-v cii:/data` to keep databases and logs between runs.

Binaries for Linux (amd64, arm64, armv7, 386, mips/mipsle softfloat, riscv64), macOS and Windows, `deb`, `rpm` and `apk` packages, a Homebrew formula (`cii.rb`), a Scoop manifest (`cii.json`) and an AUR `PKGBUILD` are on the [release page](https://github.com/arngory/cii/releases/latest). Everything is built by GitHub Actions from this repository, and every file carries a provenance attestation:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

```bash
gh attestation verify cii-linux-amd64 --repo arngory/cii
```

The release carries an SBOM, `cii.cdx.json` (CycloneDX): what the binary is built from. Its attestation and the provenance of the image are verified the same way:

```bash
gh attestation verify cii-linux-amd64 --repo arngory/cii --predicate-type https://cyclonedx.org/bom
```

```bash
gh attestation verify oci://ghcr.io/arngory/cii:latest --repo arngory/cii
```

From source: `make build` (needs the Go version from `go.mod`).

## Completion and man

The `deb`, `rpm` and `apk` packages and the Homebrew formula install completion for bash, zsh and fish and the `man cii` page themselves. For a binary downloaded on its own:

```bash
cii completion bash > ~/.local/share/bash-completion/completions/cii
```

```bash
cii completion zsh > "${fpath[1]}/_cii"
```

```bash
cii completion fish > ~/.config/fish/completions/cii.fish
```

```bash
cii man | man -l -
```
