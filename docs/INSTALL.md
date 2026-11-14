# Установка

[English version](en/INSTALL.md)

## Одной командой

Linux и macOS (архитектура определяется сама):

```bash
curl -fsSLo cii "https://github.com/arngory/cii/releases/latest/download/cii-$(uname -s | tr A-Z a-z)-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/;s/armv7l/arm-7/;s/i[3-6]86/386/')" && chmod +x cii && ./cii
```

Windows (PowerShell):

```powershell
iwr https://github.com/arngory/cii/releases/latest/download/cii-windows-amd64.exe -OutFile cii.exe; .\cii.exe
```

Команда скачивает бинарник последнего релиза с GitHub в текущий каталог и запускает его. На роутере её удобно выполнить из `/tmp`: бинарник останется только в памяти. Для mips/mipsle и других архитектур имя файла смотрите на [странице релиза](https://github.com/arngory/cii/releases/latest).

Локальные базы DB-IP (страна и ASN без обращений к сервисам, подписи хопов в `cii route`) скачиваются один раз:

```bash
./cii data update
```

## Менеджеры пакетов и Docker

Homebrew (macOS и Linux):

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

Формула и манифест лежат в этом же репозитории (`Formula/`, `bucket/`), их обновляет релизный workflow.

Docker (образ `ghcr.io/arngory/cii`, amd64 и arm64, собирается из тех же бинарников):

```bash
docker run --rm -it --network host ghcr.io/arngory/cii
```

`--network host` нужен, чтобы проверялась сеть машины, а не сеть контейнера; `-it` — для меню. Для хопов в `cii route` добавьте `--cap-add NET_RAW`, для баз и логов между запусками — том `-v cii:/data`.

Бинарники для Linux (amd64, arm64, armv7, 386, mips/mipsle softfloat, riscv64), macOS и Windows, пакеты `deb`, `rpm` и `apk`, формула Homebrew (`cii.rb`), манифест Scoop (`cii.json`) и `PKGBUILD` для AUR лежат на [странице релиза](https://github.com/arngory/cii/releases/latest). Всё собирается в GitHub Actions из этого репозитория, у каждого файла есть подтверждение происхождения:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

```bash
gh attestation verify cii-linux-amd64 --repo arngory/cii
```

К релизу приложен SBOM `cii.cdx.json` (CycloneDX): из чего собран бинарник. Его аттестацию и происхождение образа проверяют так же:

```bash
gh attestation verify cii-linux-amd64 --repo arngory/cii --predicate-type https://cyclonedx.org/bom
```

```bash
gh attestation verify oci://ghcr.io/arngory/cii:latest --repo arngory/cii
```

Сборка из исходников: `make build` (нужен Go из `go.mod`).

## Автодополнение и man

Пакеты `deb`, `rpm`, `apk` и формула Homebrew ставят автодополнение для bash, zsh и fish и страницу `man cii` сами. Для бинарника, скачанного отдельно:

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
