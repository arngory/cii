#!/usr/bin/env bash
set -euo pipefail
version=${1#v}
cfg=.nfpm.yaml
trap 'rm -f "$cfg"' EXIT
for spec in amd64:cii-linux-amd64 arm64:cii-linux-arm64 arm7:cii-linux-arm-7 386:cii-linux-386 riscv64:cii-linux-riscv64; do
	arch=${spec%%:*}
	binary=dist/${spec#*:}
	test -f "$binary"
	sed -e "s|@ARCH@|$arch|" -e "s|@VERSION@|$version|" -e "s|@BINARY@|$binary|" packaging/nfpm.yaml >"$cfg"
	for format in deb rpm apk; do
		nfpm package --config "$cfg" --packager "$format" --target dist/
	done
done
