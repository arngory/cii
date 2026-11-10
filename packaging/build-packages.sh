#!/usr/bin/env bash
set -euo pipefail
version=${1#v}
for spec in amd64:cii-linux-amd64 arm64:cii-linux-arm64 arm7:cii-linux-arm-7 386:cii-linux-386 riscv64:cii-linux-riscv64; do
	arch=${spec%%:*}
	for format in deb rpm apk; do
		NFPM_ARCH=$arch VERSION=$version BINARY=dist/${spec#*:} nfpm package --config packaging/nfpm.yaml --packager "$format" --target dist/
	done
done
