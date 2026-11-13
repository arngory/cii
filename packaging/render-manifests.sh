#!/usr/bin/env bash
set -euo pipefail
tag=$1
version=${tag#v}
base="https://github.com/arngory/cii/releases/download/$tag"
sum() { awk -v f="$1" '$2 == f { print $1 }' dist/SHA256SUMS; }

cat > dist/cii.rb <<RUBY
class Cii < Formula
  desc "Complete information about the current IP address"
  homepage "https://github.com/arngory/cii"
  version "$version"
  license "AGPL-3.0-only"

  on_macos do
    on_arm do
      url "$base/cii-darwin-arm64"
      sha256 "$(sum cii-darwin-arm64)"
    end
    on_intel do
      url "$base/cii-darwin-amd64"
      sha256 "$(sum cii-darwin-amd64)"
    end
  end

  on_linux do
    on_arm do
      url "$base/cii-linux-arm64"
      sha256 "$(sum cii-linux-arm64)"
    end
    on_intel do
      url "$base/cii-linux-amd64"
      sha256 "$(sum cii-linux-amd64)"
    end
  end

  def install
    bin.install Dir["cii-*"].first => "cii"
    generate_completions_from_executable(bin/"cii", "completion")
    (man1/"cii.1").write Utils.safe_popen_read(bin/"cii", "man")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/cii version")
  end
end
RUBY

cat > dist/cii.json <<JSON
{
  "version": "$version",
  "description": "Complete information about the current IP address",
  "homepage": "https://github.com/arngory/cii",
  "license": "AGPL-3.0-only",
  "architecture": {
    "64bit": {
      "url": "$base/cii-windows-amd64.exe#/cii.exe",
      "hash": "$(sum cii-windows-amd64.exe)"
    },
    "arm64": {
      "url": "$base/cii-windows-arm64.exe#/cii.exe",
      "hash": "$(sum cii-windows-arm64.exe)"
    }
  },
  "bin": "cii.exe"
}
JSON

cat > dist/PKGBUILD <<PKG
pkgname=cii-bin
pkgver=${version//-/_}
pkgrel=1
pkgdesc="Complete information about the current IP address"
arch=('x86_64' 'aarch64')
url="https://github.com/arngory/cii"
license=('AGPL-3.0-only')
provides=('cii')
conflicts=('cii')
source_x86_64=("cii-\$pkgver-x86_64::$base/cii-linux-amd64")
source_aarch64=("cii-\$pkgver-aarch64::$base/cii-linux-arm64")
sha256sums_x86_64=('$(sum cii-linux-amd64)')
sha256sums_aarch64=('$(sum cii-linux-arm64)')

package() {
  install -Dm755 "\$srcdir/cii-\$pkgver-\$CARCH" "\$pkgdir/usr/bin/cii"
}
PKG
