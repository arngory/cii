class Cii < Formula
  desc "Complete information about the current IP address"
  homepage "https://github.com/arngory/cii"
  version "0.3.0"
  license "AGPL-3.0-only"

  on_macos do
    on_arm do
      url "https://github.com/arngory/cii/releases/download/v0.3.0/cii-darwin-arm64"
      sha256 "8bce76663038358c5a8be1c24a863f624d9edd90a6d3a74309b8a044b09ed24e"
    end
    on_intel do
      url "https://github.com/arngory/cii/releases/download/v0.3.0/cii-darwin-amd64"
      sha256 "d22f40b3b6cab3116c3a20c078c2d1e70a495a1475eb2d6dd96f195e1f7733c4"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/arngory/cii/releases/download/v0.3.0/cii-linux-arm64"
      sha256 "6510188d9aace10da2349d647e43d864df3e3936166e3c1550bed61bd0b66369"
    end
    on_intel do
      url "https://github.com/arngory/cii/releases/download/v0.3.0/cii-linux-amd64"
      sha256 "a974498e29400fc70161cd1592ab27bc50159d5d41e38da207f6879c6a0cef00"
    end
  end

  def install
    bin.install Dir["cii-*"].first => "cii"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/cii version")
  end
end
