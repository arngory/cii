class Cii < Formula
  desc "Complete information about the current IP address"
  homepage "https://github.com/arngory/cii"
  version "0.2.2"
  license "AGPL-3.0-only"

  on_macos do
    on_arm do
      url "https://github.com/arngory/cii/releases/download/v0.2.2/cii-darwin-arm64"
      sha256 "7a092895ee7c4c75c58d12b5681e56e141e6f0c95facf1b65a176834da360c38"
    end
    on_intel do
      url "https://github.com/arngory/cii/releases/download/v0.2.2/cii-darwin-amd64"
      sha256 "bc9c280e6a7367627d5059ff934d5802d14de29657db26418269279a85567e38"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/arngory/cii/releases/download/v0.2.2/cii-linux-arm64"
      sha256 "1826e7bb4ee059905f470a193e9793cebf9b975318ce8119c28394ded9fc6d10"
    end
    on_intel do
      url "https://github.com/arngory/cii/releases/download/v0.2.2/cii-linux-amd64"
      sha256 "93691cf6dfdf3da91abada45586dc75ce3afdd679ea244c59255b844ba6eebe7"
    end
  end

  def install
    bin.install Dir["cii-*"].first => "cii"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/cii version")
  end
end
