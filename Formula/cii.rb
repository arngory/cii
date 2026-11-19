class Cii < Formula
  desc "Complete information about the current IP address"
  homepage "https://github.com/arngory/cii"
  version "0.4.1"
  license "AGPL-3.0-only"

  on_macos do
    on_arm do
      url "https://github.com/arngory/cii/releases/download/v0.4.1/cii-darwin-arm64"
      sha256 "02220e69926b0a7354edf229d5effcb3365fed7ad15efa5bce9ad5eb8aa9a56b"
    end
    on_intel do
      url "https://github.com/arngory/cii/releases/download/v0.4.1/cii-darwin-amd64"
      sha256 "883eb2d996796e1219c040f5b51704a6bab4c9281a8455f64b54e8487aacc2ae"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/arngory/cii/releases/download/v0.4.1/cii-linux-arm64"
      sha256 "8744e0d806ceaadc57809217ad72aa979d16ce19997a6be7c5522d102a052e90"
    end
    on_intel do
      url "https://github.com/arngory/cii/releases/download/v0.4.1/cii-linux-amd64"
      sha256 "2843778e6d6ed311431761ace861366c1fb0b247fd5b4cafb2726d21d51da22f"
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
