class Cii < Formula
  desc "Complete information about the current IP address"
  homepage "https://github.com/arngory/cii"
  version "0.4.0"
  license "AGPL-3.0-only"

  on_macos do
    on_arm do
      url "https://github.com/arngory/cii/releases/download/v0.4.0/cii-darwin-arm64"
      sha256 "658a00c9e9d394baa9d066448365b9da68263f50e384f1e84cd7f122eb51c8d4"
    end
    on_intel do
      url "https://github.com/arngory/cii/releases/download/v0.4.0/cii-darwin-amd64"
      sha256 "aa4ac6e2db978f08427a58316cca313c4cc0e8fa58916dadbbcecbfa23fa2017"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/arngory/cii/releases/download/v0.4.0/cii-linux-arm64"
      sha256 "fcec44fbe4ffa9a80a69a427ed3bb655348db14235f3402dd2b4f5ae258cae52"
    end
    on_intel do
      url "https://github.com/arngory/cii/releases/download/v0.4.0/cii-linux-amd64"
      sha256 "799f51b15794d0b292a5c47b7f367fbf5d2c38cc75fc983b0e1dbfc1f75790c2"
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
