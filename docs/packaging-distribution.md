# Packaging & Universal Distribution

Neutron VPN is designed for easy distribution across all major Linux packaging ecosystems.

---

## Packaging Channels Overview

| Format | Target Platform | Dependencies | Standalone? | Build Command |
| :--- | :--- | :--- | :---: | :--- |
| **Homebrew** | macOS / Linuxbrew | Zero (Pure Rust TUI/CLI) | Yes | `brew install neutron-vpn` |
| **Static Musl** | Headless Servers, SSH | Zero (Static musl binary) | Yes | `cargo build --target x86_64-unknown-linux-musl` |
| **Arch AUR** | Arch Linux, Manjaro | System dependencies | Native | `makepkg -si` |

---

## 1. Homebrew Tap Formula (`Formula/neutron.rb`)

Sample formula for custom tap (`brew tap pandabytez/tap`):

```ruby
class Neutron < Formula
  desc "Fast WireGuard profile manager via NetworkManager"
  homepage "https://github.com/PandaBytez/neutron"
  url "https://github.com/PandaBytez/neutron/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "<checksum>"
  license "GPL-3.0-or-later"

  depends_on "rust" => :build
  depends_on :linux

  def install
    system "cargo", "install", *std_cargo_args
    bin.install_symlink "neutron" => "neutron-vpn"
  end

  test do
    assert_match "Neutron", shell_output("#{bin}/neutron --help")
  end
end
```

---

## 2. Static Musl Target (Headless Servers / Homelabs)

Compile a 100% statically-linked executable with no dynamic shared library dependencies:

```bash
# Add musl target
rustup target add x86_64-unknown-linux-musl

# Build static binary
cargo build --release --target x86_64-unknown-linux-musl
```
The resulting binary (`target/x86_64-unknown-linux-musl/release/neutron-vpn`) runs on Alpine Linux, Debian, RHEL, Ubuntu, and any minimal Linux environment.

---

## 3. Arch Linux AUR Package (`PKGBUILD`)

Sample `PKGBUILD` for Arch Linux:

```bash
pkgname=neutron-vpn-bin
pkgver=0.1.0
pkgrel=1
pkgdesc="High-performance WireGuard manager via NetworkManager"
arch=('x86_64' 'aarch64')
url="https://github.com/PandaBytez/neutron"
license=('GPL-3.0-or-later')
depends=('networkmanager')
source_x86_64=("https://github.com/PandaBytez/neutron/releases/download/v${pkgver}/neutron-vpn-linux-amd64.tar.gz")
sha256sums_x86_64=('SKIP')

package() {
    install -Dm755 neutron-vpn "${pkgdir}/usr/bin/neutron-vpn"
}
```