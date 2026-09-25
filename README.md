<!--suppress HtmlDeprecatedAttribute -->
<h1 align="center">
  N E U T R O N<br>
  ---==[ ⚛ ]==---<br>
  <small>ɴ ᴇ ᴛ ᴡ ᴏ ʀ ᴋ &nbsp; ᴍ ᴀ ɴ ᴀ ɢ ᴇ ʀ</small>
</h1>

<!--suppress HtmlDeprecatedAttribute -->
<p align="center">
  <img src="docs/screenshots/Neutron-Connected.png" alt="Neutron TUI - Active WireGuard Connection" width="850">
</p>

A lightweight, high-performance WireGuard manager for Linux built in Rust, utilizing NetworkManager as the underlying
networking control plane. Designed to be minimal and resource-efficient, Neutron runs as a standalone ~3–5 MB binary
with zero dynamic dependencies, uses only ~10–15 MB of RAM, idles at 0% CPU, and launches in under 10 ms.

---

## Key Features

- **Connection Management**
- **Random Profile on Boot**
- **Global Split Tunneling**
- **Port Forwarding**
- **NetworkManager-Native Kill Switch**
- **Always-On Lockdown Mode (blocking all physical traffic while disconnected)**
- **NetworkManager profile sync**
- **Multi-File Profile Import**
- **Multiple Interfaces (TUI, CLI)**
- **qBittorrent automatic port synchronization**
- **qBittorrent automatic wg profile binding**

---

## Quick Start

### 1. One-Line Install

Install via [Homebrew](https://brew.sh/) (including tap trust so background auto-updates work seamlessly):

```bash
brew tap pandabytez/tap && brew trust pandabytez/tap && brew install neutron
```

*(Or via Cargo: `cargo install --git https://github.com/PandaBytez/neutron.git`)*

### 2. Import Profiles

Neutron automatically pre-creates `~/.config/neutron/profiles/` with secure user-only permissions (`0700`). Simply place
your WireGuard configuration files (`*.conf`) into the drop directory in your file manager app or use command:

```bash
mv *.conf ~/.config/neutron/profiles/
```

> **Note:** If you already have WireGuard profiles loaded in NetworkManager, you can skip this step — Neutron detects
> and manages all existing NetworkManager profiles automatically.

### 3. Launch TUI & Useful Commands

#### Interactive Terminal UI (Recommended)

Launch the full interactive TUI:

```bash
neutron
```

Browse profiles, connect/disconnect with `Space` or `Enter`, switch profiles with `s`, configure split tunneling with
`t`, toggle the kill switch with `k`, or press `Ctrl+P` for the command palette.

#### Complete restart command

```bash
# Restart background daemon and refresh system tray state
neutron restart
```

---

## 🌐 **[Documentation](https://pandabytez.github.io/neutron/)**

---

## Building from Source

```bash
# Build standard release binary
cargo build --release

# Statically-linked musl binary (zero dynamic dependencies)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### Auto-Connect at Login

Auto-connect is **off by default**. Press **`a`** in the TUI to enable it and install the desktop autostart entry,
which connects an eligible WireGuard profile at login.

For headless servers without an XDG desktop environment, an optional user service is provided in [`systemd/`](systemd/).

### Lockdown across reboots

Lockdown is stored in firewalld's permanent configuration and takes effect when
firewalld starts, before login. Enabling/disabling it requires administrator
authentication. Enabling also installs a root-owned refresh helper and a dedicated
polkit action so an active local session can refresh tunnel/DNS allowances
without another password prompt. The helper cannot turn lockdown on or off.

After upgrading (including from 0.1.2), run `neutron lockdown enable` once from an
active local session to install/update the helper and its authorization. This
replaces the old authorization check that polkit rejected for non-root users.
Existing protection stays in place if an automatic refresh cannot be authorized.
Enabling lockdown also enables firewalld at boot on systemd systems. Polkit 126+
uses `/usr/local/share/polkit-1/actions`, supporting immutable `/usr`; older
versions require a writable `/usr/share/polkit-1/actions`.

### Uninstalling

Run `neutron uninstall` as your normal user. It stops the tray daemon, lifts
lockdown (one password prompt, only if lockdown is on — the permanent firewalld
rules), revokes the password-free refresh grant (the root-owned helper and its
polkit action), removes the autostart entry, and then hands the binary to
whichever package manager installed it: `brew uninstall neutron` for a Homebrew
install, `cargo uninstall neutron` for a `cargo install`.

Those root-owned files live outside the package's own file list, and no packaging
hook can remove them: Homebrew's `post_uninstall` runs *after* the files are gone,
with no way to authenticate. So the teardown has to happen while the binary still
exists — which is why it is a subcommand rather than a package script. The grant
is revoked here rather than by `neutron lockdown disable`, so turning lockdown
off and back on again does not cost a second password prompt.

`~/.config/neutron` is **kept** (eligibility pool, favorites, settings) so a
reinstall finds it intact; add `--purge` to delete it too, which is also how the
stored qBittorrent password goes away. A drop directory configured *outside* it
is always left alone, since it holds your own files.

An install Neutron does not recognize — an AppImage, a distro package — is
refused with an explanation and **nothing is changed**, rather than guessing a
package manager. If the package is already gone and rules were left behind, see
[the manual recovery steps](docs/security.md#uninstalling-revokes-everything-it-installed).

---
