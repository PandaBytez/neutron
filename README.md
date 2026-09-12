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

---
