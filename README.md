<!--suppress HtmlDeprecatedAttribute -->
<h1 align="center">
  N E U T R O N<br>
  ---==[ ⚛ ]==---<br>
  <small>ɴ ᴇ ᴛ ᴡ ᴏ ʀ ᴋ &nbsp; ᴍ ᴀ ɴ ᴀ ɢ ᴇ ʀ</small>
</h1>

A lightweight, high-performance WireGuard manager for Linux built in Rust, utilizing NetworkManager as the underlying
networking control plane. Designed to be minimal and resource-efficient, Neutron runs as a standalone ~3–5 MB binary
with zero dynamic dependencies, uses only ~10–15 MB of RAM, idles at 0% CPU, and launches in under 10 ms.

Distributed via **Homebrew Formula**, **AUR**, and standalone static binaries.

---

## Key Features

- **NetworkManager Source-of-Truth**: Native integration with NetworkManager WireGuard connections without managing raw
  `wg-quick` scripts.
- **Connection Management**: Instant manual connect, disconnect, and switch between WireGuard profiles.
- **Random Profile on Boot**: Automatically picks and connects a random eligible profile at login/boot, avoiding
  immediate repeats.
- **Global Split Tunneling**: Route only specific subnets/domains through the WireGuard tunnel (*Include mode*) or
  bypass the tunnel for selected traffic (*Exclude mode*) using NetworkManager policy routing.
- **Dynamic NAT-PMP Port Forwarding & qBittorrent Sync**: Automatic gateway discovery, port lease requests, periodic
  background renewals, and seamless automatic port synchronization with **qBittorrent** (native, Flatpak, and
  containers) via its local Web API.
- **NetworkManager-Native Kill Switch**: Strict routing table isolation (`fwmark` + `suppress_prefixlength 0`) with
  negative DNS priorities to eliminate DNS and routing leaks.
- **Always-On Lockdown Firewall**: Permanent `firewalld` Netfilter rules via `pkexec` blocking all physical traffic
  while disconnected, leaving only encrypted handshakes and local LAN traffic reachable.
- **Multi-File Profile Import**: Import `.conf` files in batches directly into NetworkManager with automated validation
  and error aggregation.
- **Multiple Interfaces**: Lightweight zero-dependency TUI (Terminal UI), comprehensive scriptable CLI, and a modern
  desktop GUI.

---

## Quick Start

### 1. One-Line Install

Install via Homebrew (including tap trust so background auto-updates work seamlessly):

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

📖 **Complete documentation & keybindings:** See the full [**Usage Guide (TUI & CLI)**](docs/usage.md).

---

## Documentation & Wiki

Explore detailed architectural and technical documentation in the [`docs/`](docs/) directory:

- [**Usage Guide (TUI & CLI)**](docs/usage.md)
- [**Wiki Index**](docs/README.md)
- [**System Architecture & Decoupled Engine**](docs/architecture.md)
- [**NetworkManager Integration**](docs/networkmanager.md)
- [**Security: Kill Switch & Lockdown Netfilter**](docs/security.md)
- [**Split Tunneling (IP & Domain Routing)**](docs/split-tunneling.md)
- [**NAT-PMP Port Forwarding Engine**](docs/port-forwarding.md)
- [**User Configuration & Theming (`config.toml`)**](docs/configuration.md)
- [**Packaging & Universal Distribution**](docs/packaging-distribution.md)

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

Auto-connect is built directly into Neutron: press **`a`** in the TUI (or set `autoconnect_at_login = true` in
`config.toml`) to automatically connect an eligible WireGuard profile at desktop login.

For headless servers without an XDG desktop environment, an optional user service is provided in [`systemd/`](systemd/).

---

## Quality Checks & Testing

```bash
# Run formatting and strict clippy linting across all features
cargo lint

# Run standard host unit & integration test suite
cargo test

# Run ALL tests end-to-end (host tests + containerized system & leak tests)
cargo test-all
```

Containerized System & Leak Tests (requires `podman` or `docker`):

```bash
# Run system integration tests in isolated container sandbox
cargo test-system

# Run specific system test suites
cargo test-system -- --nm        # NetworkManager system tests
cargo test-system -- --firewall  # Firewall lockdown system tests
cargo test-system -- --rebuild   # Rebuild container image

# Run leak protection regression tests
cargo test-leaks

# Open interactive shell in test sandbox
cargo xtask container-shell
```

---

## Implementation Notes

- **Auto-connect compatibility**: NetworkManager's native connection properties, such as automatic connection
  (`connection.autoconnect` and `connection.autoconnect-priority`), are fully supported. Neutron's boot-time random
  selector service first checks if any WireGuard profile is already active. If NetworkManager has already auto-connected
  a preferred profile, the randomizer cleanly skips selection, ensuring they complement each other perfectly.
- Application config (excluded-profile set and last random selection) is written atomically and, on Unix, restricted to
  owner-only access (`0o600`). No private keys or secrets are ever stored here; those remain in NetworkManager.
- All `nmcli` invocations run with a 30-second timeout and surface the command exit code on failure, so a stuck
  NetworkManager call cannot hang the CLI or GUI indefinitely.
- The kill switch is global and NetworkManager-native: it is a single on/off policy, remembered in app config, that is
  applied to every WireGuard profile. Enabling it forces each WireGuard connection's automatic default-route policy
  routing on (`wireguard.ip4/ip6-auto-default-route`) and gives the tunnel exclusive DNS priority. NetworkManager then
  installs the same `fwmark` + `suppress_prefixlength 0` policy rules as `wg-quick`, so while a tunnel is active all
  non-tunnel traffic is dropped instead of leaking to the physical default route. It applies the next time a profile is
  activated and is effective for full-tunnel profiles (a peer with `0.0.0.0/0` / `::/0` allowed IPs). No firewall rules
  or privileged helper are involved.
- Lockdown is an optional always-on firewall that closes the kill switch's one gap: the kill switch only protects
  traffic *while a tunnel is active*, whereas lockdown blocks all non-tunnel traffic even while disconnected and across
  reboots. It installs permanent `firewalld` direct rules on the OUTPUT chain (both IPv4 and IPv6) that allow only
  loopback, established connections, DNS, the WireGuard tunnel interfaces, and the peer endpoints (so the *encrypted*
  handshake can still leave); everything else is rejected by a `neutron-lockdown`-tagged rule. Because it touches the
  system firewall, `firewall-cmd` runs through `pkexec` (polkit caches the prompt, so enabling/disabling asks for a
  password at most once), and the disable path always tears the ruleset down so the user can never be permanently locked
  out. The pure rule-builders are unit-tested; the privileged `firewall-cmd`/`pkexec` calls need a real firewalld and
  root, so they are verified by running the binary, not in `cargo test`.
- Profile import runs `nmcli connection import type wireguard file <path>`, so NetworkManager stays the single source of
  truth — no local copy of the `.conf` is kept.
- The application binary is named **Neutron** (`neutron`) with zero runtime shared library dependencies when compiled
  for the musl target.
