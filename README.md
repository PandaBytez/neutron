# Neutron VPN

A high-performance WireGuard manager for Linux built in Rust, utilizing NetworkManager as the underlying networking control plane.

Branded as **Neutron VPN** (`io.github.pandabytez.neutron`), distributed via **Homebrew Formula**, **AUR**, and standalone static binaries.

---

## Key Features

- **NetworkManager Source-of-Truth**: Native integration with NetworkManager WireGuard connections without managing raw `wg-quick` scripts.
- **Connection Management**: Instant manual connect, disconnect, and switch between WireGuard profiles.
- **Random Profile on Boot**: Automatically picks and connects a random eligible profile at login/boot, avoiding immediate repeats.
- **Global Split Tunneling**: Route only specific subnets/domains through the VPN (*Include mode*) or bypass the VPN for selected traffic (*Exclude mode*) using NetworkManager policy routing.
- **Dynamic NAT-PMP Port Forwarding & qBittorrent Sync**: Automatic gateway discovery, port lease requests, periodic background renewals, and seamless automatic port synchronization with **qBittorrent** (native, Flatpak, and containers) via its local Web API.
- **NetworkManager-Native Kill Switch**: Strict routing table isolation (`fwmark` + `suppress_prefixlength 0`) with negative DNS priorities to eliminate DNS and routing leaks.
- **Always-On Lockdown Firewall**: Permanent `firewalld` Netfilter rules via `pkexec` blocking all physical traffic while disconnected, leaving only encrypted handshakes and local LAN traffic reachable.
- **Multi-File Profile Import**: Import `.conf` files in batches directly into NetworkManager with automated validation and error aggregation.
- **Multiple Interfaces**: Modern GTK4 / Libadwaita desktop GUI, comprehensive scriptable CLI, and a lightweight zero-dependency TUI (Terminal UI).

---

## Frontend & Resource Comparison

| Metric | GTK4 / Libadwaita (GUI) | Pure Rust TUI (`ratatui`) | Background Daemon / CLI | Electron / Web VPN Clients |
| :--- | :---: | :---: | :---: | :---: |
| **Binary Size** | ~15–30 MB (or AppImage bundle) | **~3–5 MB** (Static musl binary) | **~3 MB** | 150–250 MB |
| **Active RAM (RSS)** | **~70 – 110 MB** | **~10 – 15 MB** | **~3 – 6 MB** | 250 – 450 MB |
| **Idle CPU Usage** | 0.1% – 0.5% | **0.0%** (sleeps on `epoll`) | **0.0%** | 0.5% – 2.0% |
| **Startup Time** | ~150–300 ms | **< 10 ms** (instantaneous) | **< 2 ms** | 1.5 – 3.0 seconds |
| **System Dependencies** | GTK4, Libadwaita, Mesa/Wayland | **Zero** (100% static musl) | **Zero** | Node, Chromium, X11/Wayland |
| **Use Cases** | Desktop Workstations (GNOME) | Servers, SSH, Hyprland, Sway, i3 | Automation, Cron, Systemd | Legacy Desktop |

---

## Documentation & Wiki

Explore detailed architectural and technical documentation in the [`docs/`](docs/) directory:

- [**Wiki Index**](docs/README.md)
- [**System Architecture & Decoupled Engine**](docs/architecture.md)
- [**NetworkManager Integration**](docs/networkmanager.md)
- [**Security: Kill Switch & Lockdown Netfilter**](docs/security.md)
- [**Split Tunneling (IP & Domain Routing)**](docs/split-tunneling.md)
- [**NAT-PMP Port Forwarding Engine**](docs/port-forwarding.md)
- [**User Configuration & Theming (`config.toml`)**](docs/configuration.md)
- [**Packaging & Universal Distribution**](docs/packaging-distribution.md)

---

## CLI & TUI Usage

```bash
# Launch the interactive Terminal User Interface (TUI)
neutron
# or
neutron tui

# Run standalone persistent system tray AppIndicator daemon
neutron indicator

# Sync profile drop directory (~/.config/neutron/profiles) with NetworkManager
neutron sync

# List WireGuard profiles and status
neutron list

# Connect, disconnect, or switch profiles
neutron connect <profile>
neutron disconnect
neutron switch <profile>

# Manage startup-random eligibility pool
neutron eligible list
neutron eligible add <profile>
neutron eligible remove <profile>

# Global Split Tunneling
neutron split-tunnel status
neutron split-tunnel set-mode <include|exclude|disabled>
neutron split-tunnel add-cidr 10.0.0.0/8
neutron split-tunnel remove-cidr 10.0.0.0/8
neutron split-tunnel add-domain internal.corp
neutron split-tunnel clear

# Security Controls
neutron kill-switch status|enable|disable
neutron lockdown status|enable|disable

# qBittorrent Dynamic Port Sync
# (Prerequisite: Enable Web UI in qBittorrent Options -> Web UI)
neutron qbit status
neutron qbit test
neutron qbit sync
neutron qbit enable
neutron qbit disable
neutron qbit config --url http://127.0.0.1:8080 --bind true
```

### TUI keybindings

Every action below is also reachable from the command palette (`Ctrl+P` or `:`),
which searches by name — the palette and the keys dispatch the same
implementation, so they can never drift apart.

| Key | Action |
| --- | --- |
| `↑` / `↓` (or `p` / `n`) | Move through the profile list |
| `Space` / `Enter` | Connect the selected profile, or disconnect it if active |
| `s` | Switch to the selected profile |
| `e` | **Exclude the selected profile from the auto-connect pool** (press again to put it back) |
| `a` | Toggle auto-connect at login |
| `t` | Open the split tunneling manager |
| `k` | Toggle the kill switch |
| `l` | Toggle lockdown (always-on firewall) |
| `r` | Sync the profile drop directory |
| `d` / `Delete` | Delete the selected profile |
| `Ctrl+P` / `:` | Command palette |
| `Ctrl+T` | Theme picker |
| `?` / `h` | Keybinding help |
| `q` / `Esc` | Quit |

`e` controls which profiles the random login selector may pick. Profiles are in
the pool by default; excluding one records its UUID in `excluded_profile_ids`
and the selector then skips it. Excluded profiles are marked
`[EXCLUDED FROM POOL]` in the list and can still be connected manually.

`list` output now includes eligibility status from config (`eligible` or `not-eligible`). Profiles are eligible by default and become `not-eligible` only once explicitly excluded.

GUI currently renders each profile row with just the profile name, a startup-eligibility toggle (checked by default, since every profile is eligible until excluded), and a per-row connection toggle (a switch that activates the tunnel when turned on and disconnects it when turned off) wired to NetworkManager operations, alongside a single global kill-switch toggle and an always-on lockdown-firewall toggle; enabling either the kill switch or lockdown also raises a desktop notification. An Import button opens a file chooser to add a WireGuard `.conf` as a new NetworkManager profile, after which the list refreshes automatically. The list auto-refreshes after each change and also reacts to NetworkManager monitor events. NetworkManager and firewall calls run on a background thread so the UI stays responsive while `nmcli`/`firewall-cmd` work, toggles disable until the operation finishes and revert on failure, and the `nmcli monitor` child process is terminated when the window closes, which also persists the current window size.

`eligible add` clears a profile's exclusion (reporting when it was already eligible), and `eligible remove` excludes a profile from random startup (reporting when it was already excluded).

Install the optional user service for startup-random automation:

```bash
cat systemd/README.md
```

Building & standalone installation:

```bash
# Build release binary
cargo build --release

# Statically linked musl binary (zero dynamic dependencies)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Quality checks & task runner:

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

Run specific integration tests on host:

```bash
cargo test --test startup_random
cargo test --test active_connection_policies
```

## Implementation notes

- **Auto-connect compatibility**: NetworkManager's native connection properties,
  such as automatic connection (`connection.autoconnect` and `connection.autoconnect-priority`),
  are fully supported. Neutron's boot-time random selector service first checks if
  any WireGuard profile is already active. If NetworkManager has already auto-connected
  a preferred profile, the randomizer cleanly skips selection, ensuring they complement
  each other perfectly.
- Application config (excluded-profile set and last random selection) is written
  atomically and, on Unix, restricted to owner-only access (`0o600`). No private
  keys or secrets are ever stored here; those remain in NetworkManager.
- All `nmcli` invocations run with a 30-second timeout and surface the command
  exit code on failure, so a stuck NetworkManager call cannot hang the CLI or GUI
  indefinitely.
- The kill switch is global and NetworkManager-native: it is a single on/off
  policy, remembered in app config, that is applied to every WireGuard profile.
  Enabling it forces each WireGuard connection's automatic default-route policy
  routing on (`wireguard.ip4/ip6-auto-default-route`) and gives the tunnel
  exclusive DNS priority. NetworkManager then installs the same `fwmark` +
  `suppress_prefixlength 0` policy rules as `wg-quick`, so while a tunnel is
  active all non-tunnel traffic is dropped instead of leaking to the physical
  default route. It applies the next time a profile is activated and is effective
  for full-tunnel profiles (a peer with `0.0.0.0/0` / `::/0` allowed IPs). No
  firewall rules or privileged helper are involved.
- Lockdown is an optional always-on firewall that closes the kill switch's one
  gap: the kill switch only protects traffic *while a tunnel is active*, whereas
  lockdown blocks all non-VPN traffic even while disconnected and across reboots.
  It installs permanent `firewalld` direct rules on the OUTPUT chain (both IPv4
  and IPv6) that allow only loopback, established connections, DNS, the WireGuard
  tunnel interfaces, and the peer endpoints (so the *encrypted* handshake can
  still leave); everything else is rejected by a `neutron-lockdown`-tagged rule.
  Because it touches the system firewall, `firewall-cmd` runs through `pkexec`
  (polkit caches the prompt, so enabling/disabling asks for a password at most
  once), and the disable path always tears the ruleset down so the user can never
  be permanently locked out. The pure rule-builders are unit-tested; the
  privileged `firewall-cmd`/`pkexec` calls need a real firewalld and root, so they
  are verified by running the binary, not in `cargo test`.
- Profile import (GUI only) runs `nmcli connection import type wireguard file
  <path>`, so NetworkManager stays the single source of truth — no local copy of
  the `.conf` is kept.
- The application binary is named **Neutron** (`neutron`) with zero runtime shared library dependencies when compiled for the musl target.

## Roadmap summary

1. MVP core: profile list + manual connect/switch
2. Random-on-boot selector service (once per boot)
3. UX hardening and failure recovery
4. Universal packaging & distribution (Homebrew, AUR, Static Musl)
5. Advanced features (provider ingestion, kill-switch helper)
