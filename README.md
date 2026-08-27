# Neutron VPN

A desktop WireGuard manager for Linux built in Rust, using NetworkManager as backend.
Branded as **Neutron VPN** (`io.gitlab.neutron_vpn.neutron`), packaged and distributed as an **AppImage**.

## Why this project

Most VPN apps are provider-specific. This project aims to provide a provider-agnostic
WireGuard management experience while keeping system networking integration through
NetworkManager.

## Planned features

- List NetworkManager WireGuard profiles.
- Manual connect/disconnect/switch between profiles.
- Exclude individual profiles from random startup selection (opt-out: every profile is eligible by default).
- Pick one random eligible profile once per boot.
- Import WireGuard `.conf` profiles through the GUI (provider API import planned later).
- Global kill-switch policy applied to all profiles (NetworkManager-native routing).
- Optional always-on lockdown firewall that blocks all non-VPN traffic, even while disconnected.

## Non-goals (for now)

- Managing connection lifecycle with `wg-quick` directly.
- Supporting old GNOME versions first.
- Implementing every provider API in MVP.

## Tech direction

- Language: Rust
- Desktop stack: GTK4/libadwaita
- Backend: NetworkManager (D-Bus/libnm)
- Packaging target: AppImage

## Project status

MVP CLI is implemented for core NetworkManager profile workflows and startup random selection logic. GTK/libadwaita desktop UI now includes profile listing, refresh, a per-profile connection toggle, startup-eligibility toggles, a single global kill-switch toggle, an always-on lockdown-firewall toggle, and an Import button for adding WireGuard `.conf` profiles. The window remembers its last size between launches.

## Development (initial)

```bash
cargo run
```

Current CLI commands:

```bash
# list wireguard profiles and active state
cargo run -- list

# launch GUI (list + refresh + connection/kill-switch/lockdown toggles + import)
# (requires GTK/libadwaita dev packages)
cargo run --features gui -- gui

# connect/disconnect/switch
cargo run -- connect <profile-name>
cargo run -- disconnect
cargo run -- switch <profile-name>

# manage random-start eligibility (opt-out: every profile is eligible by default)
# (profile can be a UUID or unique profile name)
cargo run -- eligible list                  # show profiles excluded from random startup
cargo run -- eligible add <profile-name>    # make a profile eligible again (clear its exclusion)
cargo run -- eligible remove <profile-name> # exclude a profile from random startup

# run one-shot startup random selection manually
cargo run -- startup-random

# inspect or toggle the global kill switch
# (applies to every WireGuard profile at once)
cargo run -- kill-switch status
cargo run -- kill-switch enable
cargo run -- kill-switch disable

# inspect or toggle the always-on lockdown firewall
# (blocks all non-VPN traffic, even while disconnected; uses pkexec + firewalld)
cargo run -- lockdown status
cargo run -- lockdown enable
cargo run -- lockdown disable
```

`list` output now includes eligibility status from config (`eligible` or `not-eligible`). Profiles are eligible by default and become `not-eligible` only once explicitly excluded.

GUI currently renders each profile row with just the profile name, a startup-eligibility toggle (checked by default, since every profile is eligible until excluded), and a per-row connection toggle (a switch that activates the tunnel when turned on and disconnects it when turned off) wired to NetworkManager operations, alongside a single global kill-switch toggle and an always-on lockdown-firewall toggle; enabling either the kill switch or lockdown also raises a desktop notification. An Import button opens a file chooser to add a WireGuard `.conf` as a new NetworkManager profile, after which the list refreshes automatically. The list auto-refreshes after each change and also reacts to NetworkManager monitor events. NetworkManager and firewall calls run on a background thread so the UI stays responsive while `nmcli`/`firewall-cmd` work, toggles disable until the operation finishes and revert on failure, and the `nmcli monitor` child process is terminated when the window closes, which also persists the current window size.

`eligible add` clears a profile's exclusion (reporting when it was already eligible), and `eligible remove` excludes a profile from random startup (reporting when it was already excluded).

Install the optional user service for startup-random automation:

```bash
cat systemd/README.md
```

AppImage packaging:

To build the standalone AppImage:

```bash
./appimage/build-appimage.sh
```

This compiles the release binary and packages it into `Neutron-VPN-<arch>.AppImage`. You can then run it directly:

```bash
./Neutron-VPN-x86_64.AppImage
```

Quality checks:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Run only integration tests:

```bash
cargo test --test startup_random
```

Run all tests without optional GUI feature:

```bash
cargo test
```

Run checks with optional GUI feature (requires GTK/libadwaita dev packages installed):

```bash
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
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
- Packaging is AppImage ready, and the desktop entry and AppStream
  metainfo validate cleanly (`desktop-file-validate`, `appstreamcli validate`).
  The application is named **Neutron VPN** (`neutron-vpn`).

## Roadmap summary

1. MVP core: profile list + manual connect/switch
2. Random-on-boot selector service (once per boot)
3. UX hardening and failure recovery
4. AppImage packaging
5. Advanced features (provider ingestion, kill-switch helper)
