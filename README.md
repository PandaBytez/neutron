# wireguard-manager

A desktop WireGuard manager for Linux built in Rust, using NetworkManager as backend.

## Why this project

Most VPN apps are provider-specific. This project aims to provide a provider-agnostic
WireGuard management experience while keeping system networking integration through
NetworkManager.

## Planned features

- List NetworkManager WireGuard profiles.
- Manual connect/disconnect/switch between profiles.
- Mark profiles as eligible for random startup selection.
- Pick one random eligible profile once per boot.
- Optional provider config import workflow (later).
- Kill-switch oriented policy UX (later).

## Non-goals (for now)

- Managing connection lifecycle with `wg-quick` directly.
- Supporting old GNOME versions first.
- Implementing every provider API in MVP.

## Tech direction

- Language: Rust
- Desktop stack: GTK4/libadwaita
- Backend: NetworkManager (D-Bus/libnm)
- Packaging target: Flatpak / Flathub

## Project status

MVP CLI is implemented for core NetworkManager profile workflows and startup random selection logic. GTK/libadwaita desktop UI now includes profile listing, refresh, action buttons, and startup-eligibility toggles.

## Development (initial)

```bash
cargo run
```

Current CLI commands:

```bash
# list wireguard profiles and active state
cargo run -- list

# launch GUI (list + refresh + action buttons scaffold)
# (requires GTK/libadwaita dev packages)
cargo run --features gui -- gui

# connect/disconnect/switch
cargo run -- connect <profile-name>
cargo run -- disconnect
cargo run -- switch <profile-name>

# manage random-start eligibility
# (profile can be a UUID or unique profile name)
cargo run -- eligible list
cargo run -- eligible add <profile-name>
cargo run -- eligible remove <profile-name>

# run one-shot startup random selection manually
cargo run -- startup-random
```

`list` output now includes eligibility status from config (`eligible` or `not-eligible`).

GUI currently renders profile rows with active/inactive + eligibility labels, per-row action buttons (`Connect`, `Switch`, `Disconnect`) wired to NetworkManager operations, and startup-eligibility toggles backed by config; the list auto-refreshes after each change and also reacts to NetworkManager monitor events. NetworkManager calls run on a background thread so the UI stays responsive while `nmcli` works, action buttons disable until the operation finishes, and the `nmcli monitor` child process is terminated when the window closes.

`eligible add` reports when a profile is already eligible, and `eligible remove` returns a clear error when a profile is not currently eligible.

Install the optional user service for startup-random automation:

```bash
cat systemd/README.md
```

Flatpak packaging scaffold:

```bash
flatpak-builder --user --force-clean build-dir flatpak/com.example.wireguardmanager.json
flatpak-builder --run build-dir flatpak/com.example.wireguardmanager.json wireguard-manager gui
```

If `flatpak-builder` is missing, install it first (for example on Fedora:
`sudo dnf install flatpak-builder`) and rerun the commands above.

The Flatpak manifest currently requests NetworkManager D-Bus access via
`org.freedesktop.NetworkManager` (session and system bus talk names).

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

- Application config (eligible-profile pool and last random selection) is written
  atomically and, on Unix, restricted to owner-only access (`0o600`). No private
  keys or secrets are ever stored here; those remain in NetworkManager.
- All `nmcli` invocations run with a 30-second timeout and surface the command
  exit code on failure, so a stuck NetworkManager call cannot hang the CLI or GUI
  indefinitely.

## Roadmap summary

1. MVP core: profile list + manual connect/switch
2. Random-on-boot selector service (once per boot)
3. UX hardening and failure recovery
4. Flatpak packaging and Flathub preparation
5. Advanced features (provider ingestion, kill-switch helper)
