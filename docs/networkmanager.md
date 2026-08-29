# NetworkManager Integration

Neutron VPN relies on **NetworkManager** as the source of truth for all WireGuard network configurations.

---

## Why NetworkManager?

Direct usage of `wg-quick` creates ad-hoc network interfaces and routing tables outside the system networking daemon, often causing conflicts with system DNS (`systemd-resolved`), VPN reconnects, Wi-Fi switching, and desktop status integration.

By integrating directly with NetworkManager:
1. **System Consistency**: Profiles integrate cleanly with GNOME Shell, desktop networking indicators, and D-Bus network monitors.
2. **Key Security**: Private keys remain stored securely within NetworkManager profile storage (`/etc/NetworkManager/system-connections/`) rather than an unencrypted app database.
3. **Hardware & Power Management**: Sleep, resume, and interface roaming are handled natively by the Linux kernel and NetworkManager daemon.

---

## Technical Details & Command Flow

### 1. Profile Discovery
Profiles of type `wireguard` are enumerated via:
```bash
nmcli -t -f NAME,UUID,TYPE connection show
nmcli -t -f NAME,UUID,TYPE connection show --active
```
The output is parsed into `WireguardProfile` structs with active/inactive states.

### 2. Timeouts & Concurrency
All `nmcli` invocations run through `run_command_with_timeout` with a strict **30-second deadline** (`NMCLI_TIMEOUT`).
* Standard output and standard error pipes are drained concurrently on separate worker threads to prevent pipe buffer deadlocks.
* If a command exceeds the deadline, the child process is terminated and an explicit `AppError::NmCommandFailed` error is returned.

### 3. Error Aggregation (`apply_to_every_profile`)
When modifying global settings across all profiles (such as setting `connection.autoconnect` or applying split-tunneling routes), the sweep does not abort on the first failure. It processes every profile, collects all failures, and surfaces an aggregated report (e.g. `1 of 5 profiles rejected the change: ...`).

### 4. WireGuard Comment Ingestion
When importing `.conf` files via `nmcli connection import type wireguard file <path>`, comments inside the `[Interface]` section (often containing provider metadata, server features, or notes) are extracted and saved in `AppConfig.profile_custom_info` keyed by profile UUID.
