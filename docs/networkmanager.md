# NetworkManager Integration

Neutron relies on **NetworkManager** as the source of truth for all WireGuard network configurations.

The NetworkManager daemon and `nmcli` must both be **1.52+** with
`ipv4.routed-dns` and `ipv6.routed-dns` support. Checked preparation reads back
both selected values: `no` for kill-protected profiles, `yes` for unprotected
profiles. Failure or a discarded value refuses activation. A newer CLI alone
is not sufficient; `routed-dns=yes` alone is not a DNS protection guarantee.

Kill-protected profiles disable automatic DNS route processing and append
explicit NM-managed resolver `/32` and `/128` routes (metric 5, main table 254).
These merge with split routes without replacing defaults, including resolver
addresses explicitly excluded from ordinary tunnel traffic. After activation
and active-device reapply, iproute2's `ip` performs JSON kernel route lookups for
each resolver's UDP and TCP port-53 egress. The selected device must be the
tunnel. Verification failure attempts disconnection and returns an error,
including any teardown failure; this checks routes, not DNS packet delivery.

---

## Why NetworkManager?

Direct usage of `wg-quick` creates ad-hoc network interfaces and routing tables outside the system networking daemon, often causing conflicts with system DNS (`systemd-resolved`), connection reconnects, Wi-Fi switching, and desktop status integration.

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
NetworkManager command helpers use `process::run_with_timeout` with a **30-second deadline** (`NMCLI_TIMEOUT`). The long-lived `nmcli monitor` process is managed separately.
* Standard output and standard error pipes are drained concurrently on separate worker threads to prevent pipe buffer deadlocks.
* If a command exceeds the deadline, the child process is terminated and an explicit `AppError::CommandFailed` error is returned. Failed commands surface their exit status.
* Displayed errors and untrusted output escape control characters, line separators,
  and bidirectional controls so profile names or command stderr cannot inject
  terminal control sequences. Command arguments themselves are not rewritten.

### 3. Error Aggregation (`apply_to_every_profile`)
Autoconnect normalization processes every profile and aggregates failures. Other policy sweeps can stop on a failure and leave mixed profile settings; callers report that possible partial state. See [Implementation Notes](implementation.md#saved-intent-and-effective-policy).

### 4. WireGuard Comment Ingestion
When importing `.conf` files via `nmcli connection import type wireguard file <path>`, comments inside the `[Interface]` section (often containing provider metadata, server features, or notes) are extracted and saved in `profile-info.json` beside the application settings, keyed by profile UUID. `AppConfig.profile_custom_info` remains the in-memory view used by the CLI and TUI.
