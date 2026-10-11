# Usage Guide (TUI & CLI)

Neutron provides both an interactive, full-featured Terminal User Interface (TUI) and a comprehensive, scriptable Command-Line Interface (CLI).

---

## 1. Interactive Terminal User Interface (TUI)

The TUI is the primary, most user-friendly way to interact with Neutron. It provides real-time telemetry, zero-latency profile browsing, interactive security toggles, and live configuration management.

### Starting the TUI

Launch the TUI simply by running:

```bash
neutron
# or explicitly:
neutron tui
```

![Neutron TUI - Active WireGuard Connection](screenshots/Neutron-Connected.png)

### TUI Screen Layout

* **Header (Top):**
  * **Status Panel:** Live active profile, connection indicator, public IP, ping latency, download/upload throughput rates (`/proc/net/dev`), and active NAT-PMP forwarded port.
  * **Policies Panel:** Real-time status pills for Kill Switch, Lockdown Firewall, Split Tunneling, Port Forwarding mode (Off / ON / Auto-Sync to qBittorrent), and Auto-Connect at login.
* **Main Body:**
  * **Left (Profile Browser):** Lists all NetworkManager WireGuard profiles with active checkmarks (`●`), favorite stars (`★`), and pool exclusion badges (`⊘`).
  * **Right (Details Pane):** Full connection diagnostics including remote peer endpoint, allowed IPs, latest handshake age, cumulative RX/TX transfer counters, persistent keepalive, and assigned interface IP.
* **Footer:** Quick keybinding shortcuts and status messages.

---

### TUI Keybindings

Every action below is also searchable by name from the **Command Palette** (`Ctrl+P` or `:`).

| Key | Action | Description |
| :--- | :--- | :--- |
| `↑` / `↓` (or `p` / `n`) | **Navigate** | Move cursor up / down through the profile list |
| `Space` / `Enter` | **Connect / Disconnect** | Connect to the selected profile, or disconnect if already active |
| `s` | **Switch Profile** | Instantly switch active tunnel to the selected profile |
| `f` | **Toggle Favorite** | Star/unstar profile for quick tray indicator access |
| `e` | **Toggle Eligibility Pool** | Include or exclude selected profile from random boot connection pool |
| `a` | **Auto-Connect at Login** | Toggle automated random profile connection on login |
| `t` | **Split Tunneling** | Open interactive Split Tunneling manager (Domains & Subnets) |
| `k` | **Kill Switch** | Toggle NetworkManager-native routing kill switch |
| `l` | **Lockdown Mode** | Toggle always-on Netfilter firewall (requires `pkexec` root) |
| `o` | **Port Forwarding** | Open the Port Forwarding mode modal (Off / Forward / Forward + qBittorrent Sync) |
| `r` | **Sync Drop Directory** | Scan `~/.config/neutron/profiles/` and batch-import new `.conf` files |
| `d` / `Delete` | **Delete Profile** | Permanently remove selected profile from NetworkManager (with confirmation) |
| `Ctrl+P` / `:` | **Command Palette** | Searchable fuzzy popup for all commands and actions |
| `Ctrl+T` | **Theme Picker** | Switch themes live (`nord`, `osaka-jade`, `catppuccin`, `gruvbox`, `monochrome`) |
| `?` / `h` | **Help** | Display keybindings help modal |
| `q` / `Esc` | **Quit** | Exit the TUI cleanly |

---

### Interactive Split Tunneling (`t`)

Pressing **`t`** opens the side-by-side Split Tunneling manager:

* **Mode Selector (Top):** Use `←` / `→` to move between `[ Disabled ]`, `[ Include ]`, and `[ Exclude ]`, and `Space`/`Enter` to activate.
* **Domains (Left Column):** Type a domain (e.g. `github.com`) into the `+ Add Domain` box and press `Enter`.
* **Subnets / CIDRs (Right Column):** Type an IPv4/IPv6 CIDR (e.g. `10.0.0.0/8` or `192.168.1.0/24`) and press `Enter`.
* **Navigation:** `Tab` cycles between Mode, Domains, and Subnets. Arrow keys (`←`, `→`, `↑`, `↓`) navigate between panels and list items.
* **Deletion:** Select any entry in the list and press `Del` or `x`.
* **Non-Blocking Apply:** Changes are submitted in the background. Backend or save failures are reported; saved profile routing changes require reconnect.
* **Concurrent Edits:** If the captured split-settings snapshot conflicts with another writer, saving is rejected. Reload current settings before resubmitting, rather than retrying a stale snapshot.
* **Lockdown Notice:** If the Lockdown Firewall is active, a clear banner reminds you that all non-tunnel traffic is dropped when disconnected.

Include mode is evaluated per address family: only a family with a nonempty
destination list routes just those destinations through the tunnel. An empty
family retains default-route eligibility, which still requires a usable tunnel
family and matching peer AllowedIPs. This does not protect unsupported IPv6. See
[routing modes](split-tunneling.md#routing-modes).

---

### Command Palette (`Ctrl+P` or `:`)

Press **`Ctrl+P`** or **`:`** to open the Command Palette. Type any keyword (e.g. "kill", "split", "theme", "sync") to filter actions, then press `Enter` to execute.

---

### Theme Picker (`Ctrl+T`)

Press **`Ctrl+T`** to switch between calibrated color palettes live without restarting the app:

![Neutron Interactive Theme Picker](screenshots/Neutron-Themes.png)

---

## 2. Command Line Interface (CLI)

All operations can also be run directly from terminal commands or shell scripts.

### Profile Connections & Status

```bash
# List all WireGuard profiles with active status and eligibility
neutron list

# Connect to a profile by name or UUID
neutron connect "Home-Server"

# Switch connection directly to another profile
neutron switch "Work-VPN"

# Disconnect active tunnel
neutron disconnect
```

### Profile Ingestion & Drop Directory

```bash
# Batch-import new or updated *.conf files from ~/.config/neutron/profiles/
neutron sync

# Manage random-on-boot eligibility pool
neutron eligible list
neutron eligible add "Home-Server"
neutron eligible remove "Test-Server"
```

### Global Split Tunneling

```bash
# Check current split tunneling status and active routes
neutron split-tunnel status

# Set routing mode
neutron split-tunnel set-mode include
neutron split-tunnel set-mode exclude
neutron split-tunnel set-mode disabled

# Add destination subnets or domains
neutron split-tunnel add-cidr 10.0.0.0/8
neutron split-tunnel add-cidr 192.168.1.0/24
neutron split-tunnel add-domain internal.corp
neutron split-tunnel add-domain gitlab.company.com

# Remove destinations
neutron split-tunnel remove-cidr 10.0.0.0/8
neutron split-tunnel remove-domain internal.corp

# Clear all split tunnel routes
neutron split-tunnel clear
```

### Security & Firewalls

```bash
# Inspect or toggle NetworkManager-native routing kill switch
neutron kill-switch status
neutron kill-switch enable
neutron kill-switch disable

# Inspect or toggle always-on Netfilter lockdown firewall (requires polkit/pkexec)
neutron lockdown status
neutron lockdown enable
neutron lockdown disable
```

`enable` and `disable` escalate and rewrite the ruleset, so they show a spinner
while waiting on authentication and firewalld. Piped output gets a plain
`Enabling Lockdown...` line instead.

Helper refreshes also require fresh `auth_admin`, not a password-free grant.
Automatic connections, switching, login selection, and reconciliation may prompt;
headless denial fails closed and a required pre-activation refresh failure stops
activation. After upgrading an existing install, authenticate with
`neutron lockdown enable` to replace its old grant. Disable retains only hardened
authorization and revokes unsafe grants, including mixed actions and legacy rules.
NetworkManager and `nmcli` 1.52+ and iproute2's `ip` are required. Protected DNS
disables automatic routed-DNS processing and merges explicit resolver host routes
in main table 254, even for exclusions. After activation/reapply, kernel UDP/TCP
DNS egress is checked; failure attempts disconnection and returns an error.
Without lockdown, kill protection refuses unsupported IP
families and unsplit profiles lacking both `0.0.0.0/0` and `::/0` AllowedIPs.
Explicit split bypasses remain intentional. See [security](security.md).

### Factory Reset

```bash
# Withdraw every applied policy and clear all settings (asks for confirmation)
neutron reset

# Unattended
neutron reset --yes
```

Restores a first-run state: the lockdown ruleset, refresh helper, and polkit
action are revoked, the kill switch and split-tunnel routes are withdrawn from
every profile, settings (including the qBittorrent password) go back to
defaults, and the autostart entry is removed. The profile drop directory is
reported and left alone, since it holds your own files. Requires a terminal to
confirm, or `--yes`.

### Uninstalling

```bash
# Revoke everything outside the package, then remove the package itself
neutron uninstall

# Also delete ~/.config/neutron (settings, eligibility, qBittorrent password)
neutron uninstall --purge
```

Run it as your normal user, not under `sudo`: the polkit prompt needs an active
session, and Homebrew refuses to run as root. Neutron detects whether it was
installed by Homebrew or `cargo install` and runs the matching removal. It stops
the tray daemon, deletes the autostart entry, and -- in one privileged batch, and
only if any lockdown state is present -- lifts the firewall rules and revokes the
authenticated refresh helper and action. Settings are kept unless `--purge` is given. An unrecognized install is refused without changing anything; see
[security.md](security.md#uninstalling-revokes-everything-it-installed).

### NAT-PMP & qBittorrent Dynamic Port Sync

```bash
# Check qBittorrent integration status, WebUI connectivity, and active ports
neutron qbit status

# Test connection to qBittorrent WebUI
neutron qbit test

# Immediately sync active NAT-PMP port to qBittorrent
neutron qbit sync

# Enable / disable automated sync (sets the [port_forwarding] policy mode;
# disable keeps port forwarding on and only stops the qBittorrent sync)
neutron qbit enable    # forward-and-sync
neutron qbit disable   # forward

# Configure WebUI connection parameters (--bind forces interface binding on/off)
neutron qbit config --url http://127.0.0.1:8080

# Read the first password line from an existing owner-only file (0600)
neutron qbit config --username admin --password-stdin < /path/to/protected-password
```

`--password` is not supported. `--password-stdin` rejects terminal input before
reading so the password is not echoed. Use protected redirection or a secret
manager pipe, not a literal secret in command arguments or shell history. An
empty line clears the saved password; EOF without a line is rejected.

In the TUI, use the Command Palette's qBittorrent sync action for a manual push.
It runs in the background using a snapshot of the daemon's leased port and profile
UUID. A pending indicator remains until completion; success or failure appears in
the status message without changing the daemon's automatic-sync badge verdict.
Without an active published lease, the action reports that no port is available.

For headless renewal and missing `XDG_RUNTIME_DIR` behavior, see the
[port-forwarding lifecycle](port-forwarding.md#auto-renewal-lifecycle).

### System Tray AppIndicator & Background Daemon

Neutron includes a pure-Rust D-Bus `StatusNotifierItem` and `DBusMenu` system tray indicator (`src/service/indicator.rs` via `zbus`) that monitors link health and provides quick desktop controls:

![Neutron System Tray AppIndicator](screenshots/Neutron-Tray.png)

```bash
# Run persistent D-Bus system tray AppIndicator daemon
neutron indicator

# Terminate running background instances and launch fresh session
neutron restart

# Run one-shot random profile connection (used by boot/login automation)
neutron startup-random
```
