# User Configuration & Theming (`config.toml`)

Neutron VPN uses a human-readable, self-documenting **TOML** configuration file located at `~/.config/neutron-vpn/config.toml`.

---

## Configuration File Schema

```toml
# ==============================================================================
# Neutron VPN Configuration (~/.config/neutron-vpn/config.toml)
# ==============================================================================

[general]
# Directory monitored for WireGuard .conf files.
# Dropping, copying, or git-cloning profiles here automatically imports them to NetworkManager.
profiles_dir = "~/.config/neutron-vpn/profiles"

# Automatically import new/updated .conf files from profiles_dir on launch
auto_sync_profiles = true

# Connect a random eligible profile when logging in
autoconnect_at_login = true

# Default interface when launching `neutron-vpn` with no arguments: "tui" or "gui"
default_ui = "tui"

# ==============================================================================
# Security & Routing Policies
# ==============================================================================
[security]
# NetworkManager policy routing (drops traffic if tunnel fails; exclusive DNS priority)
kill_switch = false

# Always-on Netfilter firewall via firewalld (blocks non-VPN traffic even when disconnected)
lockdown = false

# ==============================================================================
# Global Split Tunneling
# ==============================================================================
[split_tunnel]
# Routing mode: "disabled", "include" (route only listed), or "exclude" (bypass listed)
mode = "include"

# Custom IP subnets (CIDRs) or single host IPs
cidrs = [
    "10.0.0.0/8",
    "192.168.10.0/24",
    "172.16.0.0/12",
]

# Domain names resolved dynamically at connection time
domains = [
    "internal.corp",
    "homelab.local",
]

# ==============================================================================
# Startup Random Profile Selection Pool
# ==============================================================================
[startup_pool]
# List of profile names or UUIDs excluded from random selection (opt-out model)
excluded_profiles = [
    "backup-slow-server",
    "emergency-profile",
]

# ==============================================================================
# Terminal User Interface (TUI) & Theming
# ==============================================================================
[tui]
# Telemetry polling rate in milliseconds (handshake, transfer counters)
refresh_interval_ms = 1000

# Built-in theme preset: "adwaita", "catppuccin", "nord", "dracula", "gruvbox", "monochrome"
theme = "adwaita"

# Optional custom color overrides (accepts hex #rrggbb or standard color names)
[tui.colors]
active_border = "#3584e4"
status_connected = "#2ec27e"
status_disconnected = "#e01b24"
transfer_rx = "#62a0ea"
transfer_tx = "#ffa348"
```

---

## Theming Engine

Neutron VPN features a built-in terminal theme engine with 6 carefully calibrated color palettes:

| Theme | Description | Accent Colors | Best For |
| :--- | :--- | :--- | :--- |
| **`adwaita` (Default)** | Matches GNOME / Libadwaita dark palette | GNOME Blue, Emerald, Coral | Standard GNOME desktop integration |
| **`catppuccin`** | Soothing pastel palette (Mocha & Latte) | Mauve, Sapphire, Peach | Modern terminal setups |
| **`nord`** | Arctic, north-bluish clean palette | Frost Cyan, Polar Night Gray | Minimalist dark setups |
| **`dracula`** | Famous high-contrast vibrant theme | Gothic Purple, Pink, Green | High-contrast readability |
| **`gruvbox`** | Retro groove warm earthy palette | Warm Amber, Forest Green | Tiling window managers & vim users |
| **`monochrome`** | High-compatibility black & white | High-contrast ASCII/ANSI | Minimal TTYs, serial consoles, 16-color terms |

---

## Managed Profile Drop Directory (`profiles/`)

Neutron VPN manages a dedicated profile drop directory at `~/.config/neutron-vpn/profiles/` (with strict `0700` user-only permissions).

### Workflow:
1. **Drop / Copy Profiles**: Users can simply copy `.conf` files into the directory:
   ```bash
   cp ~/Downloads/VPN_configs/*.conf ~/.config/neutron-vpn/profiles/
   ```
2. **Auto-Sync on Launch**: Whenever the TUI or CLI runs, Neutron VPN scans the folder, compares content checksums against NetworkManager, and batch-imports new profiles in milliseconds.
3. **Manual Sync Command**: You can trigger an instant sync via CLI or within the TUI:
   ```bash
   neutron-vpn sync
   ```
4. **Git/Dotfiles Automation**: The entire `~/.config/neutron-vpn/` folder can be tracked in a private Git repository for instant syncing across multiple machines.
