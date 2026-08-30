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

# Built-in theme preset: "osaka-jade" (default), "catppuccin", "nord", "gruvbox", "monochrome"
theme = "osaka-jade"

# Optional custom color overrides (accepts hex #rrggbb or standard color names)
[tui.colors]
active_border = "#2dd5b7"
status_connected = "#63b07a"
status_disconnected = "#ff5345"
transfer_rx = "#acd4cf"
transfer_tx = "#e5c736"

# ==============================================================================
# Port Forwarding (NAT-PMP)
# ==============================================================================
[port_forwarding]
# Lease an incoming port from the VPN gateway and keep renewing it.
# Also togglable live from the TUI with `f`. Off by default: the lease is
# renewed on a timer against the provider, so it is only requested on request.
enabled = false

# ==============================================================================
# qBittorrent Dynamic Port Forwarding Sync
# ==============================================================================
[qbittorrent]
# Automatically push NAT-PMP leased ports to qBittorrent WebUI on connect/renew
enabled = false

# WebUI HTTP/HTTPS endpoint URL
url = "http://127.0.0.1:8080"

# Optional authentication (leave empty if localhost auth bypass is enabled in qBittorrent)
# username = "admin"
# password = "your-webui-password"

# Bind qBittorrent network interface to the active WireGuard interface
bind_interface = false
```

---

## Theming Engine

Neutron features a built-in terminal theme engine with 5 carefully calibrated color palettes:

| Theme | Description | Accent Colors | Best For |
| :--- | :--- | :--- | :--- |
| **`osaka-jade` (Default)** | Osaka Jade / Bamboo palette | Jade Cyan, Bamboo Green, Gold | Dark forest green aesthetic |
| **`catppuccin`** | Soothing pastel palette (Mocha) | Mauve, Sapphire, Peach | Modern terminal setups |
| **`nord`** | Arctic, north-bluish clean palette | Frost Cyan, Polar Night Gray | Minimalist dark setups |
| **`gruvbox`** | Retro groove warm earthy palette | Warm Amber, Forest Green | Tiling window managers & vim users |
| **`monochrome`** | High-compatibility black & white | High-contrast ASCII/ANSI | Minimal TTYs, serial consoles, 16-color terms |

---

## Managed Profile Drop Directory (`profiles/`)

Neutron manages a dedicated profile drop directory at `~/.config/neutron/profiles/` (with strict `0700` user-only permissions).

### Workflow:
1. **Drop / Copy Profiles**: Users can simply copy `.conf` files into the directory:
   ```bash
   cp ~/Downloads/VPN_configs/*.conf ~/.config/neutron/profiles/
   ```
2. **Auto-Sync on Launch**: Whenever the TUI or CLI runs, Neutron scans the folder, compares content checksums against NetworkManager, and batch-imports new profiles in milliseconds.
3. **Manual Sync Command**: You can trigger an instant sync via CLI or within the TUI:
   ```bash
   neutron sync
   ```
4. **Git/Dotfiles Automation**: The entire `~/.config/neutron/` folder can be tracked in a private Git repository for instant syncing across multiple machines.
