# System Architecture & Design Principles

Neutron VPN is designed with a strictly decoupled architecture where all networking, security, and state logic exist in pure Rust modules that can be driven by any UI frontend (CLI, TUI, or GUI).

---

## High-Level Architecture Diagram

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                            User Interface Layer                             │
│  ┌───────────────────────┐  ┌───────────────────────┐  ┌─────────────────┐  │
│  │     CLI (clap)        │  │     GUI (Adwaita)     │  │   TUI (ratatui) │  │
│  │ (Scripting & Headless)│  │ (GNOME Desktop Window)│  │ (Terminal UI)   │  │
│  └───────────┬───────────┘  └───────────┬───────────┘  └────────┬────────┘  │
└──────────────┼──────────────────────────┼───────────────────────┼───────────┘
               └──────────────────────────┼───────────────────────┘
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Core Decoupled Engine                            │
│  ┌─────────────────────────┐  ┌─────────────────────────┐  ┌─────────────┐  │
│  │   NetworkManager (nm/)  │  │  Firewall (firewall/)   │  │ NAT-PMP     │  │
│  │ • Profile Discovery     │  │ • Lockdown Netfilter    │  │ (portforward│  │
│  │ • Policy Kill Switch    │  │ • Surgical Teardown     │  │ • UDP Lease │  │
│  │ • Split Tunnel Routes   │  │ • pkexec Orchestration  │  │ • Auto-Renew│  │
│  └─────────────────────────┘  └─────────────────────────┘  └─────────────┘  │
│  ┌─────────────────────────┐  ┌─────────────────────────┐                   │
│  │    Config (config/)     │  │    Service (service/)   │                   │
│  │ • Atomic Persistence    │  │ • Random Boot Selector  │                   │
│  │ • Unix Mode 0600        │  │ • Autostart Unit        │                   │
│  └─────────────────────────┘  └─────────────────────────┘                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Subsystem Responsibilities

### 1. `nm/` — NetworkManager Control Plane
- Trait `NmClient` provides an abstract interface for listing, connecting, disconnecting, switching profiles, setting kill-switch properties, and applying split-tunneling routes.
- `CliNmClient` interacts with NetworkManager via `nmcli` with a strict 30-second execution deadline.
- Submodule `nm::split_tunnel` validates and normalizes CIDRs, resolves domain names to IP addresses, and formats `ipv4.routes` / `ipv6.routes` / `never-default` arguments.
- Submodule `nm::kill_switch` configures kernel policy routing (`wireguard.ip4-auto-default-route`) and negative DNS priorities (`-1500`).

### 2. `firewall/` — Always-On Lockdown Netfilter Engine
- Trait `FirewallClient` manages permanent direct `OUTPUT` chain rules in `firewalld`.
- Protects traffic while disconnected by rejecting all non-VPN traffic except loopback, established connections, DNS, tunnel interfaces, and peer handshake endpoints.
- All rules are tagged with a unique comment (`neutron-lockdown`) ensuring surgical removal without modifying user-defined firewall rules.
- Privilege escalation is consolidated into a single `pkexec /bin/sh` transaction.

### 3. `portforward/` — NAT-PMP Dynamic Port Leasing & App Integrations
- Implements RFC 6886 NAT-PMP client directly over `std::net::UdpSocket`.
- Derives the VPN gateway address from the local tunnel IPv4 address (`10.x.x.x` / `100.x.x.x`).
- Acquires dynamic UDP/TCP port mappings and schedules automatic lease renewals before expiration.
- Integrates `portforward::qbittorrent` Web API bridge to automatically synchronize dynamic listening ports to qBittorrent (native, Flatpak, containerized).

### 4. `config/` — Configuration & State Persistence
- Manages `AppConfig` serialized as JSON in `~/.config/neutron-vpn/config.json`.
- Implements atomic file writes (`fs::rename` with fallback across filesystem boundaries) with strict `0o600` permissions.
- Stores global split-tunnel rules, startup eligibility exclusions, kill-switch intent, and window geometry.

### 5. `service/` — Boot-Time Automation
- Implements the one-shot random profile selector for login / boot.
- Manages XDG desktop autostart entries (`~/.config/autostart/io.gitlab.neutron_vpn.neutron.desktop`).
- Prevents immediate profile repeats and respects user-defined eligibility exclusion sets.

---

## Frontend & Resource Comparison Matrix

| Metric | GTK4 / Libadwaita (GUI)`UNRELEASED` | Pure Rust TUI (`ratatui`) | Background Daemon / CLI | Electron / Web VPN Clients |
| :--- |:-----------------------------------:| :---: | :---: | :---: |
| **Binary Size** |   ~15–30 MB (or AppImage bundle)    | **~3–5 MB** (Static musl binary) | **~3 MB** | 150–250 MB |
| **Active RAM (RSS)** |          **~70 – 110 MB**           | **~10 – 15 MB** | **~3 – 6 MB** | 250 – 450 MB |
| **Idle CPU Usage** |             0.1% – 0.5%             | **0.0%** (sleeps on `epoll`) | **0.0%** | 0.5% – 2.0% |
| **Startup Time** |             ~150–300 ms             | **< 10 ms** (instantaneous) | **< 2 ms** | 1.5 – 3.0 seconds |
| **System Dependencies** |   GTK4, Libadwaita, Mesa/Wayland    | **Zero** (100% static musl) | **Zero** | Node, Chromium, X11/Wayland |
| **Primary Environments** |     GNOME Desktop Workstations      | Servers, SSH, Hyprland, Sway, i3 | Automation, Cron, Systemd | Legacy Cross-Platform |
| **Distribution Channels** |      AppImage, Distro Packages      | Homebrew, Cargo, AUR, Static Musl | Homebrew, System Package | Custom Installers |
