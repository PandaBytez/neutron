# NAT-PMP Dynamic Port Forwarding Engine

Neutron includes a native, pure Rust NAT-PMP (RFC 6886) client designed for WireGuard endpoints and providers that support dynamic port forwarding (such as Proton, Mullvad, and PIA).

---

## Technical Protocol Overview

NAT-PMP (Port Mapping Protocol) allows clients behind a NAT gateway to request dynamic UDP and TCP port mappings.

```text
┌──────────────┐                            ┌──────────────┐
│   Neutron    │                            │Tunnel Gateway│
│   (Client)   │                            │ (NAT Router) │
└──────┬───────┘                            └──────┬───────┘
       │                                           │
       │  1. UDP Request (Opcode 1: Map UDP)       │
       │──────────────────────────────────────────>│
       │     Internal: 0 (Request any WAN port)    │
       │     External: 0                           │
       │     Lifetime: 60 seconds                  │
       │                                           │
       │  2. UDP Response (Opcode 129: Success)    │
       │<──────────────────────────────────────────│
       │     Assigned Port: 51423                  │
       │     Lifetime: 60 seconds                  │
       │                                           │
       │  3. Auto-Renew Loop (Every 45 seconds)    │
       │──────────────────────────────────────────>│
       │     Repeats mapping request before expiry │
       │                                           │
```

---

## Gateway Derivation Logic

WireGuard profile interfaces obtain private IPv4 addresses (e.g. `10.2.0.2/32` or `100.96.0.4/32`).

Neutron derives the default NAT-PMP gateway IP automatically:
1. Extracts the primary tunnel IPv4 address via `nmcli -g ipv4.addresses connection show <uuid>`.
2. Replaces the host octet with `.1` (e.g. `10.2.0.2` $\rightarrow$ `10.2.0.1`).
3. Dispatches the NAT-PMP packet to UDP port `5351` at that gateway address.

---

## Auto-Renewal Lifecycle

Port forwarding is **off by default** — a lease is renewed on a timer against the provider's gateway, so it is never requested unless asked for. Press **`o`** in the TUI to open the Port Forwarding mode modal and pick **Disabled**, **Forward** (lease only), or **Forward + qBittorrent Sync** (lease and push to qBittorrent), or set it in `~/.config/neutron/config.toml`:

```toml
[port_forwarding]
mode = "forward-and-sync"
```

Legacy configs with the old `enabled` flags keep loading: `[port_forwarding] enabled = true` becomes `forward`, and additionally `[qbittorrent] enabled = true` becomes `forward-and-sync`.

1. **Lease Grant**: Upon receiving a success packet, the granted port number is stored in memory and displayed in the UI banner.
2. **Periodic Renewal Timer**: A background timer runs at `RENEW_INTERVAL` (every 45 seconds) to refresh the lease with the gateway.
3. **Profile Switch / Disconnect Cleanup**: When switching profiles or disconnecting, the active port is cleared immediately to prevent displaying stale mappings.
4. **Clipboard Integration**: A 1-click button in the GUI copies the forwarded port to the system clipboard for easy pasting into BitTorrent or game servers.

---

## qBittorrent Dynamic Port Sync

Neutron can automatically push the dynamic NAT-PMP port to a running **qBittorrent** instance (native package, Flatpak, Docker/Podman container, or headless server) via its official Web API (`/api/v2`).

### Setup Prerequisite (Required in qBittorrent)

Before enabling synchronization, ensure qBittorrent's Web User Interface is enabled:

1. In qBittorrent, open **Tools** $\rightarrow$ **Options** $\rightarrow$ **Web UI** (or **Preferences** $\rightarrow$ **Web UI**).
2. Check **"Web User Interface (Remote control)"** (default port: `8080`).
3. *(Recommended)* Under **Authentication**, check **"Bypass authentication for clients on localhost"**.
   - If localhost authentication bypass is not enabled, configure your WebUI username and password in Neutron via `neutron qbit config --username <user> --password <pass>`.

### Compatibility (Flatpak, Native, Containers)

- **Flatpak (`org.qbittorrent.qBittorrent`)**: Fully compatible. Because Flatpak packages share the host network stack (`--share=network`), the WebUI is reached at `http://127.0.0.1:8080`, and updated listening ports apply directly to the host socket.
- **Native Package**: Fully compatible.
- **Docker / Podman / Remote WebUI**: Fully compatible by configuring the target URL (e.g. `neutron qbit config --url http://192.168.1.50:8080`).

### CLI Management

```bash
# Check status and test WebUI connectivity
neutron qbit status

# Test WebUI credentials and fetch current listening port
neutron qbit test

# Immediately forward the active leased port to qBittorrent
neutron qbit sync

# Sync mode control (sets the [port_forwarding] policy mode)
neutron qbit enable    # forward-and-sync: lease and auto-sync
neutron qbit disable   # forward: lease only, port forwarding stays on

# Configure WebUI parameters (host, port, credentials)
neutron qbit config --url http://127.0.0.1:8080
```

### Interface Binding

A forwarded port only arrives on the tunnel's interface, so a **local** qBittorrent (any `127.0.0.1`/`localhost`/`[::1]` WebUI URL, native, Flatpak or container) is bound to it along with the port — no setting to turn on. A WebUI on **another host** is left on whatever interface it already uses, since it has no tunnel device to bind.

The URL is what decides that. For the two cases it cannot, say so explicitly:

```bash
# qBittorrent on this machine but reached at a container bridge address: bind.
neutron qbit config --url http://172.17.0.1:8080 --bind true

# A WebUI on another host that must keep its own interface: do not bind.
neutron qbit config --url http://192.168.1.50:8080 --bind false
```
