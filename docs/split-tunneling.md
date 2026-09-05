# Split Tunneling (IP & Domain Routing)

Neutron provides **Global Split Tunneling**, allowing users to specify exact subnets, IPs, and domain names that should route through or bypass the WireGuard tunnel.

---

## Routing Modes

### 1. `Include` Mode (Route Only Listed Destinations via Tunnel)
* **Behavior**: Default internet browsing bypasses the tunnel over your physical interface, while only specified subnets and domain IPs are routed securely through the WireGuard tunnel.
* **NetworkManager Mechanism**:
  ```bash
  nmcli connection modify <uuid> \
      ipv4.never-default yes \
      ipv6.never-default yes \
      ipv4.routes "10.0.0.0/8, 192.168.10.0/24" \
      ipv6.routes "2001:db8::/32"
  ```
* **Use Case**: Remote network access where corporate/homelab subnets must route through the WireGuard tunnel while streaming, gaming, and personal browsing remain on high-speed unthrottled physical internet.

### 2. `Exclude` Mode (Bypass Tunnel for Listed Destinations)
* **Behavior**: All general traffic routes through the encrypted WireGuard tunnel, while specified subnets or domains bypass the tunnel directly to your local physical gateway.
* **NetworkManager Mechanism**: `never-default = yes` with the **complement** of the listed destinations installed as tunnel routes.

  Adding an excluded range to `ipv4.routes` would route it *into* the tunnel — the opposite of excluding it. There is no "bypass route" to install, because every route on a WireGuard connection points at the WireGuard device. So Neutron inverts the selection instead: it computes every CIDR *except* the listed ones and routes those through the tunnel, leaving the excluded ranges to the physical default route.

  Excluding `10.0.0.0/8` therefore produces:
  ```bash
  nmcli connection modify <uuid> \
      ipv4.never-default yes \
      ipv6.never-default yes \
      ipv4.routes "0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, ..." \
      ipv6.routes "::/0"
  ```
  The complement is computed by `nm::split_tunnel::complement_routes`, which recursively splits the address space into the smallest set of aligned CIDRs that covers everything but the exclusions. Excluding nothing yields a full tunnel (`0.0.0.0/0`); excluding `0.0.0.0/0` yields no routes at all.
* **Use Case**: Privacy browsing with exclusions for local services, banking portals, or gaming servers that block remote tunnel endpoints.

### 3. `Disabled` Mode (Standard Full-Tunnel)
* Restores `never-default = no` and clears all custom static routes.

---

## Route Normalization & Dynamic DNS

### 1. CIDR Normalization
Input routes are parsed and normalized into standard CIDR format:
* Single IPv4 `192.168.1.50` $\rightarrow$ `192.168.1.50/32`
* Single IPv6 `::1` $\rightarrow$ `::1/128`
* Subnets `10.0.0.0/8` $\rightarrow$ `10.0.0.0/8`
* Routes are partitioned into `ipv4.routes` and `ipv6.routes` automatically.

### 2. Client-Side Domain Resolution
For domain entries (e.g., `internal.corp`, `service.local`):
1. The domain is resolved via `std::net::ToSocketAddrs` to all associated IPv4 (`/32`) and IPv6 (`/128`) literals.
2. Resolved IPs are merged with configured CIDRs before applying route arguments to NetworkManager.
3. Resolution is performed in the background during connection or rule modification.

---

## CLI & GUI Configuration

### CLI Commands
```bash
# Check status
neutron split-tunnel status

# Set routing mode
neutron split-tunnel set-mode include
neutron split-tunnel set-mode exclude
neutron split-tunnel set-mode disabled

# Manage CIDRs & Domains
neutron split-tunnel add-cidr 10.0.0.0/8
neutron split-tunnel remove-cidr 10.0.0.0/8
neutron split-tunnel add-domain internal.corp
neutron split-tunnel remove-domain internal.corp

# Clear all rules
neutron split-tunnel clear
```

### GUI Dialog
Available in the **Settings** section of the GUI main window:
* Clean mode selector dropdown (`Disabled`, `Include`, `Exclude`).
* Interactive list editors for CIDRs and Domain names with inline syntax validation.
* Real-time subtitle updates reflecting active rules.
