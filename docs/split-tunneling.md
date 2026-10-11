# Split Tunneling (IP & Domain Routing)

Neutron provides **Global Split Tunneling**, allowing users to specify exact subnets, IPs, and domain names that should route through or bypass the WireGuard tunnel.

---

## Routing Modes

### 1. `Include` Mode (Per-Family Destination Selection)
* **Behavior**: For each address family with a nonempty list of configured CIDRs and resolved domain IPs, only listed destinations route through the tunnel; other destinations in that family use the physical default route. An empty family retains the full-tunnel default (`never-default = no`). This is intentional, tested behavior: an IPv4-only Include list does not make IPv6 bypass the tunnel, and an entirely empty list retains both defaults.
* **NetworkManager Mechanism**:
  With nonempty lists for both families:
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
4. Invalid CIDRs or domains without a successful or retained last-known-good
   resolution prevent an enabled policy from being applied and saved, rather
   than silently applying a partial list. Entries can be stored while the mode
   is disabled; enabling it validates and resolves the list.

---

## CLI & TUI Configuration

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

### TUI Editor
Press `t` in the TUI to edit the global mode, CIDRs, and domains. See the
[usage guide](usage.md#interactive-split-tunneling-t) for editor controls and
[configuration reference](configuration.md) for `[global_split_tunnel]` settings.
