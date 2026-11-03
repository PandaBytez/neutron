# Split Tunneling (IP & Domain Routing)

Neutron provides **Global Split Tunneling**, allowing users to specify exact subnets, IPs, and domain names that should route through or bypass the WireGuard tunnel.

---

## Routing Modes

Enabled modes put split routes in Neutron's table `1313166676` and set the
WireGuard `fwmark` to the same value (`0x4e455554` in nmcli's hexadecimal syntax).
An NM-managed `not fwmark` rule at priority `30000` checks specific split routes
before NetworkManager's automatic main-table lookup. This lets an included host
override an overlapping physical subnet without capturing encrypted VPN transport.
The early lookup suppresses `/0` routes; full-family defaults retain NetworkManager's
normal routing behavior. Keeping broad split routes out of the main table prevents
them from routing the VPN endpoint back into its own tunnel and breaking all traffic,
including DNS. Policy updates remove and re-add only Neutron's exact routing rule,
preserving foreign rules.

### 1. `Include` Mode (Per-Family Destination Selection)
* **Behavior**: For each address family with a nonempty list of configured CIDRs and resolved domain IPs, only listed destinations route through the tunnel; other destinations in that family use the physical default route. An empty family retains default-route eligibility (`never-default = no`), not a guarantee of protection: it still needs a usable tunnel family and matching peer AllowedIPs. An IPv4-only Include list does not intentionally exclude IPv6, but cannot make an unsupported IPv6 family safe.
* **NetworkManager Mechanism**:
  With nonempty lists for both families:
  ```bash
  nmcli connection modify <uuid> \
      wireguard.fwmark 0x4e455554 \
      ipv4.never-default yes \
      ipv6.never-default yes \
      ipv4.routes "10.0.0.0/8 table=1313166676, 192.168.10.0/24 table=1313166676" \
      ipv6.routes "2001:db8::/32 table=1313166676" \
      +ipv4.routing-rules "priority 30000 not fwmark 0x4e455554 table 1313166676 suppress_prefixlength 0" \
      +ipv6.routing-rules "priority 30000 not fwmark 0x4e455554 table 1313166676 suppress_prefixlength 0"
  ```
* **Use Case**: Remote network access where corporate/homelab subnets must route through the WireGuard tunnel while streaming, gaming, and personal browsing remain on high-speed unthrottled physical internet.

### 2. `Exclude` Mode (Bypass Tunnel for Listed Destinations)
* **Behavior**: The complement of listed destinations routes through the tunnel where its IP families and peer AllowedIPs support it; listed destinations intentionally bypass to the physical gateway. This is not a guarantee for unsupported families.
* **NetworkManager Mechanism**: The **complement** of the listed destinations is installed as tunnel routes. `never-default = yes` suppresses peer defaults for a split or fully excluded family; a family without exclusions uses `no` so its full-tunnel `/0` route is not discarded.

  Adding an excluded range to `ipv4.routes` would route it *into* the tunnel — the opposite of excluding it. There is no "bypass route" to install, because every route on a WireGuard connection points at the WireGuard device. So Neutron inverts the selection instead: it computes every CIDR *except* the listed ones and routes those through the tunnel, leaving the excluded ranges to the physical default route.

  Excluding `10.0.0.0/8` therefore produces:
  ```bash
  nmcli connection modify <uuid> \
      wireguard.fwmark 0x4e455554 \
      ipv4.never-default yes \
      ipv6.never-default no \
      ipv4.routes "0.0.0.0/5 table=1313166676, 8.0.0.0/7 table=1313166676, ..." \
      ipv6.routes "::/0 table=1313166676" \
      +ipv4.routing-rules "priority 30000 not fwmark 0x4e455554 table 1313166676 suppress_prefixlength 0" \
      +ipv6.routing-rules "priority 30000 not fwmark 0x4e455554 table 1313166676 suppress_prefixlength 0"
  ```
  The complement is computed by `nm::split_tunnel::complement_routes`, which recursively splits the address space into the smallest set of aligned CIDRs that covers everything but the exclusions. Excluding nothing yields a full tunnel (`0.0.0.0/0`); excluding `0.0.0.0/0` yields no routes at all.
* **Use Case**: Privacy browsing with exclusions for local services, banking portals, or gaming servers that block remote tunnel endpoints.

### 3. `Disabled` Mode (Standard Full-Tunnel)
* Restores `never-default = no` and clears stale split routes, then merges the
  explicit resolver host routes required by kill-protected profiles.
* Removes Neutron's early split lookup rules without clearing foreign rules.
* Resets `fwmark` to `0` only when its current value is Neutron's reserved
  `0x4e455554` mark. Other custom marks are preserved during activation, import,
  and policy sweeps.

Changing to disabled applies stale-route cleanup before saving. Every activation
also clears stale split properties when the saved mode is disabled. Default-route
eligibility alone does not establish full-family protection.

Explicit Include/Exclude bypasses are intentional even with the kill switch.
Without lockdown, kill protection still rejects unsupported IPv4/IPv6 families;
unsplit protection requires both `0.0.0.0/0` and `::/0` peer AllowedIPs. Lockdown
can block unsupported or bypass traffic rather than route it. Kill-protected DNS
uses explicit NM-managed resolver `/32` and `/128` routes in main table 254,
merged with split routes even for excluded resolvers without replacing defaults.
Automatic routed-DNS processing is disabled for these profiles; `yes` remains
selected for unprotected profiles and is not a protection guarantee. After
activation/reapply, kernel UDP/TCP port-53 egress must select the tunnel or
Neutron attempts disconnection and reports an error. NetworkManager/nmcli 1.52+
and iproute2's `ip` verifier are required. See [security](security.md).

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
Snapshot saves reject a conflicting writer's changes with a reload-required
error. Reload current settings before resubmitting; do not overwrite from the
stale editor snapshot.
