---
name: neutron-policy-audit
description: Audit and verify VPN routing, kill switch, split tunnel, and firewall lockdown policies against IP and DNS leaks. Use when modifying src/nm/, src/firewall/, routing rules, split tunnel CIDRs, or firewall rules.
---

# Neutron Policy and Leak Prevention Invariants

Neutron's core security promise is strict leak prevention. Policy changes must not leave windows where unencrypted traffic leaves over physical interfaces or DNS queries reach ISP resolvers.

## Architectural Security Invariants

### 1. Invariant I1: Default-Route Protection
- A WireGuard profile must never be left in an unroutable state when activated.
- Pin automatic default-route properties (`wireguard.ip4-auto-default-route=yes`, `wireguard.ip6-auto-default-route=yes`) before bringing connections up.
- In split-tunnel modes, ensure non-empty route complements are calculated so unrouted traffic does not inadvertently fall back to the cleartext gateway.

### 2. Invariant I2: Global Policy Inheritance
- Global security policies (Kill Switch, Split Tunneling) must not be applied only as a point-in-time sweep over existing profiles.
- Any profile that is newly imported (`import_wireguard_profile`) or activated (`activate`) must immediately inherit:
  - `ipv4.dns-priority = -1500` / `ipv6.dns-priority = -1500` if the Kill Switch is enabled.
  - Split-tunnel routing rules (`ipv4.never-default = yes`, `ipv4.routes = ...`) if split tunneling is enabled.
  - `connection.autoconnect = no` so NetworkManager never auto-connects newly imported profiles at boot without user consent.

### 3. Invariant I3: Lockdown Firewall Scoping
- Under Lockdown (`src/firewall/`), all outbound traffic is dropped by default (`REJECT`) except:
  - Loopback (`-o lo -j ACCEPT`).
  - Local LAN ranges (IPv4 RFC 1918 + link-local; IPv6 link-local + unique local).
  - Explicit tunnel interfaces (`-o <interface> -j ACCEPT`).
  - Peer endpoints pinned to resolved IP literals (`-p udp -d <ip> --dport <port> -j ACCEPT`).
- **Forbidden:** Never install an unscoped `ESTABLISHED,RELATED` rule on the `OUTPUT` chain—conntrack tracks flows rather than devices, so dying tunnels would allow existing flows to leak over the physical interface in the clear.
- **DNS Scoping:** Unscoped port 53 DNS is only permitted when no tunnel is active (to resolve peer hostnames); once a tunnel is connected, DNS must traverse the tunnel interface.

### 4. Surgical Teardown
- All firewall rules installed by Neutron must carry the marker comment (`neutron-lockdown`).
- Teardown operations must target only marked rules individually; chain-wide flushes are forbidden as they would wipe foreign user rules.
