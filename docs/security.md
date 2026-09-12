# Security Architecture (Kill Switch & Lockdown)

Neutron combines NetworkManager routing/DNS policy with an optional always-on firewall.

---

## Defense Tiers Overview

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                             Defense Tier 1:                                 │
│                   Kill Switch (Layer 3 Routing Plane)                       │
│  • Active while WireGuard tunnel is UP                                      │
│  • NetworkManager Policy Routing (`wireguard.ip4-auto-default-route = yes`) │
│  • Dedicated routing table + `fwmark` + `suppress_prefixlength 0`           │
│  • Exclusive DNS priority (`ipv4.dns-priority = -1500`)                     │
│  • Drops traffic if tunnel fails; prevents fallback to physical gateway     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                             Defense Tier 2:                                 │
│                   Lockdown Mode (Netfilter Firewall Plane)                  │
│  • Active 24/7 (Even when tunnel is DISCONNECTED or RECONNECTING)           │
│  • Permanent `firewalld` direct mangle OUTPUT rules (IPv4 & IPv6)           │
│  • Allows: Loopback, configured tunnel interfaces, conditional DNS (53)     │
│  • Allows: Peer Handshake Endpoints (Host:Port)                             │
│  • Allows: Private LAN (RFC 1918: 10.0.0.0/8, 192.168.0.0/16, DHCP, mDNS)  │
│  • Blocks: Other outbound traffic via terminal DROP                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. NetworkManager-Native Kill Switch

### How It Works
The kill switch operates entirely through NetworkManager connection properties without introducing custom firewall scripts:
```bash
nmcli connection modify <uuid> \
    wireguard.ip4-auto-default-route yes \
    wireguard.ip6-auto-default-route yes \
    ipv4.dns-priority -1500 \
    ipv6.dns-priority -1500
```

### Routing Invariants
1. **Dedicated Table Routing**: NetworkManager places the tunnel default route into an isolated routing table guarded by an `fwmark` and a `suppress_prefixlength 0` rule.
2. **Active-Connection Scope**: Routing protection depends on the active connection's routes and rules. Lockdown provides protection across disconnection and switching.
3. **DNS Priority**: A negative DNS priority (`-1500`) gives the tunnel's DNS resolvers exclusive precedence over LAN/DHCP resolvers, eliminating DNS leaks to your local ISP.

The setting is global and applies to saved profiles for their next activation.
Automatic default-route handling is pinned independently of the DNS toggle;
full-tunnel routing requires a peer allowing `0.0.0.0/0` or `::/0`. IPv6 policy
is adjusted for profiles without IPv6. See [saved versus effective policy](implementation.md#saved-intent-and-effective-policy).

---

## 2. Always-On Lockdown Firewall

### Why Lockdown is Needed
The Kill Switch only protects traffic while a tunnel connection is actively established. When disconnected, traffic flows normally over the physical interface.

**Lockdown closes that gap** by installing permanent `firewalld` direct rules in
`mangle OUTPUT` via a single batched `pkexec` invocation. This runs before
filter-table established-connection accepts on both firewalld backends.

### Ruleset Hierarchy (OUTPUT Chain)

| Priority | Match Criteria | Target | Purpose |
| :---: | :--- | :---: | :--- |
| **0** | `-o lo` | `ACCEPT` | Allow local loopback communication |
| **1** | `-p udp/tcp --dport 53` | `ACCEPT` | Allow DNS when the supplied tunnel list is empty |
| **1** | `-d <LAN_SUBNETS>` | `ACCEPT` | Keep local LAN devices reachable (Router, Printer, NAS) |
| **1** | `-o <TUNNEL_IFACE>` | `ACCEPT` | Allow decrypted traffic through active WireGuard tunnels |
| **1** | `-p udp -d <PEER_HOST> --dport <PEER_PORT>` | `ACCEPT` | Allow encrypted WireGuard handshake packets out |
| **10** | All remaining packets | `DROP` | Block other outbound traffic before filter-table accepts |

The supplied list contains configured tunnels, not just active ones. LAN
allowances also permit DNS to LAN resolvers. An `ACCEPT` here finishes this
table; it does not bypass other firewall policy.

### Surgical Teardown Guarantee
Every single rule installed by Lockdown carries a marker:
`-m comment --comment neutron-lockdown`

When disabling Lockdown:
1. Unprivileged reads enumerate permanent tagged rules in both mangle and legacy filter OUTPUT.
2. A single privileged batch removes those rules individually and reloads firewalld.
3. Foreign permanent direct rules are preserved. The global reload can still discard unrelated runtime-only configuration.
4. Disable requires successful firewall authorization and execution; failures are reported.

### Rebuild Recovery

Rebuilds install tagged priority `-1` DROP guards for both address families before
replacing old permanent rules. Guards are removed only after the replacement is
complete. An interruption therefore remains fail-closed after reload or reboot,
but can block all outbound traffic. Retry enabling lockdown or explicitly disable
it to remove the guards and recover.

[Sandbox tests](testing.md) exercise interrupted rebuilds, migration, teardown,
and established IPv4/IPv6 egress on both firewalld backends.
