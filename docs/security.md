# Security Architecture (Kill Switch & Lockdown)

Neutron implements a two-tier defense model designed to prevent IP, routing, and DNS leaks under all connection states.

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
│  • Permanent `firewalld` direct OUTPUT filter rules (IPv4 & IPv6)           │
│  • Allows: Loopback, Established/Related, DNS (53), Tunnel Interfaces (wg*) │
│  • Allows: Peer Handshake Endpoints (Host:Port)                             │
│  • Allows: Private LAN (RFC 1918: 10.0.0.0/8, 192.168.0.0/16, DHCP, mDNS)  │
│  • Blocks: ALL other outbound internet traffic via terminal REJECT          │
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
2. **No Fallback**: If the WireGuard interface drops, non-tunnel packets are forced into the dead table rather than leaking over the default physical network interface.
3. **DNS Priority**: A negative DNS priority (`-1500`) gives the tunnel's DNS resolvers exclusive precedence over LAN/DHCP resolvers, eliminating DNS leaks to your local ISP.

---

## 2. Always-On Lockdown Firewall

### Why Lockdown is Needed
The Kill Switch only protects traffic while a tunnel connection is actively established. When disconnected, traffic flows normally over the physical interface.

**Lockdown closes that gap** by installing permanent `firewalld` direct rules on the `OUTPUT` chain via `pkexec`.

### Ruleset Hierarchy (OUTPUT Chain)

| Priority | Match Criteria | Target | Purpose |
| :---: | :--- | :---: | :--- |
| **0** | `-o lo` | `ACCEPT` | Allow local loopback communication |
| **0** | `-m conntrack --ctstate ESTABLISHED,RELATED` | `ACCEPT` | Allow existing established connections |
| **1** | `-p udp/tcp --dport 53` | `ACCEPT` | Allow DNS resolution for endpoint hostnames |
| **1** | `-d <LAN_SUBNETS>` | `ACCEPT` | Keep local LAN devices reachable (Router, Printer, NAS) |
| **1** | `-o <TUNNEL_IFACE>` | `ACCEPT` | Allow decrypted traffic through active WireGuard tunnels |
| **1** | `-p udp -d <PEER_HOST> --dport <PEER_PORT>` | `ACCEPT` | Allow encrypted WireGuard handshake packets out |
| **10** | `-m comment --comment neutron-lockdown` | `REJECT` | Block all other outbound traffic |

### Surgical Teardown Guarantee
Every single rule installed by Lockdown carries a marker:
`-m comment --comment neutron-lockdown`

When disabling Lockdown:
1. An unprivileged read (`firewall-cmd --direct --get-rules`) parses all rules tagged with `neutron-lockdown`.
2. A single batched `pkexec firewall-cmd --remove-rule ...` removes only our tagged rules.
3. User-defined direct rules or foreign software rules are completely untouched.
4. The disable path always functions, ensuring the user can never be locked out.
