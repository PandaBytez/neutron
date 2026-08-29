# NAT-PMP Dynamic Port Forwarding Engine

Neutron VPN includes a native, pure Rust NAT-PMP (RFC 6886) client designed for VPN providers that support dynamic port forwarding (such as Proton VPN, Mullvad, and PIA).

---

## Technical Protocol Overview

NAT-PMP (Port Mapping Protocol) allows clients behind a NAT gateway to request dynamic UDP and TCP port mappings.

```text
┌──────────────┐                            ┌──────────────┐
│  Neutron VPN │                            │  VPN Gateway │
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

Neutron VPN derives the default NAT-PMP gateway IP automatically:
1. Extracts the primary tunnel IPv4 address via `nmcli -g ipv4.addresses connection show <uuid>`.
2. Replaces the host octet with `.1` (e.g. `10.2.0.2` $\rightarrow$ `10.2.0.1`).
3. Dispatches the NAT-PMP packet to UDP port `5351` at that gateway address.

---

## Auto-Renewal Lifecycle

1. **Lease Grant**: Upon receiving a success packet, the granted port number is stored in memory and displayed in the UI banner.
2. **Periodic Renewal Timer**: A background timer runs at `RENEW_INTERVAL` (every 45 seconds) to refresh the lease with the gateway.
3. **Profile Switch / Disconnect Cleanup**: When switching profiles or disconnecting, the active port is cleared immediately to prevent displaying stale mappings.
4. **Clipboard Integration**: A 1-click button in the GUI copies the forwarded port to the system clipboard for easy pasting into BitTorrent or game servers.
