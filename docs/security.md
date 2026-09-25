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
| **1** | `-p udp/tcp --dport 53` | `ACCEPT` / `DROP` | Allow bootstrap DNS when disconnected; block non-tunnel DNS when connected |
| **1** | `-d <LAN_SUBNETS>` | `ACCEPT` | Keep local LAN devices reachable (Router, Printer, NAS) |
| **0** | `-o <TUNNEL_IFACE>` | `ACCEPT` | Allow first traffic on configured WireGuard interfaces |
| **1** | `-p udp -d <PEER_HOST> --dport <PEER_PORT>` | `ACCEPT` | Allow encrypted WireGuard handshake packets out |
| **10** | All remaining packets | `DROP` | Block other outbound traffic before filter-table accepts |

Activation installs the target interface and connected DNS policy before bringing
the tunnel up. DNS drops precede LAN allowances. An `ACCEPT` here finishes this
table; it does not bypass other firewall policy.

### Surgical Teardown Guarantee
Every single rule installed by Lockdown carries a marker:
`-m comment --comment neutron-lockdown`

When disabling Lockdown:
1. Unprivileged reads enumerate permanent and runtime tagged rules in both mangle and legacy filter OUTPUT.
2. A single privileged batch removes those rules individually, without reloading firewalld.
3. Foreign runtime/permanent rules, custom chains, and rich rules are left untouched.
4. Disable requires successful firewall authorization and execution; failures are reported.

### Uninstalling Revokes Everything It Installed

Enabling Lockdown also writes two root-owned files that no package owns, because
they must live outside the app directory:

| Path | Purpose |
| :--- | :--- |
| `/usr/local/libexec/neutron-lockdown-helper` | Root-owned, refresh-only copy of the binary, so a rule refresh needs no password |
| `/usr/local/share/polkit-1/actions/io.github.pandabytez.neutron.lockdown-refresh.policy` | Authorizes that copy, `allow_active=yes` |

Together they are the **password-free refresh grant**. Its lifetime is the
*installation*, not the current lockdown state: `lockdown enable` installs it and
`neutron uninstall` revokes it, while `lockdown disable` leaves it in place so a
re-enable needs no second prompt — and so the emergency path that lifts the block
stays limited to the one thing a locked-out user needs. Revocation sweeps both
polkit action directories, so a downgrade from polkit 126+ cannot leave a live
grant, then verifies from unprivileged `stat` that nothing survived; a leftover
is reported rather than ignored.

**Package managers cannot clean this up themselves**, so uninstall through the
app:

```bash
neutron uninstall              # revoke, then brew/cargo uninstall
neutron uninstall --purge      # also delete ~/.config/neutron
```

`neutron uninstall` stops the tray daemon, lifts the rules, revokes the grant,
drops the autostart entry, and then runs the removal command for the install it
detects. Homebrew's own `post_uninstall` hook cannot do this: it runs *after* the
files are removed, with no way to authenticate.

The install source is resolved **before** anything is deleted, and an
unrecognized one is refused outright. Tearing down the firewall and then failing
to remove the package would leave a machine with no protection *and* an app the
user still has to remove by hand; a refusal that changes nothing is the safer
failure. `~/.config/neutron` is kept by default — the eligibility pool and
favorites are tedious to rebuild, and a reinstall should find them intact —
while `--purge` deletes it, which is also how the stored qBittorrent password goes
away. A `profiles_dir` configured *outside* that directory is your own files, so
it is only reported, never deleted. The teardown also runs before the purge: if
the privileged teardown fails, the settings are left in place.

If you remove the package first, `firewalld` keeps the tagged DROP rules and the
machine stays blocked with no app left to lift them; recover by hand:

```bash
sudo firewall-cmd --permanent --direct --get-all-rules | grep neutron-lockdown
# remove each reported rule with --remove-rule, then reload:
sudo firewall-cmd --reload
sudo rm -f /usr/local/libexec/neutron-lockdown-helper \
  /usr/local/share/polkit-1/actions/io.github.pandabytez.neutron.lockdown-refresh.policy
```

### Rebuild Recovery

Rebuilds install tagged priority `-1` DROP guards for both address families before
replacing rules in each of the permanent and runtime configurations. Guards are removed only after the replacement is
complete. An interruption therefore remains fail-closed after reload or reboot,
but can block all outbound traffic. Retry enabling lockdown or explicitly disable
it to remove the guards and recover.

[Sandbox tests](testing.md) exercise interrupted rebuilds, migration, teardown,
and established IPv4/IPv6 egress on both firewalld backends.
