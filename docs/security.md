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
    ipv6.dns-priority -1500 \
    ipv4.routed-dns no \
    ipv6.routed-dns no
```

### Routing Invariants
1. **Dedicated Table Routing**: NetworkManager places the tunnel default route into an isolated routing table guarded by an `fwmark` and a `suppress_prefixlength 0` rule.
2. **Active-Connection Scope**: Routing protection depends on the active connection's routes and rules. Lockdown provides protection across disconnection and switching.
3. **DNS Policy**: Negative DNS priority (`-1500`) selects tunnel resolvers. Preparation requires explicit tunnel DNS covered by peer AllowedIPs, adds `~.` on supported families, and makes those families non-optional (`may-fail=no`). Protected profiles disable automatic DNS route processing (`ipv4.routed-dns=no`, `ipv6.routed-dns=no`) and append explicit NetworkManager-managed resolver `/32` and `/128` routes with metric 5 in the main table (`table=254`). These routes merge with the selected split routes, preserve default-route policy, and retain resolver transport through the tunnel even when the resolver is excluded.

The command above shows only the base properties, not complete DNS preparation.
Automatic `routed-dns=yes` processing was found in the sandbox to remove IPv6
host routes during device reapply on NetworkManager 1.56; it is not a protection
guarantee. Protected profiles use explicit routes instead.

The setting is global and applies to saved profiles for their next activation.
Automatic default-route handling is pinned independently of the DNS toggle;
full-tunnel routes still depend on peer AllowedIPs. Both the NetworkManager
daemon and `nmcli` must be **1.52+**. Preparation verifies that both routed-DNS
properties retained the selected value: `no` for kill-protected profiles, `yes`
for unprotected profiles. Unsupported or discarded properties refuse activation.
The `ip` tool from **iproute2** is also required for kernel egress verification.

After protected activation and active-device route reapply, Neutron checks each
resolver's actual kernel egress selection using JSON `ip -4/-6 route get` with
`ipproto udp/tcp dport 53`. Each lookup must select the tunnel interface; checks
allow a short retry window for asynchronous route commits. This is a kernel route
check, not a DNS response or packet-delivery probe. A failed lookup, malformed
result, or non-tunnel egress triggers `nmcli connection down` and an error;
disconnection failure is reported too. Saved properties alone are not verification.

With the kill switch enabled **without lockdown**, activation refuses an
unsupported IPv4 or IPv6 family. With split mode disabled, peers must allow both
`0.0.0.0/0` and `::/0`. An IPv4-only or partial tunnel is not silently IPv6-safe:
use a suitable dual-stack profile or enable lockdown to block unsupported traffic.
Explicit split bypasses remain intentional, not a promise of full-tunnel
protection. See [saved versus effective policy](implementation.md#saved-intent-and-effective-policy).

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

### Helper Authorization and Trust Boundary

Every invocation of the root-owned refresh helper requires **fresh `auth_admin`**
authorization. The action uses `allow_any=no`, and `auth_admin` for active and
inactive sessions, not `yes` or `auth_admin_keep`. There is no password-free
refresh grant. Automatic activation, switching, login selection, profile changes,
and background firewall/DNS reconciliation may therefore prompt. Missing agents,
headless denial, or rejected authorization fail closed; required pre-activation
refresh failures stop activation, and existing firewall protection remains.

Existing installations must run `neutron lockdown enable` and authenticate to
upgrade the old helper and password-free action. Current source refuses the old
grant, checking both action directories and the legacy rules file, including
mixed policies and dangling links. A hardened action in one directory does not
excuse an unsafe grant elsewhere. Authenticated `lockdown disable` rechecks under
the root lock and revokes the helper and all known authorization files if they
are not hardened; it preserves only hardened authorization. The refresh-only
helper derives allowances from NetworkManager and accepts
only an optional validated activation UUID, never caller-provided firewall rules.
It cannot enable or disable lockdown.

Interface allowances use exact names: 1-15 bytes of ASCII letters, digits, `_`,
or `-`, with no `+` wildcard. Existing links must be verified kernel WireGuard
devices, even if named `wg...`. An absent inactive/pending interface must begin
with `wg` and have a suffix; an active interface may not be absent. Authenticated
toggles recheck the link type after authorization and before writing rules.

Helper installation copies the running executable through `/proc/<pid>/exe`,
opens that pinned inode, verifies its device/inode identity, and copies from the
open descriptor rather than trusting a replaceable executable pathname.

Mutations take the legacy `/run/neutron-lockdown.lock` and then the private
`/run/neutron-lockdown/lock`, preserving old inode coordination across upgrades.
The private directory is root-owned `0700`, lock files are root-owned `0600`, and
each lock acquisition is bounded to 10 seconds. Unsafe file types, owners, or
links are rejected; lock files are not unlinked during teardown. This bounds lock
contention, not the administrator authentication wait.

### Surgical Teardown Guarantee
Every single rule installed by Lockdown carries a marker:
`-m comment --comment neutron-lockdown`

When disabling Lockdown:
1. Unprivileged reads enumerate permanent and runtime tagged rules in both mangle and legacy filter OUTPUT.
2. A single privileged batch removes those rules individually, without reloading firewalld.
3. Foreign runtime/permanent rules, custom chains, and rich rules are left untouched.
4. Disable requires successful firewall authorization and execution; failures are reported.

### Uninstalling Revokes Everything It Installed

Enabling Lockdown writes root-owned helper/action files that no package owns, because
they must live outside the app directory:

| Path | Purpose |
| :--- | :--- |
| `/usr/local/libexec/neutron-lockdown-helper` | Root-owned, refresh-only copy of the running binary |
| `/usr/local/share/polkit-1/actions/io.github.pandabytez.neutron.lockdown-refresh.policy` | Requires fresh `auth_admin` for that copy; polkit 126+ location |

`lockdown enable` installs/updates the authenticated helper and migrates old
grants. `lockdown disable` keeps only hardened authorization; otherwise it revokes
the helper and every known grant. Reset and uninstall revoke them unconditionally.
Re-enabling and helper refreshes still require authentication. Older polkit uses
`/usr/share/polkit-1/actions`; the legacy rules file is
`/etc/polkit-1/rules.d/49-neutron-lockdown-refresh.rules`. Detection and revocation
cover both action directories, the legacy file, and the helper, including dangling
links. Revocation reloads polkit and reports surviving files rather than ignoring
them.

**Package managers cannot clean this up themselves**, so uninstall through the
app:

```bash
neutron uninstall              # revoke, then brew/cargo uninstall
neutron uninstall --purge      # also delete ~/.config/neutron
```

`neutron uninstall` stops the tray daemon, drops the autostart entry, and then
runs the removal command for the install it detects. The privileged work — lifting
the rules *and* removing the helper/action — is one batch, so it is at most one password
prompt, and it is skipped entirely when the machine holds no Neutron-owned
lockdown state. Homebrew's own `post_uninstall` hook cannot do this: it runs
*after* the files are removed, with no way to authenticate.

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
sudo rm -f /usr/share/polkit-1/actions/io.github.pandabytez.neutron.lockdown-refresh.policy \
  /etc/polkit-1/rules.d/49-neutron-lockdown-refresh.rules
# Reload/restart the polkit authority using your system's service manager.
```

### Rebuild Recovery

Rebuilds install tagged priority `-1` DROP guards for both address families before
replacing rules in each of the permanent and runtime configurations. Guards are removed only after the replacement is
complete. An interruption therefore remains fail-closed after reload or reboot,
but can block all outbound traffic. Retry enabling lockdown or explicitly disable
it to remove the guards and recover.

[Sandbox tests](testing.md) exercise interrupted rebuilds, migration, teardown,
and established IPv4/IPv6 egress on both firewalld backends.
