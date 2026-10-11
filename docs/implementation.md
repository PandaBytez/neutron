# Implementation Notes

This page collects lifecycle and persistence details. See the existing
[architecture](architecture.md), [NetworkManager integration](networkmanager.md),
and [security](security.md) chapters for subsystem and policy design.

## Startup Selection

Auto-connect at login defaults to off. Enable it with `a` in the TUI to persist
the preference and install the desktop autostart entry. Explicit saved settings
are preserved when upgrading.

Neutron issues explicit connection requests and disables NetworkManager's native
autoconnect on managed WireGuard profiles. The startup selector leaves a single
active, eligible profile untouched. If replacement is needed, it validates the
eligible pool before disconnecting existing tunnels; an empty pool returns an
error without teardown. Candidate selection avoids immediately repeating the
last random profile when alternatives exist.

## Configuration Persistence

Application configuration is written atomically and uses owner-only `0o600`
permissions on Unix. Production writers update individual settings under a
stable sidecar file lock, preserving newer settings written by other Neutron
processes. External editors must cooperate with locking to serialize edits.

Imported profile notes live in a separate `profile-info.json` alongside the
settings file. Reading older inline notes is backward-compatible; the next save
writes the notes file before removing the inline section. Once present, the notes
file is authoritative, including an empty map after deletion. Malformed or
unreadable notes produce an error rather than being silently overwritten.

WireGuard private keys remain in NetworkManager storage. Optional qBittorrent
WebUI credentials are application settings; they are passed to curl through
stdin rather than command-line arguments.
The CLI accepts `--password-stdin` only with piped or redirected input, not a
terminal; `--password` is not supported. Use a protected file or secret-producing
pipe, never an inline password in a shell command. Settings still store these
credentials, so do not publish the configuration directory.

## Activation and Import

Activation requires successful configuration loading and routing/DNS policy
preparation. Invalid split-tunnel targets, unresolved domains, or rejected
NetworkManager modifications stop activation with an error. Imported profiles
receive the same checked preparation.

Preparation requires NetworkManager and `nmcli` 1.52+ and verifies retained
routed-DNS properties (`no` for protected profiles, `yes` for unprotected ones).
Kill-protected profiles disable automatic DNS route processing and merge explicit
NM-managed resolver `/32` and `/128` routes in main table 254 with split routes,
even exclusions, without replacing defaults. After activation and active-device
reapply, iproute2's `ip` verifies the kernel's UDP/TCP port-53 egress for every
resolver. Non-tunnel routes or verification errors attempt disconnection and
return an error, including any teardown failure; this is not a packet probe.
Kill protection without lockdown refuses unsupported IP
families; unsplit profiles need both full-family AllowedIPs. Explicit split
bypasses remain intentional. Disabled split mode clears stale split routes during
activation, and changing to disabled applies cleanup before saving; protected
resolver host routes are merged back, not removed with the split policy.

When lockdown is enabled, activation performs authenticated helper refreshes
before activation and during reconciliation afterward. Each helper invocation
requires fresh `auth_admin`, including automatic/headless paths; authorization
failure does not remove existing protection, and a required pre-activation
refresh failure aborts activation. Upgrade old grants with an authenticated
`neutron lockdown enable`. Detection covers both action directories and legacy
rules; disable retains only hardened authorization and revokes unsafe grants
under the root lock. See [helper security](security.md#helper-authorization-and-trust-boundary).

Automatic handshake-failure teardown applies to fresh interfaces whose profiles
have an endpoint and nonzero persistent keepalive, when verification is enabled.
On-demand profiles remain active while idle so their first packet can initiate
the handshake.

Imports use `nmcli connection import type wireguard file <path>`. The profile
UUID comes from that command's validated C-locale confirmation, rather than
guessing from concurrent profile-list changes. The profile
inbox consumes source files after successful import; source removal is
best-effort, and matching filenames are currently skipped by profile name rather
than content comparison. Interface comments are retained as application metadata.

## Saved Intent and Effective Policy

The long-lived indicator refreshes domain routes every 30 seconds and reapplies
them to active NetworkManager devices. Automatic firewall reconciliation and
domain refresh share coordination with explicit policy changes; failed firewall
reconciliation is retried. DNS rotation still has a polling interval, not a
per-query routing guarantee.

TUI profile refresh and startup sync run in background workers. Transient profile
read failures retry with a delay, and public-IP requests coalesce without losing
the last request during worker shutdown. Favorite menu IDs remain tied to UUIDs
across layout refreshes; clicks on removed items are ignored.

Port leases renew at half the granted lifetime (capped at 45 seconds). Failed
qBittorrent synchronization retries after 45 seconds, while changed configuration
can trigger an immediate attempt.

Routing/DNS changes to saved NetworkManager profiles require reconnect. Action
toasts explain this; the policy panel shows saved settings. DNS details do not
claim a verified live priority.

Policy errors distinguish potentially partial application from completed
application followed by failed saving. The current TUI session marks affected
policies `UNKNOWN` until a successful retry, even after a config refresh. CLI
lockdown status explicitly reports saved intent rather than verified firewall
state. Emergency disable attempts firewall removal even when saving is unavailable.

Split-editor snapshot writes compare the captured original with current saved
settings under policy coordination. A conflicting writer causes a reload-required
error rather than overwriting its changes; reload before resubmitting TUI edits.
Displayed errors escape terminal control characters and bidi controls.

For permanent rebuild guards and recovery, see
[Lockdown rebuild recovery](security.md#rebuild-recovery).

## Binary and Verification

NAT-PMP sockets accept replies only from the requested gateway address and port.
Replies must match the protocol version, length, opcode and internal port (with
the provider's zero-port allocation convention supported). Failure to bind the
requested tunnel address aborts the request instead of falling back to another source.

The executable is named `neutron`. The musl target produces a statically linked
binary; system tools and services such as NetworkManager are still required.
Build instructions are in [Installation & Releases](packaging-distribution.md).
Commands and test-tier boundaries are in [Testing & Quality Checks](testing.md).
