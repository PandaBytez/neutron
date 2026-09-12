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

## Activation and Import

Activation requires successful configuration loading and routing/DNS policy
preparation. Invalid split-tunnel targets, unresolved domains, or rejected
NetworkManager modifications stop activation with an error. Imported profiles
receive the same checked preparation.

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

Routing/DNS changes to saved NetworkManager profiles require reconnect. Action
toasts explain this; the policy panel shows saved settings. DNS details do not
claim a verified live priority.

Policy errors distinguish potentially partial application from completed
application followed by failed saving. The current TUI session marks affected
policies `UNKNOWN` until a successful retry, even after a config refresh. CLI
lockdown status explicitly reports saved intent rather than verified firewall
state. Emergency disable attempts firewall removal even when saving is unavailable.

For permanent rebuild guards and recovery, see
[Lockdown rebuild recovery](security.md#rebuild-recovery).

## Binary and Verification

NAT-PMP sockets accept replies only from the requested gateway address and port.
Replies must match the protocol version, length, opcode and internal port (with
the provider's zero-port allocation convention supported).

The executable is named `neutron`. The musl target produces a statically linked
binary; system tools and services such as NetworkManager are still required.
Build instructions are in [Packaging & Distribution](packaging-distribution.md).
Commands and test-tier boundaries are in [Testing & Quality Checks](testing.md).
