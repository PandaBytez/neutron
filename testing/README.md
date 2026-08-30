# Test environments

Neutron drives `nmcli` and `firewall-cmd` against real system daemons. Most of
the suite runs against mocks, but a mock can only prove Neutron's own argument
builders are self-consistent — never that NetworkManager *accepts* those
arguments, *stores* them, or reports them back the way the parsers expect.

Every leak in `BUGS.md` lived in exactly that gap, and several were verified by
hand on a developer's live desktop. That is unsafe and unrepeatable. This
directory replaces it.

## Tiers

| Tier | Where | Covers | Preferred Command | Low-Level Shell Script |
| --- | --- | --- | --- | --- |
| Full suite (All tiers) | host + container | all host tests + all container tests | `cargo test-all` | `cargo test && ./testing/run-container-tests.sh` |
| Unit + integration | host | logic, arg builders, TUI state | `cargo test` / `cargo test-all -- --host-only` | `cargo test` |
| System — NetworkManager | container | real profiles, routing, parsers | `cargo test-system -- --nm` | `./testing/run-container-tests.sh --nm` |
| System — firewall | container | real firewalld rules, teardown | `cargo test-system -- --firewall` | `./testing/run-container-tests.sh --firewall` |
| Leak demonstrations | container | regression guards | `cargo test-leaks` | `./testing/run-container-tests.sh --leaks` |

### Custom Cargo Tasks (`cargo xtask`)

Neutron supports standard Cargo tasks (`xtask`) configured in `.cargo/config.toml` so you do not need to invoke shell scripts directly:

```sh
# Run ALL test tiers (host unit/integration tests + container sandbox tests)
cargo test-all

# Run only containerized system tests in sandbox
cargo test-system

# Run specific tiers
cargo test-system -- --nm        # NetworkManager system tests
cargo test-system -- --firewall  # Firewall lockdown system tests
cargo test-system -- --rebuild   # Force rebuild the container image

# Run leak regression guards
cargo test-leaks

# Open an interactive shell inside the sandbox container
cargo xtask container-shell

# Run strict linter across all feature gates
cargo lint
```

Requires `podman` (or `docker`). The first run builds the `neutron-sandbox` Fedora image with NetworkManager,
firewalld, WireGuard tools, and the Rust toolchain.

## Safety model

The system tests create and delete real NetworkManager profiles and install a
REJECT-all firewall ruleset. Two independent mechanisms keep that away from your
machine.

**1. They refuse to run outside the sandbox.** Every system test calls
`neutron::testing::require_sandbox()`, which panics unless
`NEUTRON_TEST_SANDBOX=1` — set only by `Containerfile`. Combined with `#[ignore]`
this gives three layers:

| Invocation | Result |
| --- | --- |
| `cargo test` on your machine | skipped — never started |
| `cargo test -- --ignored` on your machine | **panics immediately**, changes nothing |
| inside the sandbox | runs |

The middle row is the point: forcing these tests to run outside the sandbox has
to fail loudly rather than quietly reconfigure someone's network.

**2. The kernel isolates them.** Netfilter tables and routing are per network
namespace, so a container with its own netns has its own firewall and routes.

This was *verified before being relied on*, not assumed. A uniquely marked
`iptables` rule was added inside a privileged container, then the host was
checked:

```
container:  iptables -A OUTPUT -m comment --comment NETNS-ISOLATION-PROBE -j ACCEPT
            → rule present (1)
host:       firewall-cmd --direct --get-all-rules | grep -c NETNS-ISOLATION-PROBE
            → 0
host:       curl https://1.1.1.1/  → http=301   (connectivity intact)
```

That result is why lockdown's deny-by-default ruleset can be exercised here at
all. If you change the isolation assumptions, re-run that probe first.

## Why there is no VM tier

One was built and then removed. Its only unique claim was that lockdown's
`--permanent` rules survive a reboot — but the container tests already read the
**permanent** store:

```
firewall-cmd --permanent --direct --get-all-rules
```

That is the on-disk configuration, not the runtime ruleset. A reboot re-reads
the same store, so a VM would have been testing that *firewalld honours its own
documented flag* — someone else's software — at the cost of a 500 MB image
download, cloud-init provisioning and mirror flakiness.

If a future change makes Neutron responsible for persistence itself (a systemd
unit, a boot-time hook), that reasoning stops holding and the tier should come
back.

## Leak regression guards

`tests/system_firewall.rs` contains `leak_*` tests asserting the behaviour that
BUG-018, BUG-019, and BUG-022 in `BUGS.md` violated. They now pass and serve as
permanent regression guards:

```sh
cargo test-leaks
```

They verify:
- **BUG-018**: No unscoped `ESTABLISHED,RELATED` rule exists in the OUTPUT chain that could let traffic leak over the physical interface when the tunnel drops.
- **BUG-019**: Port 53 DNS is strictly scoped rather than permitted to arbitrary public resolvers under full lockdown.
- **BUG-022**: Hostname endpoints are resolved and pinned to specific IP allow-rules rather than leaving the UDP port open to every host.

## Adding a system test

1. Put it in `tests/system_nm.rs` or `tests/system_firewall.rs`.
2. Mark it `#[ignore = "system test: requires the disposable sandbox"]`.
3. Call `require_sandbox()` first.
4. Clean up in `Drop`, not at the end of the test body — so a panicking
   assertion cannot leave a profile or ruleset behind and make later runs
   irreproducible.

Two constraints worth knowing:

- **Profile names must be valid interface names.** `nmcli connection import type
  wireguard` derives the interface from the file stem and rejects anything over
  15 characters. Use `testing::sandbox_profile_name()`.
- **Tests run single-threaded.** They share one NetworkManager and one
  firewalld; parallel runs interleave and produce irreproducible failures.

## Optional features

The qBittorrent integration is behind a Cargo feature and is **off by default**:

```sh
cargo test --features qbittorrent
./testing/run-container-tests.sh --shell   # then: cargo test --features qbittorrent
```

It drives a third-party Web API from paths that fire automatically on every
reconnect, and has not been validated against a real qBittorrent instance.
