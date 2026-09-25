# Testing & Quality Checks

Run these commands from the repository root with the Rust toolchain installed.

## Host Checks

```bash
# Check formatting and run strict Clippy across all features
cargo lint

# Rebuild and install the binary, leaving lockdown and settings alone (dev loop).
# Extra flags go to `cargo install`, so --debug and --root work:
cargo xtask reinstall -- --debug

# Run default-feature unit and integration tests
cargo test

# Include the optional qBittorrent integration tests
cargo test --all-features
```

Host tests use pure logic, mocks, and isolated local responders. Tests that
modify real NetworkManager profiles or firewall rules are ignored on the host.

## Disposable System Sandbox

Requires Podman or Docker. The Cargo tasks start NetworkManager and firewalld in
a disposable container with its own network namespace. Network and firewall
changes stay inside that sandbox.

Every container tier also runs on pull requests, via the `System Tests (sandbox)`
job, so the tests below are enforced rather than advisory.

```bash
# Host tests across all features, then containerized system tests
cargo test-all

# Containerized system tests only (this is what CI runs)
cargo test-system

# Select a system tier or rebuild the sandbox image
cargo test-system -- --nm
cargo test-system -- --firewall
cargo test-system -- --uninstall
cargo test-system -- --rebuild

`cargo xtask reinstall` keeps your settings as they are: the settings files are
captured before the install and restored if anything changes them, and the
result is reported rather than silently reverted.

# Firewall leak regression checks
cargo test-leaks

# Interactive sandbox for investigation
cargo xtask container-shell
```

Never run `cargo test -- --ignored` directly on the host or set
`NEUTRON_TEST_SANDBOX=1` there. The sandbox sets that marker for tests guarded by
`require_sandbox()`.

## Coverage and Limits

- NetworkManager tests check profile import, policy properties, and real
  WireGuard activation, including idle on-demand tunnels.
- Firewall tests check rule acceptance, legacy-rule migration, surgical teardown,
  and established IPv4/IPv6 packet egress. The `leak_*` checks are also included
  in the firewall tier.
- The ignored library test `interrupted_rebuild_stays_closed_after_reload_and_recovers`
  exercises partial permanent rebuilds and recovery. It runs in the full system
  suite; `--firewall` selects only `tests/system_firewall.rs`.
- The default sandbox uses firewalld's iptables backend. Its entrypoint also
  accepts `NEUTRON_TEST_FIREWALL_BACKEND=nftables` inside the container for
  cross-backend checks.
- Container reload checks do not establish persistence across an actual reboot.

## Build the Documentation

```bash
cargo docs
cargo xtask docs --serve
```

mdBook writes the site to `public/`. See [Implementation Notes](implementation.md)
for the behavior these tests protect.
