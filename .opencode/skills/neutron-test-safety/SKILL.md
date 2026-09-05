---
name: neutron-test-safety
description: Enforce Neutron's tiered test safety model and sandbox isolation rules. Use when running tests, executing cargo test or cargo test-system, writing system tests in tests/system_nm.rs or tests/system_firewall.rs, or dealing with container sandboxing.
---

# Neutron Test Safety and Tiered Execution

Neutron interfaces directly with `nmcli` and `firewall-cmd`. Because destructive NetworkManager operations and `REJECT-all` firewall rules can disrupt host workstation connectivity, a strict multi-tier testing safety model is enforced.

## Testing Tiers

| Tier | Where | Description | Command |
|---|---|---|---|
| **Unit & Integration** | Host | Pure argument builders, state machines, TUI actions, mocks | `cargo test` or `cargo test --all-features` |
| **System (NetworkManager)** | Container Sandbox | Exercises real `nmcli` operations, profile creation, and default-route handling | `cargo test-system -- --nm` |
| **System (Firewall)** | Container Sandbox | Exercises real `firewall-cmd` rules, Netfilter chains, and lockdown teardown | `cargo test-system -- --firewall` |
| **Leak Regression** | Container Sandbox | Verifies Netfilter lockdown rules and routing tables for potential leaks | `cargo test-leaks` |
| **Full Suite** | Host + Container | Runs host tests followed by all container system tests | `cargo test-all` |

## Safety Model & Rules

### 1. Never Run Ignored Tests Directly on Host
- System tests in `tests/system_nm.rs` and `tests/system_firewall.rs` are marked with `#[ignore = "system test: requires the disposable sandbox"]`.
- Every system test begins with `neutron::testing::require_sandbox()`, which panics if `NEUTRON_TEST_SANDBOX=1` is not set in the environment.
- **NEVER** run `cargo test -- --ignored` on the host machine. Forcing execution outside the container will either trigger immediate panics or risk reconfiguring host network interfaces and firewalls.

### 2. Use `cargo xtask` or Aliases
Run system tests inside the container sandbox using the preconfigured Cargo aliases:
```sh
# Host unit and integration tests only
cargo test --all-features

# Strict lint checks across features
cargo lint

# Run containerized system tests in Podman/Docker sandbox
cargo test-system

# Run leak regression checks inside sandbox
cargo test-leaks

# Full suite (Host unit/integration + Container system tests)
cargo test-all
```

### 3. Container Isolation Invariants
- Tests inside the container run in their own network namespace (`netns`).
- Privileged operations (`CAP_NET_ADMIN`) are strictly confined to the container sandbox.
- When creating temporary configuration or profile directories in tests, always use unique timestamps or ephemeral paths (`std::env::temp_dir()`).
