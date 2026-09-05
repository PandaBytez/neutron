# AGENTS.md

Guidance for coding agents working in this repository.

## Project Intent

This project (Neutron) is a Rust desktop app to manage WireGuard connections via NetworkManager.

Primary goals:
- Use NetworkManager as the control plane.
- Support manual connect/disconnect/switch between WireGuard profiles.
- Support random profile selection once per boot from an eligible profile pool.
- Stay compatible with modern GNOME/Linux desktop workflows.

## Architectural Rules

- Treat NetworkManager profiles as source of truth.
- Do not run `wg-quick up/down` for normal connection lifecycle.
- Optional `wg` CLI usage is read-only diagnostics only.
- Keep UI logic separate from NetworkManager/service logic.

## Coding Standards

- Keep modules focused and small.
- Prefer explicit error types over `anyhow` everywhere in core domain code.
- Use `Result` and avoid panics in runtime code paths.
- Use `clippy` cleanly (no ignored lints without rationale).
- Format with `rustfmt`.

## Suggested Module Boundaries

- `nm/`: NetworkManager integration (list profiles, activate/deactivate).
- `app/`: GTK/libadwaita UI state and actions.
- `service/`: boot-time random selector logic.
- `config/`: app settings and eligible-profile persistence.

## Safety Constraints

- Never execute shell commands constructed from untrusted user input.
- Avoid storing private keys or secrets outside NetworkManager profile storage.
- Do not auto-modify profile settings silently without clear user action.

## Definition of Done (per feature)

- Behavior implemented and manually verified.
- Error paths handled with user-visible messages where relevant.
- `cargo fmt`, `cargo clippy`, and `cargo test` pass.
- README and TODO updated if scope changes.
