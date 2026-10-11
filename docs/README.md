# Neutron Documentation Wiki

Welcome to the **Neutron** technical documentation and developer wiki.

Neutron is a high-performance WireGuard manager for Linux written in Rust, leveraging NetworkManager as the
system-native networking control plane.

---

## Wiki Contents

### 1. [Usage Guide (TUI & CLI)](usage.md)

Complete interactive guide to the Terminal User Interface (TUI), keybindings, modal navigation, and scriptable CLI
command reference.

### 2. [System Architecture & Design Principles](architecture.md)

Detailed overview of the decoupled subsystem architecture, module boundaries, data flows, thread model, and comparative
analysis of UI frontends (CLI, TUI, GUI, Electron).

### 3. [NetworkManager Integration](networkmanager.md)

How Neutron interfaces with NetworkManager, `nmcli` command execution, batch error aggregation, profile discovery,
interface comment extraction, and connection lifecycle.

### 4. [Security Architecture (Kill Switch & Lockdown)](security.md)

Comprehensive explanation of the two security layers: Layer 3 NetworkManager policy routing (`fwmark`, exclusive DNS
priorities) and Netfilter/Firewalld always-on OUTPUT filtering.

### 5. [Split Tunneling (IP & Domain Routing)](split-tunneling.md)

Architecture of global split tunneling, Include vs. Exclude routing modes, CIDR normalization (`/32` & `/128`),
client-side DNS resolution, and NetworkManager route injection.

### 6. [NAT-PMP Port Forwarding Engine](port-forwarding.md)

Pure Rust UDP implementation of the NAT-PMP protocol (RFC 6886), tunnel gateway derivation, mapping request framing,
lease renewal timers, and clipboard integration.

### 7. [User Configuration & Theming (`config.toml`)](configuration.md)

Specification for the human-readable TOML configuration, managed profile drop directory (`profiles/`) auto-sync,
built-in themes (Osaka Jade, Catppuccin, Nord, Gruvbox, Monochrome), and color customization.

### 8. [Installation & Releases](packaging-distribution.md)

Supported Homebrew, pinned Cargo, and static binary installations, system
requirements, removal, and the verified release process.

### 9. [Implementation Notes](implementation.md)

Startup selection, checked activation, configuration persistence, and saved versus effective policy state.

### 10. [Testing & Quality Checks](testing.md)

Formatting, Clippy, host tests, and disposable NetworkManager/firewall sandbox tests.

---

## Core Invariants

* **NetworkManager as Single Source of Truth**: All WireGuard profile parameters and secrets remain stored exclusively
  inside NetworkManager profile storage.
* **Decoupled Business Logic**: No domain logic (routing, firewall, config, port forwarding) is coupled to GTK or
  terminal drawing code.
* **Apply-Before-Persist**: Network operations are executed first; persisted application configurations are only updated
  if the underlying network mutation succeeds.
* **Fail-Closed Security**: Unsupported protection and denied required refreshes
  are reported, not silently bypassed. Lockdown teardown is surgical but requires
  authorization; interrupted rebuilds can block traffic until authenticated recovery.
