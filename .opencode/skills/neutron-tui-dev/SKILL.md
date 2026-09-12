---
name: neutron-tui-dev
description: Guidelines and conventions for Neutron's terminal user interface. Use when editing or creating code in src/tui/, managing Ratatui widgets, adding keyboard shortcuts, modifying theme presets, or handling command palette actions.
---

# Neutron TUI Development and Architecture

Neutron's TUI is built on `ratatui` and `crossterm`. It is designed for high responsiveness, zero runtime dependencies, and flicker-free rendering.

## Architecture and Key Modules

- `src/tui/mod.rs`: Main event loop, background ticker, terminal setup/cleanup, panic hook restoring raw mode.
- `src/tui/ui.rs`: Frame rendering functions (`render_status_panel`, `render_policies_panel`, `render_telemetry_panel`, `render_profile_list`, modals).
- `src/tui/events.rs`: Key event dispatchers, action executor (`execute_action`), profile list reloading.
- `src/tui/state.rs`: `TuiState`, modal state machines, palette filtering, toast expiration, throughput meters.
- `src/tui/theme.rs`: Color presets (`nord`, `osaka-jade`, `catppuccin`, `gruvbox`, `monochrome`) and hex color parser.

## Core Invariants

### 1. Unified Action Dispatching
- Any action reachable via keyboard shortcut (`handle_normal_key`) or footer legend MUST be registered in `CommandPaletteState::all_items()`.
- The string action ID passed to `execute_action` must be handled in the exhaustive `match action { ... }` block.
- An integration test (`tests/tui_actions.rs`) enforces that every action listed in the palette is implemented by the dispatcher without panics.

### 2. Non-blocking UI Loop
- Never perform blocking network round trips on the UI rendering thread.
- Forwarded port leases (`NAT-PMP`) and qBittorrent sync statuses are read asynchronously from the tray daemon's runtime publication file (`service::lease::read()`) during periodic ticker refresh (`refresh_lease`).
- Network throughput rates and diagnostics are polled on 1.5s background intervals rather than on every frame render.

### 3. Responsive Minimum Layout
- Minimum supported dimensions: **120 columns × 30 rows** (`MIN_WIDTH`, `MIN_HEIGHT`).
- If terminal dimensions fall below the minimum, `render_size_warning` displays an informative resize prompt instead of corrupting panel boundaries.
- Render elements (e.g. status badge, DNS, port, speed) must fit within the horizontal constraints without unexpected line wrapping.

### 4. Resilient Error Handling
- Normal user actions (such as attempting connection to an unreachable or misconfigured peer) must NEVER panic or terminate the TUI session.
- Errors must be caught, formatted, and displayed via `state.set_error(...)` or temporary toasts (`state.set_toast(...)`), leaving the terminal responsive.
