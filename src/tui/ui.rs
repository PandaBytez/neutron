//! Ratatui rendering engine, widget layouts, and Command Palette modals.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph, Wrap};

use crate::config::SplitTunnelMode;
use crate::nm::network_info::format_speed;
#[cfg(feature = "qbittorrent")]
use crate::service::lease::QbitSyncStatus;
use crate::tui::state::{
    ActiveModal, CommandPaletteState, SplitTunnelFocus, SplitTunnelModalState, ThemePickerState,
    TuiState,
};
pub const MIN_WIDTH: u16 = 120;
pub const MIN_HEIGHT: u16 = 30;

pub fn render(frame: &mut Frame, state: &TuiState) {
    let size = frame.area();

    if size.width < MIN_WIDTH || size.height < MIN_HEIGHT {
        render_size_warning(frame, size, state);
        return;
    }

    // Overall vertical layout: Header, Body, Footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Header with Status & Policies panels
            Constraint::Min(10),   // Main body: Left List, Right Full Detail
            Constraint::Length(4), // Footer with Hotkeys and Legend
        ])
        .split(size);

    render_header(frame, chunks[0], state);
    render_body(frame, chunks[1], state);
    render_footer(frame, chunks[2], state);

    // Overlay Modals
    match &state.modal {
        ActiveModal::CommandPalette(cp) => render_command_palette_modal(frame, size, cp, state),
        ActiveModal::ThemePicker(tp) => render_theme_picker_modal(frame, size, tp, state),
        ActiveModal::Help => render_help_modal(frame, size, state),
        ActiveModal::SplitTunnel(st) => render_split_tunnel_modal(frame, size, st, state),
        ActiveModal::ConfirmDelete { name, .. } => {
            render_confirm_delete_modal(frame, size, name, state)
        }
        ActiveModal::None => {}
    }

    // Floating Toast Notification or Connecting Progress
    if let Some(ref conn) = state.connecting {
        render_connecting_toast(frame, size, conn, state);
    } else if let Some(toast) = state.active_toast() {
        render_toast(frame, size, toast, state);
    }
}

fn render_size_warning(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;
    let msg = vec![
        Line::raw(""),
        Line::from(vec![Span::styled(
            " ⚠ Terminal window too small! ",
            theme.warning,
        )]),
        Line::raw(""),
        Line::from(vec![Span::styled(
            format!(
                "Current size: {}x{}  |  Minimum required: {}x{}",
                area.width, area.height, MIN_WIDTH, MIN_HEIGHT
            ),
            theme.text_secondary,
        )]),
        Line::raw(""),
        Line::from(vec![Span::styled(
            "Please resize or zoom out your terminal window.",
            theme.label_dim,
        )]),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.warning)
        .title(Span::styled(" Window Size Warning ", theme.warning));

    let paragraph = Paragraph::new(msg)
        .block(block)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });

    frame.render_widget(paragraph, area);
}

fn render_header(frame: &mut Frame, area: Rect, state: &TuiState) {
    let header_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(52), // Left: Status & Telemetry
            Constraint::Percentage(48), // Right: Policies
        ])
        .split(area);

    render_status_panel(frame, header_chunks[0], state);
    render_policies_panel(frame, header_chunks[1], state);
}

fn render_status_panel(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;

    // Status pill (clean profile name)
    let (status_text, status_style) = if let Some(ref conn) = state.connecting {
        let elapsed = conn.started_at.elapsed();
        const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let spinner = SPINNER_FRAMES[(elapsed.as_millis() / 80) as usize % SPINNER_FRAMES.len()];
        if conn.is_disconnect {
            (
                format!(" Disconnecting: {} {spinner} ", conn.name),
                theme.status_pill_disconnected,
            )
        } else {
            (
                format!(" Connecting: {} {spinner} ", conn.name),
                theme.status_pill_connected,
            )
        }
    } else if let Some(ref name) = state.active_profile_name {
        (format!(" Connected: {name} "), theme.status_pill_connected)
    } else {
        (" Disconnected ".to_string(), theme.status_pill_disconnected)
    };

    let status_icon_style = if state.connecting.is_some() {
        theme.accent
    } else if state.active_profile_name.is_some() {
        theme.status_connected
    } else {
        theme.label_dim
    };
    let title = Line::from(vec![
        Span::styled(" 🌐 ", status_icon_style),
        Span::styled("Status ", theme.title),
    ]);

    let status_badge = Span::styled(status_text, status_style);

    // Dedicated Forwarded Port field (clean text, with icon).
    //
    // The port comes from the tray daemon, which owns the lease. When it is not
    // publishing one there is nothing renewing a port, so that is reported as
    // its own state rather than as a bare "N/A" -- otherwise a stopped daemon
    // looks like a provider that does not offer port forwarding.
    let (port_val, port_val_style) = if let Some(port) = state.forwarded_port() {
        (format!("{port}"), theme.accent)
    } else if !state.config.port_forwarding.enabled {
        ("Disabled".to_string(), theme.label_dim)
    } else if state.lease.is_none() {
        ("No daemon".to_string(), theme.warning)
    } else if state.active_profile_name.is_some() {
        ("N/A".to_string(), theme.label_dim)
    } else {
        ("--".to_string(), theme.label_dim)
    };
    let port_label = "🔌 Port: ";

    // Latency & Speed counters
    let latency_text = if state.connecting.is_some() {
        "⏱ handshake...".to_string()
    } else if let Some(ms) = state.latency_ms {
        format!("⏱ {ms}ms")
    } else {
        "⏱ --ms".to_string()
    };

    let down_speed = format_speed(state.download_rate);
    let up_speed = format_speed(state.upload_rate);
    let speed_text = format!("↓ {down_speed:<9}  ↑ {up_speed}");

    // Line 1: Status badge + Ping + Up/Down live speeds
    let line1 = Line::from(vec![
        Span::raw(" "),
        status_badge,
        Span::raw("  "),
        Span::styled(latency_text, theme.keybinding),
        Span::raw("    "),
        Span::styled(speed_text, theme.accent),
    ]);

    // Line 2: Public IP
    let pub_ip_text = if let Some(ref ip_info) = state.public_ip_info {
        ip_info.format_display()
    } else {
        "Detecting...".to_string()
    };
    let line2 = Line::from(vec![
        Span::styled(" Public IP: ", theme.label_dim),
        Span::styled(pub_ip_text, theme.text_primary),
    ]);

    // Line 3: DNS Resolver under Public IP + Port under/alongside DNS
    let dns_text = state
        .selected_info
        .as_ref()
        .and_then(|i| i.tunnel_dns.as_deref())
        .unwrap_or("N/A");
    let mut line3 = vec![
        Span::styled(" DNS:       ", theme.label_dim),
        Span::styled(dns_text, theme.accent),
        Span::raw("  "),
        Span::styled(port_label, theme.label_dim),
        Span::styled(port_val, port_val_style),
    ];
    line3.extend(qbit_sync_badge(state));
    let line3 = Line::from(line3);

    let status_widget = Paragraph::new(vec![line1, line2, line3])
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(theme.border)
                .title(title),
        );

    frame.render_widget(status_widget, area);
}

/// The qBittorrent port-sync badge for the status line, or nothing at all when
/// the integration is switched off -- it only describes that one feature, so it
/// would be noise for everyone who does not use it.
///
/// Styled with the same pills as the connection badge so it reads as live state
/// rather than as another static label.
#[cfg(feature = "qbittorrent")]
fn qbit_sync_badge(state: &TuiState) -> Vec<Span<'static>> {
    if !state.config.qbittorrent.enabled {
        return Vec::new();
    }

    let theme = &state.theme;
    let (label, style) = match state.qbit_sync() {
        Some(QbitSyncStatus::Synchronized) => {
            (" qBittorrent: Synced ", theme.status_pill_connected)
        }
        Some(QbitSyncStatus::Failed) => (" qBittorrent: Failed ", theme.status_pill_disconnected),
        Some(QbitSyncStatus::Pending) => (" qBittorrent: Pending ", theme.status_pill_disconnected),
        // The daemon performs the push, so without it there is no verdict to
        // report -- distinct from having pushed and failed.
        None => (" qBittorrent: No daemon ", theme.status_pill_disconnected),
    };

    vec![Span::raw("  "), Span::styled(label, style)]
}

/// No badge when the `qbittorrent` feature is compiled out.
#[cfg(not(feature = "qbittorrent"))]
fn qbit_sync_badge(_: &TuiState) -> Vec<Span<'static>> {
    Vec::new()
}

fn render_policies_panel(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;

    let toggle_status = |enabled: bool| {
        if enabled {
            ("ON", theme.status_connected)
        } else {
            ("OFF", theme.label_dim)
        }
    };

    let (auto_val, auto_val_style) = toggle_status(state.config.general.autoconnect_at_login);
    let (kill_val, kill_val_style) = toggle_status(state.config.kill_switch_enabled);
    let (lock_val, lock_val_style) = toggle_status(state.config.lockdown_enabled);
    let (pf_val, pf_val_style) = toggle_status(state.config.port_forwarding.enabled);

    let split_count = state.config.global_split_tunnel.cidrs.len()
        + state.config.global_split_tunnel.domains.len();

    let (split_val, split_val_style) = match state.config.global_split_tunnel.mode {
        SplitTunnelMode::Disabled => ("OFF".to_string(), theme.label_dim),
        SplitTunnelMode::Include => (format!("Include ({split_count})"), theme.accent),
        SplitTunnelMode::Exclude => (format!("Exclude ({split_count})"), theme.accent),
    };

    let col1_w = 34_usize;
    let auto_lead = "[a] Auto Connect: ";
    let auto_pad = col1_w.saturating_sub(auto_lead.len() + auto_val.len());

    let lock_lead = "[l] Lockdown Mode (root): ";
    let lock_pad = col1_w.saturating_sub(lock_lead.len() + lock_val.len());

    let line1 = Line::from(vec![
        Span::raw(" "),
        Span::styled(auto_lead, theme.text_primary),
        Span::styled(auto_val, auto_val_style),
        Span::raw(" ".repeat(auto_pad)),
        Span::styled("[k] Kill Switch: ", theme.text_primary),
        Span::styled(kill_val, kill_val_style),
    ]);

    let line2 = Line::from(vec![
        Span::raw(" "),
        Span::styled(lock_lead, theme.text_primary),
        Span::styled(lock_val, lock_val_style),
        Span::raw(" ".repeat(lock_pad)),
        Span::styled("[o] Port Forward: ", theme.text_primary),
        Span::styled(pf_val, pf_val_style),
    ]);

    let line3 = Line::from(vec![
        Span::raw(" "),
        Span::styled("[t] Split Tunneling: ", theme.text_primary),
        Span::styled(split_val, split_val_style),
    ]);

    let title = Line::from(vec![Span::styled(" 🛡  Policies ", theme.title)]);

    let policies_widget = Paragraph::new(vec![line1, line2, line3])
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(theme.border)
                .title(title),
        );

    frame.render_widget(policies_widget, area);
}

fn render_body(frame: &mut Frame, area: Rect, state: &TuiState) {
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40), // Left: Profile List
            Constraint::Percentage(60), // Right: Full Detail & Telemetry Panel
        ])
        .split(area);

    render_profile_list(frame, body_chunks[0], state);
    render_telemetry_panel(frame, body_chunks[1], state);
}

fn render_profile_list(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;

    // The selected row is padded out to here so its highlight is a solid bar.
    // Without it the backdrop grid stays visible past the end of the text and
    // the highlight looks like it has dots punched through it.
    let inner_width = area.width.saturating_sub(2) as usize;

    // Fixed column width for profile names so all markers align in their own columns
    let name_col_w = state
        .rows
        .iter()
        .map(|r| r.name.chars().count())
        .max()
        .unwrap_or(16)
        .max(18);

    let items: Vec<ListItem> = state
        .rows
        .iter()
        .enumerate()
        .map(|(idx, row)| {
            let is_selected = idx == state.selected_index;

            // Inactive rows get blank space rather than a marker, so only the
            // connected profile carries a glyph. The width matches "✔ " to keep
            // the name column aligned. While connecting, a live spinner cycles here.
            let is_connecting_row = state
                .connecting
                .as_ref()
                .map(|c| c.uuid == row.uuid)
                .unwrap_or(false);

            let (icon, icon_style) = if is_connecting_row {
                let elapsed = state.connecting.as_ref().unwrap().started_at.elapsed();
                const SPINNER_FRAMES: [&str; 10] =
                    ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                let spinner =
                    SPINNER_FRAMES[(elapsed.as_millis() / 80) as usize % SPINNER_FRAMES.len()];
                (format!("{spinner} "), theme.accent)
            } else if row.is_active {
                ("✔ ".to_string(), theme.status_connected)
            } else {
                ("  ".to_string(), theme.inactive_profile)
            };

            let prefix = if is_selected {
                SELECTED_POINTER
            } else {
                UNSELECTED_POINTER
            };

            let name_style = if row.is_active {
                theme.active_profile
            } else if is_selected {
                theme.title
            } else {
                theme.text_secondary
            };

            let (fav_icon, fav_style) = if row.is_favorite {
                ("★", theme.keybinding)
            } else {
                (" ", theme.label_dim)
            };

            let (excl_icon, excl_style) = if !row.eligible {
                ("⊘", theme.warning)
            } else {
                (" ", theme.label_dim)
            };

            let name_len = row.name.chars().count();
            let name_pad = name_col_w.saturating_sub(name_len);

            let spans = vec![
                Span::styled(prefix, theme.accent),
                Span::styled(icon, icon_style),
                Span::styled(&row.name, name_style),
                Span::raw(" ".repeat(name_pad)),
                Span::raw("   "),
                Span::styled(fav_icon, fav_style),
                Span::raw("   "),
                Span::styled(excl_icon, excl_style),
            ];

            let mut line = Line::from(spans);

            // Every row is padded to the full inner width so the backdrop grid
            // cannot show through past the end of the text. Without it the
            // selected row's highlight has dots punched through it and inactive
            // rows trail off into "wg-eu · · · ·".
            let padding = inner_width.saturating_sub(line.width());
            if padding > 0 {
                line.push_span(Span::raw(" ".repeat(padding)));
            }
            if is_selected {
                line = line.style(theme.selected_item);
            }

            ListItem::new(line)
        })
        .collect();

    let title = Line::from(vec![
        Span::styled(format!(" 📋 Profiles ({}) ", state.rows.len()), theme.title),
        Span::styled(" [↑/↓] ", theme.keybinding),
    ]);

    let list_widget = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(theme.active_border)
            .title(title),
    );

    frame.render_widget(list_widget, area);
}

fn render_telemetry_panel(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.border)
        .title(Span::styled(" 📋 Details ", theme.title));

    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let info = state.selected_info.as_ref();
    if let Some(row) = state.selected_row() {
        let mut lines = Vec::new();

        // Section: Overview
        lines.push(Line::from(vec![
            Span::styled("Profile:       ", theme.label_dim),
            Span::styled(&row.name, theme.title),
            Span::styled(format!("  ({})", row.uuid), theme.label_dim),
        ]));

        let (status_str, status_style) = if row.is_active {
            ("Connected (Active Tunnel)", theme.status_connected)
        } else {
            ("Inactive", theme.status_disconnected)
        };
        lines.push(Line::from(vec![
            Span::styled("Status:        ", theme.label_dim),
            Span::styled(status_str, status_style),
        ]));

        let (elig_str, elig_style) = if row.eligible {
            ("✔ In pool (may be auto-connected)", theme.status_connected)
        } else {
            ("✗ Excluded (never auto-connected)", theme.label_dim)
        };
        lines.push(Line::from(vec![
            Span::styled("Auto Connect:   ", theme.label_dim),
            Span::styled(elig_str, elig_style),
        ]));

        let (fav_str, fav_style) = if row.is_favorite {
            (
                "★ Favorite (pinned to tray quick actions)",
                theme.keybinding,
            )
        } else {
            ("No", theme.label_dim)
        };
        lines.push(Line::from(vec![
            Span::styled("Favorite:       ", theme.label_dim),
            Span::styled(fav_str, fav_style),
        ]));

        lines.push(Line::raw(""));

        // Section: Network & Routing
        if row.is_active {
            if let Some(addr) = info.and_then(|i| i.tunnel_address.as_ref()) {
                let gw_str = info
                    .and_then(|i| i.gateway.as_deref())
                    .map(|gw| format!("  (Gateway: {gw})"))
                    .unwrap_or_default();
                lines.push(Line::from(vec![
                    Span::styled("Tunnel IP:     ", theme.label_dim),
                    Span::styled(format!("{addr}{gw_str}"), theme.accent),
                ]));
            }

            if let Some(port) = state.forwarded_port() {
                lines.push(Line::from(vec![
                    Span::styled("NAT-PMP Port:  ", theme.label_dim),
                    Span::styled(format!("{port} (Leased & Auto-Renewing)"), theme.keybinding),
                ]));
            }
        }

        if let Some(dns) = info.and_then(|i| i.tunnel_dns.as_ref()) {
            lines.push(Line::from(vec![
                Span::styled("DNS Resolver:  ", theme.label_dim),
                Span::styled(format!("{dns} (VPN Priority -1500)"), theme.text_secondary),
            ]));
        }

        lines.push(Line::raw(""));

        // Section: Diagnostics & Link Stats
        if let Some(diag) = info.map(|i| &i.diagnostics) {
            lines.push(Line::from(vec![
                Span::styled("Remote Peer:   ", theme.label_dim),
                Span::styled(&diag.endpoint, theme.text_primary),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Total Data:    ", theme.label_dim),
                Span::styled(
                    format!("↑ {}  ↓ {}", diag.transfer_tx, diag.transfer_rx),
                    theme.accent,
                ),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Handshake:     ", theme.label_dim),
                Span::styled(&diag.latest_handshake, theme.text_secondary),
            ]));

            if diag.keepalive != "N/A" && !diag.keepalive.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("Keepalive:     ", theme.label_dim),
                    Span::styled(format!("{}s", diag.keepalive), theme.text_secondary),
                ]));
            }

            lines.push(Line::from(vec![
                Span::styled("Allowed IPs:   ", theme.label_dim),
                Span::styled(&diag.allowed_ips, theme.text_secondary),
            ]));
        }

        if let Some(ref custom) = row.custom_info {
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled("Config Info:   ", theme.label_dim),
                Span::styled(custom.replace('\n', " | "), theme.text_secondary),
            ]));
        }

        let content_len = lines.len() as u16;
        let panel = Paragraph::new(lines).wrap(Wrap { trim: true });
        frame.render_widget(panel, inner_area);

        let is_connected = row.is_active || state.active_profile_name.is_some();
        render_telemetry_watermark(frame, inner_area, content_len, is_connected, theme);
    } else {
        let is_connected = state.active_profile_name.is_some();
        render_empty_telemetry(frame, inner_area, is_connected, theme);
    }
}

fn watermark_static_spans<'a>(
    is_connected: bool,
    theme: &'a crate::tui::theme::Theme,
) -> (Vec<Span<'a>>, Vec<Span<'a>>, Vec<Span<'a>>) {
    let core_style = if is_connected {
        theme.accent
    } else {
        theme.label_dim
    };
    let grid_style = theme.backdrop_grid;

    // Line 1: NEUTRON (15 chars)
    let name_line = vec![Span::styled(" N E U T R O N ", theme.label_dim)];

    // Line 2: Particle Accelerator Logo (15 chars)
    let logo_line = vec![
        Span::styled("---==[ ", grid_style),
        Span::styled("⚛", core_style),
        Span::styled(" ]==---", grid_style),
    ];

    // Line 3: Network Manager in small caps (15 chars)
    let subtitle_line = vec![Span::styled("ɴᴇᴛᴡᴏʀᴋ ᴍᴀɴᴀɢᴇʀ", theme.backdrop_grid)];

    (name_line, logo_line, subtitle_line)
}

fn render_telemetry_watermark(
    frame: &mut Frame,
    inner_area: Rect,
    content_lines: u16,
    is_connected: bool,
    theme: &crate::tui::theme::Theme,
) {
    let watermark_height = 3;
    if inner_area.height > content_lines + watermark_height {
        let watermark_area = Rect {
            x: inner_area.x,
            y: inner_area.y + inner_area.height.saturating_sub(watermark_height),
            width: inner_area.width,
            height: watermark_height,
        };
        let (mut line1, mut line2, mut line3) = watermark_static_spans(is_connected, theme);

        // Pad each line with 3 spaces so right alignment keeps a clean right margin
        line1.push(Span::raw("   "));
        line2.push(Span::raw("   "));
        line3.push(Span::raw("   "));

        let watermark_lines = vec![Line::from(line1), Line::from(line2), Line::from(line3)];
        let watermark_widget = Paragraph::new(watermark_lines).alignment(Alignment::Right);
        frame.render_widget(watermark_widget, watermark_area);
    } else if inner_area.height >= content_lines + 2 {
        let watermark_area = Rect {
            x: inner_area.x,
            y: inner_area.y + inner_area.height.saturating_sub(1),
            width: inner_area.width,
            height: 1,
        };
        let icon_style = if is_connected {
            theme.accent
        } else {
            theme.label_dim
        };
        let watermark_line = Line::from(vec![
            Span::styled("⚛ ", icon_style),
            Span::styled("NEUTRON ", theme.label_dim),
            Span::styled("• ɴᴇᴛᴡᴏʀᴋ ᴍᴀɴᴀɢᴇʀ", theme.backdrop_grid),
            Span::raw("   "),
        ]);
        let watermark_widget = Paragraph::new(watermark_line).alignment(Alignment::Right);
        frame.render_widget(watermark_widget, watermark_area);
    }
}

fn render_empty_telemetry(
    frame: &mut Frame,
    area: Rect,
    is_connected: bool,
    theme: &crate::tui::theme::Theme,
) {
    let (line1, line2, line3) = watermark_static_spans(is_connected, theme);

    let empty_lines = vec![
        Line::raw(""),
        Line::from(line1),
        Line::from(line2),
        Line::from(line3),
        Line::raw(""),
        Line::styled("No profile selected.", theme.label_dim),
    ];
    let p = Paragraph::new(empty_lines).alignment(Alignment::Center);
    frame.render_widget(p, area);
}

/// A `[key] label` badge pair for the footer and modal hint rows.
fn key_item<'a>(
    theme: &'a crate::tui::theme::Theme,
    badge: Style,
    key: &'a str,
    label: &'a str,
) -> Vec<Span<'a>> {
    vec![
        Span::styled(format!(" {key} "), badge),
        Span::styled(format!(" {label} "), theme.text_primary),
    ]
}

/// Marks the selected row in every list. Declared once so the profile list, the
/// palette, the theme picker and the split-tunnel lists cannot drift apart.
const SELECTED_POINTER: &str = "▶ ";

/// Same width as [`SELECTED_POINTER`], for rows that are not selected.
const UNSELECTED_POINTER: &str = "  ";

/// Footer badges for keys that are not palette actions.
const FOOTER_ACCENT_KEYS: [(&str, &str); 2] = [("Ctrl+P", "Menu"), ("Ctrl+T", "Theme")];

/// Footer badges, with labels abbreviated to fit one row. Every key here must
/// also be a palette shortcut -- asserted by the tests below, so the two views
/// cannot drift.
const FOOTER_KEYS: [(&str, &str); 7] = [
    ("Space", "Connect"),
    ("s", "Switch"),
    ("f", "Favorite"),
    ("e", "Excl. Pool"),
    ("r", "Sync"),
    ("?", "Help"),
    ("q", "Quit"),
];

fn render_footer(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;

    let mut hotkeys = Vec::new();
    for (key, label) in FOOTER_ACCENT_KEYS {
        hotkeys.extend(key_item(theme, theme.key_badge_accent, key, label));
    }
    for (key, label) in FOOTER_KEYS {
        hotkeys.extend(key_item(theme, theme.key_badge, key, label));
    }

    let legend_spans = vec![
        Span::styled("Legend:  ", theme.label_dim),
        Span::styled("★ ", theme.keybinding),
        Span::styled("Favorite    ", theme.text_secondary),
        Span::styled("⊘ ", theme.warning),
        Span::styled("Excluded from pool", theme.text_secondary),
    ];

    let footer_widget = Paragraph::new(vec![Line::from(hotkeys), Line::from(legend_spans)])
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(theme.border),
        );

    frame.render_widget(footer_widget, area);
}

fn render_connecting_toast(
    frame: &mut Frame,
    area: Rect,
    conn: &crate::tui::state::ConnectingState,
    state: &TuiState,
) {
    let theme = &state.theme;
    let elapsed = conn.started_at.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();

    const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let spinner = SPINNER_FRAMES[(elapsed.as_millis() / 80) as usize % SPINNER_FRAMES.len()];

    let action_str = if conn.is_disconnect {
        format!("Disconnecting from {}... ({elapsed_secs:.1}s)", conn.name)
    } else {
        format!("Connecting to {}... ({elapsed_secs:.1}s)", conn.name)
    };

    let sub_str = if conn.is_disconnect {
        "Tearing down WireGuard interface..."
    } else {
        "Waiting for WireGuard handshake..."
    };

    let max_len = (action_str.chars().count() + 2).max(sub_str.chars().count()) as u16;
    let toast_w = (max_len + 6).clamp(38, area.width.saturating_sub(4).max(38));
    let toast_h = 4_u16;

    let toast_x = area.x + area.width.saturating_sub(toast_w + 2);
    let toast_y = area.y + 1;
    let toast_rect = Rect::new(toast_x, toast_y, toast_w, toast_h);

    frame.render_widget(Clear, toast_rect);

    let lines = vec![
        Line::from(vec![
            Span::styled(format!("{spinner} "), theme.accent),
            Span::styled(action_str, theme.title),
        ]),
        Line::from(Span::styled(sub_str, theme.text_secondary)),
    ];

    let p = Paragraph::new(lines)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::LEFT | Borders::RIGHT)
                .border_type(BorderType::Thick)
                .border_style(theme.active_border)
                .style(Style::default().bg(theme.toast_bg)),
        );

    frame.render_widget(p, toast_rect);
}

fn render_toast(frame: &mut Frame, area: Rect, toast: &crate::tui::state::Toast, state: &TuiState) {
    let theme = &state.theme;
    let max_w = (area.width.saturating_sub(4)).clamp(25, 60);
    let msg_len = toast.message.chars().count() as u16;
    let toast_w = (msg_len + 6).clamp(25, max_w);

    let content_w = toast_w.saturating_sub(4).max(1);
    let lines_count = msg_len.div_ceil(content_w).max(1);
    let toast_h = (lines_count + 2).min(area.height.saturating_sub(2));

    // Show toast notifications in the top-right corner
    let toast_x = area.x + area.width.saturating_sub(toast_w + 2);
    let toast_y = area.y + 1;
    let toast_rect = Rect::new(toast_x, toast_y, toast_w, toast_h);

    frame.render_widget(Clear, toast_rect);

    let (bg_color, border_style, text_style) = if toast.is_error {
        (theme.toast_error_bg, theme.warning, theme.warning)
    } else {
        (theme.toast_bg, theme.active_border, theme.title)
    };

    let msg_lines: Vec<Line> = toast
        .message
        .lines()
        .map(|l| Line::from(Span::styled(l, text_style)))
        .collect();

    let p = Paragraph::new(msg_lines)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::LEFT | Borders::RIGHT)
                .border_type(BorderType::Thick)
                .border_style(border_style)
                .style(Style::default().bg(bg_color)),
        );

    frame.render_widget(p, toast_rect);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn render_command_palette_modal(
    frame: &mut Frame,
    area: Rect,
    cp: &CommandPaletteState,
    state: &TuiState,
) {
    let theme = &state.theme;
    let popup_area = centered_rect(65, 50, area);

    frame.render_widget(Clear, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Search bar
            Constraint::Min(4),    // Commands list
            Constraint::Length(2), // Footer
        ])
        .margin(1)
        .split(popup_area);

    // Search bar
    let search_bar = Paragraph::new(Line::from(vec![
        Span::styled(" 🔍 > ", theme.accent),
        Span::styled(&cp.filter, theme.title),
        Span::styled("█", theme.accent),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme.active_border)
            .title(" Search Menu / Actions "),
    );
    frame.render_widget(search_bar, chunks[0]);

    // Filtered items
    let filtered = cp.filtered_items();
    let items: Vec<ListItem> = filtered
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let is_sel = idx == cp.selected_index;
            let mut spans = vec![
                Span::raw(" "),
                Span::styled(
                    if is_sel {
                        SELECTED_POINTER
                    } else {
                        UNSELECTED_POINTER
                    },
                    theme.accent,
                ),
                Span::styled(
                    item.title,
                    if is_sel {
                        theme.title
                    } else {
                        theme.text_primary
                    },
                ),
                Span::styled(format!(" — {}", item.description), theme.label_dim),
            ];

            if let Some(shortcut) = item.shortcut {
                spans.push(Span::raw(" "));
                spans.push(Span::styled(format!(" [{shortcut}] "), theme.key_badge));
            }

            let mut line = Line::from(spans);
            if is_sel {
                line = line.style(theme.selected_item);
            }
            ListItem::new(line)
        })
        .collect();

    let list_widget = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme.border)
            .title(format!(" Actions ({}) ", filtered.len())),
    );
    frame.render_widget(list_widget, chunks[1]);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled("[↑/↓] ", theme.keybinding),
        Span::raw("Navigate  "),
        Span::styled("[Enter] ", theme.keybinding),
        Span::raw("Run  "),
        Span::styled("[Esc] ", theme.keybinding),
        Span::raw("Close"),
    ]))
    .alignment(Alignment::Center);
    frame.render_widget(footer, chunks[2]);

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.active_border)
        .title(Span::styled(" Menu (Ctrl+P) ", theme.header));
    frame.render_widget(outer, popup_area);
}

fn render_theme_picker_modal(
    frame: &mut Frame,
    area: Rect,
    tp: &ThemePickerState,
    state: &TuiState,
) {
    let theme = &state.theme;
    let popup_area = centered_rect(55, 50, area);

    frame.render_widget(Clear, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length(2)])
        .margin(1)
        .split(popup_area);

    let items: Vec<ListItem> = tp
        .themes
        .iter()
        .enumerate()
        .map(|(idx, (id, label))| {
            let is_sel = idx == tp.selected_index;
            let is_active = *id == state.theme.name;

            let mut spans = vec![
                Span::raw(" "),
                Span::styled(
                    if is_sel {
                        SELECTED_POINTER
                    } else {
                        UNSELECTED_POINTER
                    },
                    theme.accent,
                ),
                Span::styled(
                    *label,
                    if is_sel {
                        theme.title
                    } else {
                        theme.text_primary
                    },
                ),
            ];

            if is_active {
                spans.push(Span::styled(" ✔ [ACTIVE]", theme.status_connected));
            }

            let mut line = Line::from(spans);
            if is_sel {
                line = line.style(theme.selected_item);
            }
            ListItem::new(line)
        })
        .collect();

    let list_widget = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme.active_border)
            .title(" Available Color Palettes "),
    );
    frame.render_widget(list_widget, chunks[0]);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled("[↑/↓] ", theme.keybinding),
        Span::raw("Select  "),
        Span::styled("[Enter] ", theme.keybinding),
        Span::raw("Apply Theme  "),
        Span::styled("[Esc] ", theme.keybinding),
        Span::raw("Cancel"),
    ]))
    .alignment(Alignment::Center);
    frame.render_widget(footer, chunks[1]);

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.active_border)
        .title(Span::styled(" 🎨 Select Color Theme ", theme.header));
    frame.render_widget(outer, popup_area);
}

/// List navigation, which moves the selection rather than running an action and
/// so has no entry in the palette.
const NAVIGATION_KEYS: [(&str, &str); 2] = [
    ("↑ / ↓ (or p / n)", "Move through the profile list"),
    ("Ctrl+P / :", "Open the command palette"),
];

fn render_help_modal(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;
    let popup_area = centered_rect(70, 80, area);

    frame.render_widget(Clear, popup_area);

    let mut lines = vec![Line::from(vec![Span::styled("Navigation", theme.header)])];
    for (key, description) in NAVIGATION_KEYS {
        lines.push(Line::from(vec![
            Span::styled(format!("  {key:<18}"), theme.keybinding),
            Span::raw(description),
        ]));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(vec![Span::styled("Actions", theme.header)]));

    // Rendered from the palette's own list, so a new action documents itself
    // and the help screen cannot drift out of step with what the keys do.
    for item in CommandPaletteState::all_items() {
        let key = item.shortcut.unwrap_or("—");
        lines.push(Line::from(vec![
            Span::styled(format!("  {key:<18}"), theme.keybinding),
            Span::raw(item.description),
        ]));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.active_border)
        .title(Span::styled(" Keybindings Help ", theme.title));

    let help_widget = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    frame.render_widget(help_widget, popup_area);
}

fn render_split_tunnel_modal(
    frame: &mut Frame,
    area: Rect,
    st: &SplitTunnelModalState,
    state: &TuiState,
) {
    let theme = &state.theme;
    let popup_area = centered_rect(75, 80, area);

    frame.render_widget(Clear, popup_area);

    let has_lockdown_warning = state.config.lockdown_enabled;

    let constraints = if has_lockdown_warning {
        vec![
            Constraint::Length(3), // Mode Selector
            Constraint::Length(2), // Lockdown warning banner
            Constraint::Min(6),    // Domains & CIDRs Columns
            Constraint::Length(2), // Controls footer
        ]
    } else {
        vec![
            Constraint::Length(3), // Mode Selector
            Constraint::Min(6),    // Domains & CIDRs Columns
            Constraint::Length(2), // Controls footer
        ]
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .margin(1)
        .split(popup_area);

    // 1. Mode Selector
    let mut mode_spans = vec![Span::styled(" Mode:  ", theme.text_secondary)];
    for (idx, mode) in SplitTunnelModalState::MODES.iter().enumerate() {
        let label = match mode {
            SplitTunnelMode::Disabled => "Disabled",
            SplitTunnelMode::Include => "Include",
            SplitTunnelMode::Exclude => "Exclude",
        };
        let is_current = st.mode == *mode;
        let is_cursor = st.focus == SplitTunnelFocus::Mode && st.highlighted_mode == idx;
        let text = format!(" [ {label} ] ");
        let style = if is_cursor && is_current {
            theme.selected_item
        } else if is_cursor {
            theme.key_badge_accent
        } else if is_current {
            theme.status_pill_connected
        } else {
            theme.key_badge
        };
        mode_spans.push(Span::styled(text, style));
        mode_spans.push(Span::raw("  "));
    }

    let mode_style = if st.focus == SplitTunnelFocus::Mode {
        theme.active_border
    } else {
        theme.border
    };

    let mode_block = Block::default()
        .borders(Borders::ALL)
        .border_style(mode_style)
        .title(Span::styled(
            " Routing Mode (←/→ Navigate, Space/Enter Select) ",
            theme.title,
        ));

    let mode_widget = Paragraph::new(Line::from(mode_spans)).block(mode_block);
    frame.render_widget(mode_widget, chunks[0]);

    let (columns_chunk, footer_chunk) = if has_lockdown_warning {
        // Lockdown Warning
        let warn_line = Line::from(vec![
            Span::styled(" ⚠ Lockdown Active: ", theme.warning),
            Span::styled(
                "All non-VPN traffic is blocked while disconnected. Excluded traffic will not route without an active tunnel.",
                theme.text_secondary,
            ),
        ]);
        let warn_widget = Paragraph::new(warn_line);
        frame.render_widget(warn_widget, chunks[1]);
        (chunks[2], chunks[3])
    } else {
        (chunks[1], chunks[2])
    };

    // 2. Side-by-Side Columns: Left = Domains, Right = Subnets / CIDRs
    let col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(columns_chunk);

    // Left Column: Domains
    render_entry_column(
        frame,
        col_chunks[0],
        EntryColumnParams {
            title: format!(" 🏷️  Domains ({}) ", st.domains.len()),
            input_title: " + Add Domain (Enter to add) ",
            input_value: &st.domain_input,
            is_input_focused: st.focus == SplitTunnelFocus::DomainInput,
            items: &st.domains,
            selected_idx: st.selected_domain,
            is_list_focused: st.focus == SplitTunnelFocus::DomainList,
            empty_label: "   (No domains added)",
        },
        theme,
    );

    // Right Column: Subnets / CIDRs
    render_entry_column(
        frame,
        col_chunks[1],
        EntryColumnParams {
            title: format!(" 🌐 Subnets / CIDRs ({}) ", st.cidrs.len()),
            input_title: " + Add CIDR / Subnet (Enter to add) ",
            input_value: &st.cidr_input,
            is_input_focused: st.focus == SplitTunnelFocus::CidrInput,
            items: &st.cidrs,
            selected_idx: st.selected_cidr,
            is_list_focused: st.focus == SplitTunnelFocus::CidrList,
            empty_label: "   (No subnets added)",
        },
        theme,
    );

    // 3. Footer instructions
    let mut modal_keys = Vec::new();
    for (key, label) in [
        ("Tab", "Panel"),
        ("←/→", "Switch"),
        ("↑/↓", "Select"),
        ("Space/Enter", "Select/Add"),
        ("Del/x", "Delete"),
        ("Esc", "Close"),
    ] {
        modal_keys.extend(key_item(theme, theme.key_badge, key, label));
    }

    let modal_footer = Paragraph::new(Line::from(modal_keys)).alignment(Alignment::Center);
    frame.render_widget(modal_footer, footer_chunk);

    let outer_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.active_border)
        .title(Span::styled(" Global Split Tunneling ", theme.title));
    frame.render_widget(outer_block, popup_area);
}

struct EntryColumnParams<'a> {
    title: String,
    input_title: &'static str,
    input_value: &'a str,
    is_input_focused: bool,
    items: &'a [String],
    selected_idx: usize,
    is_list_focused: bool,
    empty_label: &'static str,
}

fn render_entry_column(
    frame: &mut Frame,
    area: Rect,
    params: EntryColumnParams<'_>,
    theme: &crate::tui::theme::Theme,
) {
    let box_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(4)])
        .split(area);

    let input_style = if params.is_input_focused {
        theme.active_border
    } else {
        theme.border
    };
    let input_widget = Paragraph::new(Line::from(vec![
        Span::styled(params.input_value, theme.title),
        Span::styled(if params.is_input_focused { "█" } else { "" }, theme.accent),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(input_style)
            .title(params.input_title),
    );
    frame.render_widget(input_widget, box_chunks[0]);

    let list_style = if params.is_list_focused {
        theme.active_border
    } else {
        theme.border
    };
    let list_items: Vec<ListItem> = if params.items.is_empty() {
        vec![ListItem::new(Line::from(vec![Span::styled(
            params.empty_label,
            theme.label_dim,
        )]))]
    } else {
        params
            .items
            .iter()
            .enumerate()
            .map(|(idx, val)| {
                let is_sel = params.is_list_focused && idx == params.selected_idx;
                let line = Line::from(vec![
                    Span::styled(
                        if is_sel {
                            SELECTED_POINTER
                        } else {
                            UNSELECTED_POINTER
                        },
                        theme.accent,
                    ),
                    Span::styled(
                        val,
                        if is_sel {
                            theme.title
                        } else {
                            theme.text_secondary
                        },
                    ),
                ]);
                ListItem::new(line)
            })
            .collect()
    };
    let list_widget = List::new(list_items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(list_style)
            .title(params.title),
    );
    frame.render_widget(list_widget, box_chunks[1]);
}

fn render_confirm_delete_modal(frame: &mut Frame, area: Rect, name: &str, state: &TuiState) {
    let theme = &state.theme;
    let popup_area = centered_rect(50, 25, area);

    frame.render_widget(Clear, popup_area);

    let text = vec![
        Line::raw(""),
        Line::from(vec![
            Span::raw("Are you sure you want to permanently delete '"),
            Span::styled(name, theme.warning),
            Span::raw("' from NetworkManager?"),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  [y / Enter] ", theme.keybinding),
            Span::raw("Confirm Delete    "),
            Span::styled("[n / Esc] ", theme.keybinding),
            Span::raw("Cancel"),
        ]),
    ];

    let widget = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(theme.warning)
                .title(Span::styled(" Confirm Delete ", theme.warning)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(widget, popup_area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_footer_key_is_a_real_palette_shortcut() {
        // The footer abbreviates labels to fit one row, so it cannot render
        // straight from the palette -- but its keys must still be actions that
        // exist, or the row advertises a binding that does nothing.
        let shortcuts: Vec<&str> = CommandPaletteState::all_items()
            .into_iter()
            .filter_map(|item| item.shortcut)
            .collect();

        for (key, label) in FOOTER_KEYS {
            assert!(
                shortcuts.contains(&key),
                "footer offers '{key}' ({label}) but no palette action uses that key"
            );
        }
    }

    #[test]
    fn the_help_screen_documents_how_to_open_the_help_screen() {
        // Regression: the hand-written help modal listed neither `?` nor `h`,
        // so the only way to discover the Help key was to already know it.
        let documented: Vec<&str> = CommandPaletteState::all_items()
            .into_iter()
            .filter_map(|item| item.shortcut)
            .chain(NAVIGATION_KEYS.iter().map(|(key, _)| *key))
            .collect();

        assert!(documented.contains(&"?"));
        assert!(documented.iter().any(|key| key.contains("Ctrl+P")));
    }
}

#[cfg(test)]
mod render_tests {
    use super::*;
    use crate::app::profile_list::ProfileListRow;
    use crate::config::AppConfig;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn row(name: &str, is_active: bool) -> ProfileListRow {
        ProfileListRow {
            name: name.to_string(),
            uuid: format!("uuid-{name}"),
            is_active,
            state_label: if is_active { "active" } else { "inactive" },
            eligible: true,
            is_favorite: false,
            custom_info: None,
        }
    }

    /// Render just the profile list and return its rows as plain strings.
    fn rendered_list(rows: Vec<ProfileListRow>, selected: usize) -> Vec<String> {
        let mut state = TuiState::new(std::path::PathBuf::from("/tmp/x"), AppConfig::default());
        state.rows = rows;
        state.selected_index = selected;

        let mut terminal =
            Terminal::new(TestBackend::new(40, 6)).expect("test terminal should build");
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_profile_list(frame, area, &state);
            })
            .expect("draw should succeed");

        let buffer = terminal.backend().buffer().clone();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    /// Render just the policies panel and return its rows as plain strings.
    fn rendered_policies(config: AppConfig) -> Vec<String> {
        let state = TuiState::new(std::path::PathBuf::from("/tmp/x"), config);

        let mut terminal =
            Terminal::new(TestBackend::new(78, 5)).expect("test terminal should build");
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_policies_panel(frame, area, &state);
            })
            .expect("draw should succeed");

        let buffer = terminal.backend().buffer().clone();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn the_policies_panel_shows_consistent_spaced_policy_names() {
        let off = rendered_policies(AppConfig::default()).join("\n");
        assert!(
            off.contains("[a] Auto Connect:") && off.contains("OFF"),
            "Auto Connect must use space and render: {off}"
        );
        assert!(
            off.contains("[k] Kill Switch:") && off.contains("OFF"),
            "Kill Switch must use space and render: {off}"
        );
        assert!(
            off.contains("[l] Lockdown Mode (root):") && off.contains("OFF"),
            "Lockdown Mode (root) must render: {off}"
        );
        assert!(
            off.contains("[o] Port Forward:") && off.contains("OFF"),
            "Port Forward must render: {off}"
        );
        assert!(
            !off.contains("(51820)") && !off.contains("ON ("),
            "Port Forward toggle must not have port numbers in brackets: {off}"
        );
        assert!(
            off.contains("[t] Split Tunneling:") && off.contains("OFF"),
            "Split Tunneling must render: {off}"
        );
    }

    /// Render just the status panel and return it as one plain string.
    fn rendered_status(state: &TuiState) -> String {
        rendered_status_at(state, 78)
    }

    /// [`rendered_status`] at an explicit panel width, for the cases where the
    /// width is the thing under test.
    fn rendered_status_at(state: &TuiState, width: u16) -> String {
        let mut terminal =
            Terminal::new(TestBackend::new(width, 5)).expect("test terminal should build");
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_status_panel(frame, area, state);
            })
            .expect("draw should succeed");

        let buffer = terminal.backend().buffer().clone();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<String>>()
            .join("\n")
    }

    #[test]
    fn the_status_panel_shows_forwarded_port_with_icon() {
        let mut state = TuiState::new(std::path::PathBuf::from("/tmp/x"), AppConfig::default());
        state.active_profile_name = Some("wg-us".to_string());
        state.lease = Some(crate::service::lease::LeaseState {
            port: Some(51820),
            ..Default::default()
        });
        state.latency_ms = Some(42);

        let rendered = rendered_status(&state);

        assert!(
            rendered.contains('🔌') && rendered.contains("Port:") && rendered.contains("51820"),
            "status panel must render the port with icon: {rendered}"
        );
        assert!(
            rendered.contains("⏱ 42ms"),
            "status panel must render ping next to connected: {rendered}"
        );
        assert!(
            rendered.contains("Public IP:") && rendered.contains("DNS:"),
            "status panel must render public IP and DNS labels: {rendered}"
        );
    }

    #[cfg(feature = "qbittorrent")]
    mod qbittorrent_badge {
        use super::*;
        use crate::service::lease::{LeaseState, QbitSyncStatus};

        /// A connected tunnel whose lease the daemon is publishing, with
        /// qBittorrent sync switched on.
        fn synced_state(status: QbitSyncStatus) -> TuiState {
            let mut state = state_without_daemon();
            state.lease = Some(LeaseState {
                port: Some(51820),
                profile_uuid: Some("uuid-us".to_string()),
                qbit_sync: status,
                ..Default::default()
            });
            state
        }

        /// The same tunnel, but with no daemon publishing a lease.
        fn state_without_daemon() -> TuiState {
            let mut config = AppConfig::default();
            config.qbittorrent.enabled = true;
            config.port_forwarding.enabled = true;

            let mut state = TuiState::new(std::path::PathBuf::from("/tmp/x"), config);
            state.active_profile_name = Some("wg-us".to_string());
            state
        }

        #[test]
        fn the_badge_is_hidden_while_the_integration_is_switched_off() {
            // It describes one optional integration, so leaving it on screen for
            // everyone who does not use it would be noise -- and would read as a
            // failure, since nothing is ever synced.
            let mut state = synced_state(QbitSyncStatus::Synchronized);
            state.config.qbittorrent.enabled = false;

            let rendered = rendered_status(&state);

            assert!(
                !rendered.contains("qBittorrent"),
                "badge must stay hidden when auto-sync is off: {rendered}"
            );
        }

        #[test]
        fn the_badge_reports_a_lease_that_reached_qbittorrent() {
            let rendered = rendered_status(&synced_state(QbitSyncStatus::Synchronized));

            assert!(
                rendered.contains("qBittorrent: Synced"),
                "badge must report the synchronized lease: {rendered}"
            );
        }

        #[test]
        fn the_badge_reports_a_rejected_push() {
            let rendered = rendered_status(&synced_state(QbitSyncStatus::Failed));

            assert!(
                rendered.contains("qBittorrent: Failed"),
                "badge must report the failure: {rendered}"
            );
        }

        #[test]
        fn the_badge_shares_the_connection_status_highlight() {
            // The badge is meant to read as live state, like the Connected pill,
            // rather than as another static label sitting next to it.
            let theme = &synced_state(QbitSyncStatus::Pending).theme;
            let connected = theme.status_pill_connected;
            let disconnected = theme.status_pill_disconnected;

            let styled = |status| {
                qbit_sync_badge(&synced_state(status))
                    .into_iter()
                    .map(|span| span.style)
                    .collect::<Vec<_>>()
            };

            assert!(styled(QbitSyncStatus::Synchronized).contains(&connected));
            assert!(styled(QbitSyncStatus::Failed).contains(&disconnected));
            assert!(styled(QbitSyncStatus::Pending).contains(&disconnected));
        }

        #[test]
        fn without_a_daemon_the_badge_says_so_rather_than_reporting_a_failure() {
            // The daemon performs the push, so with no daemon there is no
            // verdict. Showing "Failed" would blame qBittorrent for a service
            // that was never asked, and "Synced" would be a plain lie.
            let rendered = rendered_status(&state_without_daemon());

            assert!(
                rendered.contains("qBittorrent: No daemon"),
                "an absent daemon must be named as such: {rendered}"
            );
        }

        #[test]
        fn without_a_daemon_the_port_is_not_shown_as_unsupported() {
            // A stopped daemon and a provider that offers no port forwarding are
            // different problems with different fixes, so they must not both
            // render as "N/A".
            let rendered = rendered_status(&state_without_daemon());

            assert!(
                rendered.contains("No daemon"),
                "the port field must distinguish a stopped daemon: {rendered}"
            );
        }

        #[test]
        fn the_status_line_still_fits_the_minimum_terminal_width() {
            // The badge shares a line with DNS and the forwarded port. The status
            // panel gets 52% of the window, so at MIN_WIDTH the three together
            // have ~60 columns; overflowing wraps onto a fourth line that the
            // 5-row header clips, which would silently drop the badge entirely.
            let mut state = synced_state(QbitSyncStatus::Failed);
            state.selected_info = Some(crate::tui::state::CachedProfileInfo {
                tunnel_dns: Some("10.2.0.1".to_string()),
                ..Default::default()
            });

            let rendered = rendered_status_at(&state, MIN_WIDTH * 52 / 100);

            assert!(
                rendered.contains("DNS:") && rendered.contains("10.2.0.1"),
                "DNS must survive at the minimum width: {rendered}"
            );
            assert!(
                rendered.contains("51820"),
                "the forwarded port must survive at the minimum width: {rendered}"
            );
            assert!(
                rendered.contains("qBittorrent: Failed"),
                "the badge must survive at the minimum width: {rendered}"
            );
        }
    }

    #[test]
    fn the_toast_notification_renders_when_active() {
        let mut state = TuiState::new(std::path::PathBuf::from("/tmp/x"), AppConfig::default());
        state.set_status("VPN connected successfully");

        let mut terminal =
            Terminal::new(TestBackend::new(120, 30)).expect("test terminal should build");
        terminal
            .draw(|frame| {
                render(frame, &state);
            })
            .expect("draw should succeed");

        let buffer = terminal.backend().buffer().clone();
        let rendered = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<String>>()
            .join("\n");

        let toast_line = rendered
            .lines()
            .find(|l| l.contains("VPN connected successfully"))
            .expect("toast must render");
        assert!(
            !toast_line.contains("Notification"),
            "toast notification must not contain 'Notification' title: {toast_line}"
        );
        assert!(
            !toast_line.contains('✔'),
            "toast notification must not contain checkmarks: {toast_line}"
        );
    }

    #[test]
    fn terminal_window_size_warning_on_small_dimensions() {
        let state = TuiState::new(std::path::PathBuf::from("/tmp/x"), AppConfig::default());

        let mut terminal =
            Terminal::new(TestBackend::new(80, 24)).expect("test terminal should build");
        terminal
            .draw(|frame| {
                render(frame, &state);
            })
            .expect("draw should succeed");

        let buffer = terminal.backend().buffer().clone();
        let rendered = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<String>>()
            .join("\n");

        assert!(
            rendered.contains("Terminal window too small") && rendered.contains("120x30"),
            "size warning must render when below minimal size: {rendered}"
        );
    }

    #[test]
    fn favorite_profile_shows_star_indicator() {
        let mut fav_row = row("wg-fav", false);
        fav_row.is_favorite = true;
        let lines = rendered_list(vec![fav_row, row("wg-other", false)], 0);

        let fav_line = lines
            .iter()
            .find(|line| line.contains("wg-fav"))
            .expect("favorite row should render");

        assert!(
            fav_line.contains('★'),
            "favorite row must contain ★ marker: {fav_line}"
        );
    }

    #[test]
    fn excluded_profile_shows_excluded_indicator() {
        let mut excl_row = row("wg-excl", false);
        excl_row.eligible = false;
        let lines = rendered_list(vec![excl_row, row("wg-other", false)], 0);

        let excl_line = lines
            .iter()
            .find(|line| line.contains("wg-excl"))
            .expect("excluded row should render");

        assert!(
            excl_line.contains('⊘'),
            "excluded row must contain ⊘ marker: {excl_line}"
        );
    }

    #[test]
    fn the_selected_row_highlight_is_solid_bar() {
        let lines = rendered_list(vec![row("wg-eu", false), row("wg-us", false)], 0);
        let selected = lines
            .iter()
            .find(|line| line.contains("wg-eu"))
            .expect("the selected row should render");

        assert!(
            !selected.contains('·'),
            "selected row must be padded cleanly: {selected:?}"
        );
    }

    #[test]
    fn inactive_rows_carry_no_marker_and_the_active_row_keeps_its_tick() {
        let lines = rendered_list(vec![row("wg-eu", false), row("wg-us", true)], 1);

        let inactive = lines
            .iter()
            .find(|line| line.contains("wg-eu"))
            .expect("inactive row should render");
        assert!(
            !inactive.contains('·'),
            "inactive profiles must not be marked with a dot: {inactive:?}"
        );

        let active = lines
            .iter()
            .find(|line| line.contains("wg-us"))
            .expect("active row should render");
        assert!(active.contains('✔'), "{active:?}");
    }

    #[test]
    fn the_selected_row_is_marked_with_a_triangle_pointer() {
        let lines = rendered_list(vec![row("wg-eu", false), row("wg-us", false)], 1);

        let selected = lines
            .iter()
            .find(|line| line.contains("wg-us"))
            .expect("selected row should render");
        assert!(
            selected.contains('▶'),
            "expected the triangle pointer: {selected:?}"
        );
        assert!(!selected.contains('►'), "the old arrow must be gone");
    }

    #[test]
    fn details_panel_renders_watermark_when_empty() {
        let state = TuiState::new(std::path::PathBuf::from("/tmp/x"), AppConfig::default());
        let mut terminal =
            Terminal::new(TestBackend::new(60, 20)).expect("test terminal should build");
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_telemetry_panel(frame, area, &state);
            })
            .expect("draw should succeed");

        let buffer = terminal.backend().buffer().clone();
        let rendered = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<String>>()
            .join("\n");

        assert!(
            rendered.contains('⚛') && rendered.contains("N E U T R O N"),
            "empty details panel must render watermark emblem: {rendered}"
        );
        assert!(
            rendered.contains("No profile selected"),
            "empty details panel must state no profile selected: {rendered}"
        );
    }

    #[test]
    fn details_panel_renders_watermark_when_profile_selected() {
        let mut state = TuiState::new(std::path::PathBuf::from("/tmp/x"), AppConfig::default());
        state.rows = vec![row("wg-eu", false)];
        state.selected_index = 0;

        let mut terminal =
            Terminal::new(TestBackend::new(70, 25)).expect("test terminal should build");
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_telemetry_panel(frame, area, &state);
            })
            .expect("draw should succeed");

        let buffer = terminal.backend().buffer().clone();
        let rendered = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<String>>()
            .join("\n");

        assert!(
            rendered.contains("Profile:") && rendered.contains("wg-eu"),
            "details panel must render profile info: {rendered}"
        );
        assert!(
            rendered.contains('⚛') && rendered.contains("N E U T R O N"),
            "details panel must render watermark in empty bottom space: {rendered}"
        );
    }

    #[test]
    fn footer_renders_legend() {
        let state = TuiState::new(std::path::PathBuf::from("/tmp/x"), AppConfig::default());
        let mut terminal =
            Terminal::new(TestBackend::new(120, 4)).expect("test terminal should build");
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_footer(frame, area, &state);
            })
            .expect("draw should succeed");

        let buffer = terminal.backend().buffer().clone();
        let rendered = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<String>>()
            .join("\n");

        assert!(
            rendered.contains("Legend:")
                && rendered.contains('★')
                && rendered.contains('⊘')
                && !rendered.contains('✔'),
            "footer must render legend with favorite and exclusion icons: {rendered}"
        );
    }

    #[test]
    fn connecting_state_animates_status_pill_and_profile_row() {
        let mut state = TuiState::new(std::path::PathBuf::from("/tmp/x"), AppConfig::default());
        state.rows = vec![row("wg-cz", false), row("wg-us", false)];
        state.connecting = Some(crate::tui::state::ConnectingState {
            uuid: "uuid-wg-cz".to_string(),
            name: "wg-cz".to_string(),
            is_disconnect: false,
            started_at: std::time::Instant::now(),
        });

        let mut terminal =
            Terminal::new(TestBackend::new(120, 30)).expect("test terminal should build");
        terminal
            .draw(|frame| {
                render(frame, &state);
            })
            .expect("draw should succeed");

        let buffer = terminal.backend().buffer().clone();
        let rendered = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<String>>()
            .join("\n");

        assert!(
            rendered.contains("Connecting: wg-cz"),
            "status pill must show connecting state: {rendered}"
        );
        assert!(
            rendered.contains("Waiting for WireGuard handshake"),
            "connecting toast must render handshake wait notice: {rendered}"
        );
        assert!(
            rendered.contains("⏱ handshake..."),
            "latency counter should show handshake probing: {rendered}"
        );
    }
}
