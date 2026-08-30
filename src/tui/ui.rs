//! Ratatui rendering engine, widget layouts, and Command Palette modals.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph, Wrap};

use crate::config::SplitTunnelMode;
use crate::nm::network_info::format_speed;
use crate::tui::state::{
    ActiveModal, CommandPaletteState, SplitTunnelFocus, SplitTunnelModalState, ThemePickerState,
    TuiState,
};

pub fn render(frame: &mut Frame, state: &TuiState) {
    let size = frame.area();

    let show_ascii = size.height >= 26;
    let banner_h = if show_ascii { 3 } else { 0 };

    // Overall vertical layout: ASCII Banner (if height permits), Header, Body, Footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(banner_h), // Centered ASCII title logo
            Constraint::Length(5),        // Header with Status & Policies panels
            Constraint::Min(10),          // Main body: Left List, Right Full Detail
            Constraint::Length(4),        // Footer / Hotkeys + Status line
        ])
        .split(size);

    if show_ascii {
        render_ascii_banner(frame, chunks[0], state);
    }
    render_header(frame, chunks[1], state);
    render_body(frame, chunks[2], state);
    render_footer(frame, chunks[3], state);

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
}

fn render_ascii_banner(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;

    let ascii_lines = vec![
        Line::from(vec![
            Span::styled(" █\\  █ █▀▀█ █  █ ▀█▀ █▀▀█ █▀▀█ █\\  █", theme.header),
            Span::styled("░", theme.label_dim),
        ]),
        Line::from(vec![
            Span::styled(" █ \\ █ █▀▀  █  █  █  █▄▄▀ █  █ █ \\ █", theme.accent),
            Span::styled("░", theme.label_dim),
        ]),
        Line::from(vec![
            Span::styled(" █  \\█ ▀▀▀▀  ▀▀   ▀  ▀  ▀ ▀▀▀▀ █  \\█", theme.header),
            Span::styled("░", theme.label_dim),
        ]),
    ];

    let banner = Paragraph::new(ascii_lines).alignment(Alignment::Center);
    frame.render_widget(banner, area);
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
    let (status_text, status_style) = if let Some(ref name) = state.active_profile_name {
        (
            format!(" ✔ Connected: {name} "),
            theme.status_pill_connected,
        )
    } else {
        (
            " ○ Disconnected ".to_string(),
            theme.status_pill_disconnected,
        )
    };

    let title = Line::from(vec![Span::styled(" ⚡ Status ", theme.title)]);

    let status_badge = Span::styled(status_text, status_style);

    // Dedicated Forwarded Port field (clean text, no background pill)
    let (port_label, port_val, port_val_style) = if let Some(port) = state.active_port {
        ("Port: ", format!("{port}"), theme.accent)
    } else if state.active_profile_name.is_some() {
        if !state.config.port_forwarding.enabled {
            ("Port: ", "Disabled".to_string(), theme.label_dim)
        } else {
            ("Port: ", "N/A".to_string(), theme.label_dim)
        }
    } else {
        ("Port: ", "--".to_string(), theme.label_dim)
    };

    // Latency & Speed counters
    let latency_text = if let Some(ms) = state.latency_ms {
        format!("⏱ {ms}ms")
    } else {
        "⏱ --ms".to_string()
    };

    let down_speed = format_speed(state.download_rate);
    let up_speed = format_speed(state.upload_rate);
    let speed_text = format!("↓ {down_speed:<9}  ↑ {up_speed}");

    // Line 1: Status badge + Forwarded Port
    let line1 = Line::from(vec![
        Span::raw(" "),
        status_badge,
        Span::raw("   "),
        Span::styled(port_label, theme.label_dim),
        Span::styled(port_val, port_val_style),
    ]);

    // Line 2: Ping & D/U on the next line under connected
    let line2 = Line::from(vec![
        Span::raw(" "),
        Span::styled(latency_text, theme.keybinding),
        Span::raw("    "),
        Span::styled(speed_text, theme.accent),
    ]);

    // Line 3: Public IP & DNS telemetry
    let ip_text = if let Some(ref ip_info) = state.public_ip_info {
        ip_info.format_display()
    } else {
        "Detecting public IP...".to_string()
    };

    let mut info_spans = vec![
        Span::styled(" IP: ", theme.label_dim),
        Span::styled(ip_text, theme.text_primary),
    ];

    if let Some(dns) = state
        .selected_info
        .as_ref()
        .and_then(|i| i.tunnel_dns.as_ref())
    {
        info_spans.push(Span::styled("  •  DNS: ", theme.label_dim));
        info_spans.push(Span::styled(dns, theme.accent));
    }
    let line3 = Line::from(info_spans);

    let status_widget = Paragraph::new(vec![line1, line2, line3]).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(theme.border)
            .title(title),
    );

    frame.render_widget(status_widget, area);
}

fn render_policies_panel(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;

    let (auto_val, auto_val_style) = if state.config.general.autoconnect_at_login {
        ("ON", theme.status_connected)
    } else {
        ("OFF", theme.label_dim)
    };

    let (kill_val, kill_val_style) = if state.config.kill_switch_enabled {
        ("ON", theme.status_connected)
    } else {
        ("OFF", theme.label_dim)
    };

    let (lock_val, lock_val_style) = if state.config.lockdown_enabled {
        ("ON", theme.status_connected)
    } else {
        ("OFF", theme.label_dim)
    };

    // The leased port is the useful part, so it is shown in place of a bare
    // "ON" once the gateway has granted one.
    let (pf_val, pf_val_style) = match (state.config.port_forwarding.enabled, state.active_port) {
        (false, _) => ("OFF".to_string(), theme.label_dim),
        (true, Some(port)) => (format!("ON ({port})"), theme.status_connected),
        (true, None) => ("ON".to_string(), theme.status_connected),
    };

    let split_count = state.config.global_split_tunnel.cidrs.len()
        + state.config.global_split_tunnel.domains.len();

    let (split_val, split_val_style) = match state.config.global_split_tunnel.mode {
        SplitTunnelMode::Disabled => ("OFF".to_string(), theme.label_dim),
        SplitTunnelMode::Include => (format!("Include ({split_count})"), theme.accent),
        SplitTunnelMode::Exclude => (format!("Exclude ({split_count})"), theme.accent),
    };

    let line1 = Line::from(vec![
        Span::raw(" "),
        Span::styled("[a] Auto-Connect: ", theme.text_primary),
        Span::styled(auto_val, auto_val_style),
        Span::raw("    "),
        Span::styled("[k] Kill-Switch: ", theme.text_primary),
        Span::styled(kill_val, kill_val_style),
    ]);

    let line2 = Line::from(vec![
        Span::raw(" "),
        Span::styled("[l] Lockdown: ", theme.text_primary),
        Span::styled(lock_val, lock_val_style),
        Span::raw("       "),
        Span::styled("[f] Port Forward: ", theme.text_primary),
        Span::styled(pf_val, pf_val_style),
    ]);

    let line3 = Line::from(vec![
        Span::raw(" "),
        Span::styled("[t] Split Tunneling: ", theme.text_primary),
        Span::styled(split_val, split_val_style),
    ]);

    let title = Line::from(vec![Span::styled(" 🛡  Policies ", theme.title)]);

    let policies_widget = Paragraph::new(vec![line1, line2, line3]).block(
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

    let items: Vec<ListItem> = state
        .rows
        .iter()
        .enumerate()
        .map(|(idx, row)| {
            let is_selected = idx == state.selected_index;

            // Inactive rows get blank space rather than a marker, so only the
            // connected profile carries a glyph. The width matches "✔ " to keep
            // the name column aligned.
            let (icon, icon_style) = if row.is_active {
                ("✔ ", theme.status_connected)
            } else {
                ("  ", theme.inactive_profile)
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

            let mut spans = vec![
                Span::styled(prefix, theme.accent),
                Span::styled(icon, icon_style),
                Span::styled(&row.name, name_style),
            ];

            if !row.eligible {
                spans.push(Span::styled(" [EXCLUDED FROM POOL]", theme.label_dim));
            }

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
        Span::styled(
            " [↑/↓ Select, Space Connect, e Exclude from pool] ",
            theme.keybinding,
        ),
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

    let info = state.selected_info.as_ref();
    let content = if let Some(row) = state.selected_row() {
        let mut lines = Vec::new();

        // Section: Overview
        lines.push(Line::from(vec![
            Span::styled("Profile:       ", theme.label_dim),
            Span::styled(&row.name, theme.title),
            Span::styled(format!("  ({})", row.uuid), theme.label_dim),
        ]));

        let (status_str, status_style) = if row.is_active {
            ("✔ Connected (Active Tunnel)", theme.status_connected)
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
            Span::styled("Auto-Connect:  ", theme.label_dim),
            Span::styled(elig_str, elig_style),
        ]));

        lines.push(Line::raw(""));

        // Section: Network & Routing
        if row.is_active {
            if let Some(ref ip_info) = state.public_ip_info {
                lines.push(Line::from(vec![
                    Span::styled("Public IP:     ", theme.label_dim),
                    Span::styled(ip_info.format_display(), theme.text_primary),
                ]));
            }

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

            if let Some(port) = state.active_port {
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

        lines
    } else {
        vec![Line::styled("No profile selected.", theme.label_dim)]
    };

    let panel = Paragraph::new(content).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(theme.border)
            .title(Span::styled(" 📊 Details ", theme.title)),
    );

    frame.render_widget(panel, area);
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
        Span::styled(format!(" {label}  "), theme.text_primary),
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
const FOOTER_KEYS: [(&str, &str); 11] = [
    ("Space", "Connect/Down"),
    ("s", "Switch"),
    ("e", "Excl. from pool"),
    ("t", "Split Tunneling"),
    ("k", "KillSwitch"),
    ("l", "Lockdown"),
    ("f", "PortFwd"),
    ("a", "AutoLogin"),
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

    let mut footer_lines = vec![Line::from(hotkeys)];
    if !state.status_message.is_empty() {
        let (label, style) = if state.status_is_error {
            (" ✖ ", theme.status_disconnected)
        } else {
            (" Status: ", theme.label_dim)
        };
        footer_lines.push(Line::from(vec![
            Span::styled(label, style),
            Span::styled(
                &state.status_message,
                if state.status_is_error {
                    theme.warning
                } else {
                    theme.title
                },
            ),
        ]));
    }

    // Wrapped so a long diagnosis stays readable instead of being clipped at
    // the panel edge -- the explanation is the useful part of a failure.
    let footer_widget = Paragraph::new(footer_lines)
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
    let popup_area = centered_rect(70, 75, area);

    frame.render_widget(Clear, popup_area);

    let mode_str = match st.mode {
        SplitTunnelMode::Disabled => "[ Disabled ]  Include   Exclude  ",
        SplitTunnelMode::Include => "  Disabled  [ Include ]  Exclude  ",
        SplitTunnelMode::Exclude => "  Disabled   Include  [ Exclude ]",
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Mode Selector
            Constraint::Length(3), // Input Row
            Constraint::Min(5),    // CIDRs & Domains Lists
            Constraint::Length(2), // Controls footer
        ])
        .margin(1)
        .split(popup_area);

    // Mode Selector
    let mode_style = if st.focus == SplitTunnelFocus::Mode {
        theme.active_border
    } else {
        theme.border
    };

    let mode_block = Block::default()
        .borders(Borders::ALL)
        .border_style(mode_style)
        .title(Span::styled(
            " [m] Routing Mode (Tab to switch) ",
            theme.title,
        ));

    let mode_widget =
        Paragraph::new(Line::from(vec![Span::styled(mode_str, theme.accent)])).block(mode_block);
    frame.render_widget(mode_widget, chunks[0]);

    // Input Bar
    let input_title = match st.focus {
        SplitTunnelFocus::CidrInput => " Add Subnet / CIDR (Enter to add): ",
        SplitTunnelFocus::DomainInput => " Add Domain Name (Enter to add): ",
        _ => " Input (Select input tab below): ",
    };

    let input_widget = Paragraph::new(Line::from(vec![
        Span::styled(&st.input_buffer, theme.title),
        Span::styled("█", theme.accent),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme.border)
            .title(input_title),
    );
    frame.render_widget(input_widget, chunks[1]);

    // Lists
    let list_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[2]);

    // CIDR List
    let cidr_items: Vec<ListItem> = st
        .cidrs
        .iter()
        .enumerate()
        .map(|(idx, c)| {
            let is_sel = st.focus == SplitTunnelFocus::CidrList && idx == st.selected_cidr;
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
                    c,
                    if is_sel {
                        theme.title
                    } else {
                        theme.text_secondary
                    },
                ),
            ]);
            ListItem::new(line)
        })
        .collect();

    let cidr_list_widget = List::new(cidr_items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(if st.focus == SplitTunnelFocus::CidrList {
                theme.active_border
            } else {
                theme.border
            })
            .title(format!(" CIDRs ({}) ", st.cidrs.len())),
    );
    frame.render_widget(cidr_list_widget, list_chunks[0]);

    // Domain List
    let domain_items: Vec<ListItem> = st
        .domains
        .iter()
        .enumerate()
        .map(|(idx, d)| {
            let is_sel = st.focus == SplitTunnelFocus::DomainList && idx == st.selected_domain;
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
                    d,
                    if is_sel {
                        theme.title
                    } else {
                        theme.text_secondary
                    },
                ),
            ]);
            ListItem::new(line)
        })
        .collect();

    let domain_list_widget = List::new(domain_items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(if st.focus == SplitTunnelFocus::DomainList {
                theme.active_border
            } else {
                theme.border
            })
            .title(format!(" Domains ({}) ", st.domains.len())),
    );
    frame.render_widget(domain_list_widget, list_chunks[1]);

    // Footer instructions
    let mut modal_keys = Vec::new();
    for (key, label) in [
        ("Tab", "Focus"),
        ("m", "Mode"),
        ("1", "Add CIDR"),
        ("2", "Add Domain"),
        ("x/Del", "Delete"),
        ("Ctrl+S", "Save & Apply"),
        ("Esc", "Cancel"),
    ] {
        modal_keys.extend(key_item(theme, theme.key_badge, key, label));
    }

    let modal_footer = Paragraph::new(Line::from(modal_keys)).alignment(Alignment::Center);
    frame.render_widget(modal_footer, chunks[3]);

    let outer_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.active_border)
        .title(Span::styled(
            " Global Split Tunneling Manager ",
            theme.title,
        ));
    frame.render_widget(outer_block, popup_area);
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
    fn rendered_policies(config: AppConfig, active_port: Option<u16>) -> Vec<String> {
        let mut state = TuiState::new(std::path::PathBuf::from("/tmp/x"), config);
        state.active_port = active_port;

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
    fn the_policies_panel_shows_port_forwarding_and_its_leased_port() {
        // Port forwarding is a policy like the kill switch and lockdown, so it
        // has to be visible and readable at a glance -- not buried in a config
        // file. The leased port is the part the user actually needs.
        let off = rendered_policies(AppConfig::default(), None).join("\n");
        assert!(
            off.contains("[f] Port Forward:") && off.contains("OFF"),
            "the toggle and its key must render when off: {off}"
        );

        let mut on = AppConfig::default();
        on.port_forwarding.enabled = true;
        let leased = rendered_policies(on, Some(51820)).join("\n");
        assert!(
            leased.contains("51820"),
            "a leased port must be shown next to the toggle: {leased}"
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
}
