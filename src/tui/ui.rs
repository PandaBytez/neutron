//! Ratatui rendering engine, widget layouts, and Command Palette modals.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
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
    let theme = &state.theme;

    // Render subtle themed textured backdrop
    render_backdrop(frame, size, theme);

    let show_ascii = size.height >= 26;
    let banner_h = if show_ascii { 3 } else { 0 };

    // Overall vertical layout: ASCII Banner (if height permits), Header, Body, Footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(banner_h), // Centered ASCII title logo
            Constraint::Length(5),        // Header with Status, Bandwidth, Latency & Policies
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
        Line::styled(" _  _ ____ _  _ ___ ____ ____ _  _ ", theme.header),
        Line::styled(" |\\ | |___ |  |  |  |__/ |  | |\\ | ", theme.accent),
        Line::styled(" | \\| |___ |__|  |  |  \\ |__| | \\| ", theme.header),
    ];

    let banner = Paragraph::new(ascii_lines).alignment(Alignment::Center);
    frame.render_widget(banner, area);
}

fn render_backdrop(frame: &mut Frame, area: Rect, theme: &crate::tui::theme::Theme) {
    let mut pattern_lines = Vec::with_capacity(area.height as usize);
    for y in 0..area.height {
        let mut row = String::with_capacity(area.width as usize);
        for x in 0..area.width {
            if (x + y * 2) % 6 == 0 {
                row.push('·');
            } else {
                row.push(' ');
            }
        }
        pattern_lines.push(Line::styled(row, theme.backdrop_grid));
    }
    let backdrop = Paragraph::new(pattern_lines);
    frame.render_widget(backdrop, area);
}

fn render_header(frame: &mut Frame, area: Rect, state: &TuiState) {
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

    let title = Line::from(vec![
        Span::styled(" ⚡ NEUTRON ", theme.header),
        Span::raw("— WireGuard Manager "),
        Span::styled(format!("[Theme: {}]", state.theme.name), theme.label_dim),
    ]);

    let status_badge = Span::styled(status_text, status_style);

    // Dedicated Forwarded Port field (clean text, no background pill)
    let (port_label, port_val, port_val_style) = if let Some(port) = state.active_port {
        ("Forwarded Port: ", format!("{port}"), theme.accent)
    } else if state.active_profile_name.is_some() {
        ("Forwarded Port: ", "N/A".to_string(), theme.label_dim)
    } else {
        ("Forwarded Port: ", "--".to_string(), theme.label_dim)
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

    // Line 1: Status badge + Forwarded Port + Latency + Bandwidth rates
    let line1 = Line::from(vec![
        Span::raw(" "),
        status_badge,
        Span::raw("   "),
        Span::styled(port_label, theme.label_dim),
        Span::styled(port_val, port_val_style),
        Span::raw("   "),
        Span::styled(latency_text, theme.keybinding),
        Span::raw("    "),
        Span::styled(speed_text, theme.accent),
    ]);

    // Line 2: Public IP & DNS telemetry
    let ip_text = if let Some(ref ip_info) = state.public_ip_info {
        ip_info.format_display()
    } else {
        "Detecting public IP...".to_string()
    };

    let mut info_spans = vec![
        Span::styled(" Public IP: ", theme.label_dim),
        Span::styled(ip_text, theme.text_primary),
    ];

    if let Some(ref dns) = state.selected_tunnel_dns {
        info_spans.push(Span::styled("  •  DNS: ", theme.label_dim));
        info_spans.push(Span::styled(dns, theme.accent));
    }
    let line2 = Line::from(info_spans);

    // Line 3: Merged Policies
    let auto_mark = if state.config.general.autoconnect_at_login {
        Span::styled("✔ ", theme.status_connected)
    } else {
        Span::styled("· ", theme.label_dim)
    };

    let kill_mark = if state.config.kill_switch_enabled {
        Span::styled("✔ ", theme.status_connected)
    } else {
        Span::styled("· ", theme.label_dim)
    };

    let lock_mark = if state.config.lockdown_enabled {
        Span::styled("✔ ", theme.status_connected)
    } else {
        Span::styled("· ", theme.label_dim)
    };

    let split_mode = state.config.global_split_tunnel.mode;
    let split_count = state.config.global_split_tunnel.cidrs.len()
        + state.config.global_split_tunnel.domains.len();

    let split_desc = match split_mode {
        SplitTunnelMode::Disabled => "Off".to_string(),
        SplitTunnelMode::Include => format!("Include ({split_count})"),
        SplitTunnelMode::Exclude => format!("Exclude ({split_count})"),
    };

    let line3 = Line::from(vec![
        Span::styled(" Policies: ", theme.label_dim),
        auto_mark,
        Span::styled("[a] Auto-Connect", theme.text_primary),
        Span::raw("   "),
        kill_mark,
        Span::styled("[k] Kill-Switch", theme.text_primary),
        Span::raw("   "),
        lock_mark,
        Span::styled("[l] Lockdown", theme.text_primary),
        Span::raw("   "),
        Span::styled(format!("[t] Split Tunneling: {split_desc}"), theme.accent),
    ]);

    let header_widget = Paragraph::new(vec![line1, line2, line3]).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(theme.border)
            .title(title),
    );

    frame.render_widget(header_widget, area);
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

    let items: Vec<ListItem> = state
        .rows
        .iter()
        .enumerate()
        .map(|(idx, row)| {
            let is_selected = idx == state.selected_index;

            let (icon, icon_style) = if row.is_active {
                ("✔ ", theme.status_connected)
            } else {
                ("· ", theme.inactive_profile)
            };

            let prefix = if is_selected { "► " } else { "  " };

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
                spans.push(Span::styled(" [EXCLUDED]", theme.label_dim));
            }

            let mut line = Line::from(spans);
            if is_selected {
                line = line.style(theme.selected_item);
            }

            ListItem::new(line)
        })
        .collect();

    let title = Line::from(vec![
        Span::styled(format!(" Profiles ({}) ", state.rows.len()), theme.title),
        Span::styled(
            " [↑/↓ Select, Space Connect, e Auto-pool] ",
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

    let content = if let Some(row) = state.selected_row() {
        let mut lines = Vec::new();

        // Section: Overview
        lines.push(Line::from(vec![
            Span::styled("Profile:       ", theme.label_dim),
            Span::styled(&row.name, theme.title),
            Span::styled(format!("  ({})", &row.uuid), theme.label_dim),
        ]));

        let (status_str, status_style) = if row.is_active {
            ("✔ Connected (Active Tunnel)", theme.status_connected)
        } else {
            ("· Inactive", theme.status_disconnected)
        };
        lines.push(Line::from(vec![
            Span::styled("Status:        ", theme.label_dim),
            Span::styled(status_str, status_style),
        ]));

        let (elig_str, elig_style) = if row.eligible {
            ("✔ Eligible for Random Startup", theme.status_connected)
        } else {
            ("✗ Excluded from Startup Pool", theme.label_dim)
        };
        lines.push(Line::from(vec![
            Span::styled("Startup Pool:  ", theme.label_dim),
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

            if let Some(ref addr) = state.selected_tunnel_address {
                let gw_str = state
                    .selected_gateway
                    .as_deref()
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

        if let Some(ref dns) = state.selected_tunnel_dns {
            lines.push(Line::from(vec![
                Span::styled("DNS Resolver:  ", theme.label_dim),
                Span::styled(format!("{dns} (VPN Priority -1500)"), theme.text_secondary),
            ]));
        }

        lines.push(Line::raw(""));

        // Section: Diagnostics & Link Stats
        if let Some(ref diag) = state.selected_diagnostics {
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
            .title(Span::styled(" Profile Details & Telemetry ", theme.title)),
    );

    frame.render_widget(panel, area);
}

fn key_item<'a>(
    theme: &'a crate::tui::theme::Theme,
    key: &'a str,
    label: &'a str,
) -> Vec<Span<'a>> {
    vec![
        Span::styled(format!(" {key} "), theme.key_badge),
        Span::styled(format!(" {label}  "), theme.text_primary),
    ]
}

fn key_item_accent<'a>(
    theme: &'a crate::tui::theme::Theme,
    key: &'a str,
    label: &'a str,
) -> Vec<Span<'a>> {
    vec![
        Span::styled(format!(" {key} "), theme.key_badge_accent),
        Span::styled(format!(" {label}  "), theme.title),
    ]
}

fn render_footer(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;

    let mut hotkeys = Vec::new();
    hotkeys.extend(key_item_accent(theme, "Ctrl+P", "Menu"));
    hotkeys.extend(key_item_accent(theme, "Ctrl+T", "Theme"));
    hotkeys.extend(key_item(theme, "Space", "Connect/Down"));
    hotkeys.extend(key_item(theme, "s", "Switch"));
    hotkeys.extend(key_item(theme, "e", "Auto-pool"));
    hotkeys.extend(key_item(theme, "t", "Split Tunneling"));
    hotkeys.extend(key_item(theme, "k", "KillSwitch"));
    hotkeys.extend(key_item(theme, "l", "Lockdown"));
    hotkeys.extend(key_item(theme, "a", "AutoLogin"));
    hotkeys.extend(key_item(theme, "r", "Sync"));
    hotkeys.extend(key_item(theme, "?", "Help"));
    hotkeys.extend(key_item(theme, "q", "Quit"));

    let mut footer_lines = vec![Line::from(hotkeys)];
    if !state.status_message.is_empty() {
        footer_lines.push(Line::from(vec![
            Span::styled(" Status: ", theme.label_dim),
            Span::styled(&state.status_message, theme.title),
        ]));
    }

    let footer_widget = Paragraph::new(footer_lines).block(
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
                Span::styled(if is_sel { " ► " } else { "   " }, theme.accent),
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
                Span::styled(if is_sel { " ► " } else { "   " }, theme.accent),
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

fn render_help_modal(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;
    let popup_area = centered_rect(65, 75, area);

    frame.render_widget(Clear, popup_area);

    let lines = vec![
        Line::from(vec![Span::styled("General & Menu", theme.header)]),
        Line::from(vec![
            Span::styled("  Ctrl+P / :       ", theme.keybinding),
            Span::raw("Open Menu"),
        ]),
        Line::from(vec![
            Span::styled("  Ctrl+T           ", theme.keybinding),
            Span::raw("Open Theme Picker"),
        ]),
        Line::raw(""),
        Line::from(vec![Span::styled("Navigation & Connections", theme.header)]),
        Line::from(vec![
            Span::styled("  ↑ / ↓ (or p / n) ", theme.keybinding),
            Span::raw("Navigate profile list"),
        ]),
        Line::from(vec![
            Span::styled("  Space / Enter    ", theme.keybinding),
            Span::raw("Connect or Disconnect selected profile"),
        ]),
        Line::from(vec![
            Span::styled("  s                ", theme.keybinding),
            Span::raw("Switch to selected profile"),
        ]),
        Line::from(vec![
            Span::styled("  e                ", theme.keybinding),
            Span::raw("Toggle startup-random eligibility"),
        ]),
        Line::from(vec![
            Span::styled("  d / Delete       ", theme.keybinding),
            Span::raw("Delete profile from NetworkManager"),
        ]),
        Line::raw(""),
        Line::from(vec![Span::styled("Global Security Controls", theme.header)]),
        Line::from(vec![
            Span::styled("  t                ", theme.keybinding),
            Span::raw("Open Split Tunneling manager modal"),
        ]),
        Line::from(vec![
            Span::styled("  k                ", theme.keybinding),
            Span::raw("Toggle Kill Switch (NM policy routing)"),
        ]),
        Line::from(vec![
            Span::styled("  l                ", theme.keybinding),
            Span::raw("Toggle Lockdown mode (Always-on firewall)"),
        ]),
        Line::from(vec![
            Span::styled("  a                ", theme.keybinding),
            Span::raw("Toggle Auto-Connect at Login"),
        ]),
        Line::from(vec![
            Span::styled("  r                ", theme.keybinding),
            Span::raw("Refresh & Auto-sync profiles drop folder"),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  Esc / q          ", theme.keybinding),
            Span::raw("Close modal / Quit"),
        ]),
    ];

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
                Span::styled(if is_sel { "► " } else { "  " }, theme.accent),
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
                Span::styled(if is_sel { "► " } else { "  " }, theme.accent),
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
    modal_keys.extend(key_item(theme, "Tab", "Focus"));
    modal_keys.extend(key_item(theme, "m", "Mode"));
    modal_keys.extend(key_item(theme, "1", "Add CIDR"));
    modal_keys.extend(key_item(theme, "2", "Add Domain"));
    modal_keys.extend(key_item(theme, "x/Del", "Delete"));
    modal_keys.extend(key_item(theme, "Ctrl+S", "Save & Apply"));
    modal_keys.extend(key_item(theme, "Esc", "Cancel"));

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
