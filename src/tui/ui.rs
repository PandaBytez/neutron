//! Ratatui rendering engine and widget layouts.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph, Wrap};

use crate::config::SplitTunnelMode;
use crate::tui::state::{ActiveModal, SplitTunnelFocus, SplitTunnelModalState, TuiState};

pub fn render(frame: &mut Frame, state: &TuiState) {
    let size = frame.area();

    // Overall vertical layout: Header, Body, Footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Main body
            Constraint::Length(3), // Footer / Hotkeys
        ])
        .split(size);

    render_header(frame, chunks[0], state);
    render_body(frame, chunks[1], state);
    render_footer(frame, chunks[2], state);

    // Overlay Modals
    match &state.modal {
        ActiveModal::Help => render_help_modal(frame, size, state),
        ActiveModal::SplitTunnel(st) => render_split_tunnel_modal(frame, size, st, state),
        ActiveModal::ConfirmDelete { name, .. } => {
            render_confirm_delete_modal(frame, size, name, state)
        }
        ActiveModal::None => {}
    }
}

fn render_header(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;

    let (status_text, status_style) = if let Some(ref name) = state.active_profile_name {
        let text = if let Some(port) = state.active_port {
            format!(" ● Connected: {name} (Port: {port}) ")
        } else {
            format!(" ● Connected: {name} ")
        };
        (text, theme.status_pill_connected)
    } else {
        (
            " ○ Disconnected ".to_string(),
            theme.status_pill_disconnected,
        )
    };

    let title = Line::from(vec![
        Span::styled(" ⚡ NEUTRON ", theme.header),
        Span::raw("— WireGuard Manager "),
    ]);

    let status_badge = Span::styled(status_text, status_style);

    let header_widget = Paragraph::new(Line::from(vec![Span::raw(" "), status_badge])).block(
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
            Constraint::Percentage(45), // Left: Profile List
            Constraint::Percentage(55), // Right: Telemetry & Security
        ])
        .split(area);

    render_profile_list(frame, body_chunks[0], state);
    render_right_panel(frame, body_chunks[1], state);
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
                ("● ", theme.status_connected)
            } else {
                ("○ ", theme.inactive_profile)
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
        Span::styled(" [↑/↓ Nav] ", theme.keybinding),
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

fn render_right_panel(frame: &mut Frame, area: Rect, state: &TuiState) {
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(45), // Top: Global Security & Policies
            Constraint::Percentage(55), // Bottom: Telemetry & Connection Details
        ])
        .split(area);

    render_security_panel(frame, right_chunks[0], state);
    render_telemetry_panel(frame, right_chunks[1], state);
}

fn render_telemetry_panel(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;

    let content = if let Some(row) = state.selected_row() {
        let mut lines = Vec::new();

        lines.push(Line::from(vec![
            Span::styled("Selected:    ", theme.label_dim),
            Span::styled(&row.name, theme.title),
            Span::styled(format!(" ({})", &row.uuid), theme.label_dim),
        ]));

        lines.push(Line::from(vec![
            Span::styled("State:       ", theme.label_dim),
            if row.is_active {
                Span::styled("Connected", theme.status_connected)
            } else {
                Span::styled("Inactive", theme.status_disconnected)
            },
        ]));

        if let Some(ref diag) = state.selected_diagnostics {
            lines.push(Line::from(vec![
                Span::styled("Endpoint:    ", theme.label_dim),
                Span::styled(&diag.endpoint, theme.text_primary),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Transfer:    ", theme.label_dim),
                Span::styled(
                    format!("↑ {}  ↓ {}", diag.transfer_tx, diag.transfer_rx),
                    theme.accent,
                ),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Handshake:   ", theme.label_dim),
                Span::styled(&diag.latest_handshake, theme.text_secondary),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Allowed IPs: ", theme.label_dim),
                Span::styled(&diag.allowed_ips, theme.text_secondary),
            ]));
        }

        if let Some(ref custom) = row.custom_info {
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled("Config Info: ", theme.label_dim),
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
            .title(Span::styled(" Connection Telemetry ", theme.title)),
    );

    frame.render_widget(panel, area);
}

fn render_security_panel(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;

    let autoconnect_mark = if state.config.general.autoconnect_at_login {
        "[x]"
    } else {
        "[ ]"
    };
    let kill_switch_mark = if state.config.kill_switch_enabled {
        "[x]"
    } else {
        "[ ]"
    };
    let lockdown_mark = if state.config.lockdown_enabled {
        "[x]"
    } else {
        "[ ]"
    };
    let split_mode = state.config.global_split_tunnel.mode;
    let split_count = state.config.global_split_tunnel.cidrs.len()
        + state.config.global_split_tunnel.domains.len();

    let split_desc = match split_mode {
        SplitTunnelMode::Disabled => "Disabled (Full Tunnel)".to_string(),
        SplitTunnelMode::Include => format!("Include ({split_count} routes)"),
        SplitTunnelMode::Exclude => format!("Exclude ({split_count} routes)"),
    };

    let lines = vec![
        Line::from(vec![Span::styled(
            format!("{autoconnect_mark} [a] Auto-Connect at Login"),
            theme.text_primary,
        )]),
        Line::from(vec![
            Span::styled(
                format!("{kill_switch_mark} [k] Kill Switch "),
                theme.text_primary,
            ),
            Span::styled("(NM Policy Routing)", theme.label_dim),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{lockdown_mark} [l] Lockdown Mode "),
                theme.text_primary,
            ),
            Span::styled("(Always-On Netfilter)", theme.label_dim),
        ]),
        Line::from(vec![
            Span::styled("    [t] Split Tunneling: ", theme.text_primary),
            Span::styled(split_desc, theme.accent),
        ]),
        Line::from(vec![Span::styled(
            format!("    [p] Drop Folder: {}", state.config.general.profiles_dir),
            theme.label_dim,
        )]),
    ];

    let panel = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(theme.border)
            .title(Line::from(vec![
                Span::styled(" Global Security & Policies ", theme.title),
                Span::styled(" [a, k, l, t] ", theme.keybinding),
            ])),
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

fn render_footer(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;

    let mut hotkeys = Vec::new();
    hotkeys.extend(key_item(theme, "Space", "Connect/Down"));
    hotkeys.extend(key_item(theme, "s", "Switch"));
    hotkeys.extend(key_item(theme, "t", "Split"));
    hotkeys.extend(key_item(theme, "k", "Kill-Switch"));
    hotkeys.extend(key_item(theme, "l", "Lockdown"));
    hotkeys.extend(key_item(theme, "a", "Auto-Login"));
    hotkeys.extend(key_item(theme, "e", "Eligible"));
    hotkeys.extend(key_item(theme, "r", "Sync"));
    hotkeys.extend(key_item(theme, "d", "Delete"));
    hotkeys.extend(key_item(theme, "?", "Help"));
    hotkeys.extend(key_item(theme, "q", "Quit"));

    let log_line = Line::from(vec![
        Span::styled(" Status: ", theme.label_dim),
        Span::styled(&state.status_message, theme.title),
    ]);

    let footer_widget = Paragraph::new(vec![log_line, Line::from(hotkeys)]).block(
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

fn render_help_modal(frame: &mut Frame, area: Rect, state: &TuiState) {
    let theme = &state.theme;
    let popup_area = centered_rect(65, 70, area);

    frame.render_widget(Clear, popup_area);

    let lines = vec![
        Line::from(vec![Span::styled("Navigation & Connections", theme.header)]),
        Line::from(vec![
            Span::styled("  ↑ / k, ↓ / j     ", theme.keybinding),
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
        Line::from(vec![Span::styled("Global Controls", theme.header)]),
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
