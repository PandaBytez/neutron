//! State model for the Terminal User Interface.

use std::path::PathBuf;

use crate::app::profile_list::ProfileListRow;
use crate::config::{AppConfig, SplitTunnelConfig, SplitTunnelMode};
use crate::nm::ProfileDiagnostics;
use crate::nm::network_info::PublicIpInfo;
use crate::tui::theme::Theme;

/// The index after `index`, wrapping to the start. Yields 0 for an empty list.
pub fn wrap_next(index: usize, len: usize) -> usize {
    if len == 0 { 0 } else { (index + 1) % len }
}

/// The index before `index`, wrapping to the end. Yields 0 for an empty list.
pub fn wrap_prev(index: usize, len: usize) -> usize {
    if len == 0 { 0 } else { (index + len - 1) % len }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveModal {
    None,
    Help,
    CommandPalette(CommandPaletteState),
    ThemePicker(ThemePickerState),
    SplitTunnel(SplitTunnelModalState),
    ConfirmDelete { name: String, uuid: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPaletteItem {
    /// The action id passed to
    /// [`execute_action`](crate::tui::events::execute_action).
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub shortcut: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPaletteState {
    pub filter: String,
    pub selected_index: usize,
    pub items: Vec<CommandPaletteItem>,
}

impl Default for CommandPaletteState {
    fn default() -> Self {
        Self {
            filter: String::new(),
            selected_index: 0,
            items: Self::all_items(),
        }
    }
}

impl CommandPaletteState {
    /// Every action the palette offers.
    ///
    /// This is the palette's view of
    /// [`execute_action`](crate::tui::events::execute_action); each `id` must be
    /// one that dispatcher implements. Keep it in step with `action_for_key` --
    /// the tests in [`crate::tui::events`] fail if a key-bound action is missing
    /// from this list.
    pub fn all_items() -> Vec<CommandPaletteItem> {
        vec![
            CommandPaletteItem {
                id: "toggle",
                title: "Connection: Connect or Disconnect Selected Profile",
                description: "Bring the selected profile up, or take it down if it is active",
                shortcut: Some("Space"),
            },
            CommandPaletteItem {
                id: "switch",
                title: "Connection: Switch to Selected Profile",
                description: "Drop the active tunnel and connect the selected profile",
                shortcut: Some("s"),
            },
            CommandPaletteItem {
                id: "disconnect",
                title: "Connection: Disconnect Active Profile",
                description: "Take down whichever WireGuard tunnel is currently up",
                shortcut: None,
            },
            CommandPaletteItem {
                id: "eligible",
                title: "Auto-Connect Pool: Exclude or Include Selected Profile",
                description: "Excluded profiles are never picked by the random login selector",
                shortcut: Some("e"),
            },
            CommandPaletteItem {
                id: "autoconnect",
                title: "Auto-Connect at Login: Toggle",
                description: "Connect a random profile from the pool when you log in",
                shortcut: Some("a"),
            },
            CommandPaletteItem {
                id: "split_tunnel",
                title: "Split Tunneling: Open Manager",
                description: "Choose which subnets and domains use the VPN",
                shortcut: Some("t"),
            },
            CommandPaletteItem {
                id: "kill_switch",
                title: "Kill Switch: Toggle",
                description: "Force NetworkManager policy routing so a failed tunnel drops traffic",
                shortcut: Some("k"),
            },
            CommandPaletteItem {
                id: "lockdown",
                title: "Lockdown: Toggle Always-On Firewall",
                description: "Block all traffic except the tunnel, its handshake, DNS and the LAN",
                shortcut: Some("l"),
            },
            CommandPaletteItem {
                id: "sync",
                title: "Profiles: Sync Drop Directory",
                description: "Import new .conf files from ~/.config/neutron/profiles",
                shortcut: Some("r"),
            },
            CommandPaletteItem {
                id: "delete",
                title: "Profiles: Delete Selected Profile",
                description: "Permanently remove the profile from NetworkManager",
                shortcut: Some("d"),
            },
            #[cfg(feature = "qbittorrent")]
            CommandPaletteItem {
                id: "qbit_sync",
                title: "qBittorrent: Sync Forwarded Port Now",
                description: "Push active VPN NAT-PMP port to local qBittorrent WebUI",
                shortcut: None,
            },
            #[cfg(feature = "qbittorrent")]
            CommandPaletteItem {
                id: "qbit_toggle",
                title: "qBittorrent: Toggle Auto-Sync",
                description: "Automatically sync dynamic NAT-PMP ports with qBittorrent",
                shortcut: None,
            },
            CommandPaletteItem {
                id: "theme",
                title: "Theme: Switch Color Palette",
                description: "Osaka Jade, Catppuccin Mocha, Nord, Gruvbox or Monochrome",
                shortcut: Some("Ctrl+T"),
            },
            CommandPaletteItem {
                id: "help",
                title: "Help: Show Keybindings",
                description: "List every shortcut available in the main view",
                shortcut: Some("?"),
            },
            CommandPaletteItem {
                id: "quit",
                title: "Quit Neutron",
                description: "Leave the interface; any active tunnel stays up",
                shortcut: Some("q"),
            },
        ]
    }

    pub fn filtered_items(&self) -> Vec<&CommandPaletteItem> {
        let query = self.filter.trim().to_lowercase();
        if query.is_empty() {
            return self.items.iter().collect();
        }
        self.items
            .iter()
            .filter(|item| {
                item.title.to_lowercase().contains(&query)
                    || item.description.to_lowercase().contains(&query)
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemePickerState {
    pub selected_index: usize,
    pub themes: Vec<(&'static str, &'static str)>,
}

impl Default for ThemePickerState {
    fn default() -> Self {
        Self {
            selected_index: 0,
            themes: vec![
                ("osaka-jade", "Osaka Jade"),
                ("catppuccin-mocha", "Catppuccin Mocha"),
                ("nord", "Nord (Arctic Frost)"),
                ("gruvbox", "Gruvbox Dark"),
                ("monochrome", "Monochrome (High-Contrast)"),
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitTunnelFocus {
    Mode,
    CidrInput,
    CidrList,
    DomainInput,
    DomainList,
}

impl SplitTunnelFocus {
    /// The tab order, which [`Self::next`] and [`Self::prev`] walk in each
    /// direction. Declared once so the two cannot disagree.
    const ORDER: [Self; 5] = [
        Self::Mode,
        Self::CidrInput,
        Self::CidrList,
        Self::DomainInput,
        Self::DomainList,
    ];

    /// Whether this focus is a text field, in which case printable keys are
    /// typed into the buffer rather than treated as shortcuts.
    pub fn is_text_input(self) -> bool {
        matches!(self, Self::CidrInput | Self::DomainInput)
    }

    fn position(self) -> usize {
        Self::ORDER.iter().position(|f| *f == self).unwrap_or(0)
    }

    pub fn next(self) -> Self {
        Self::ORDER[wrap_next(self.position(), Self::ORDER.len())]
    }

    pub fn prev(self) -> Self {
        Self::ORDER[wrap_prev(self.position(), Self::ORDER.len())]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitTunnelModalState {
    pub mode: SplitTunnelMode,
    pub cidrs: Vec<String>,
    pub domains: Vec<String>,
    pub focus: SplitTunnelFocus,
    pub input_buffer: String,
    pub selected_cidr: usize,
    pub selected_domain: usize,
}

impl SplitTunnelModalState {
    pub fn from_config(st: &SplitTunnelConfig) -> Self {
        Self {
            mode: st.mode,
            cidrs: st.cidrs.clone(),
            domains: st.domains.clone(),
            focus: SplitTunnelFocus::Mode,
            input_buffer: String::new(),
            selected_cidr: 0,
            selected_domain: 0,
        }
    }

    pub fn to_config(&self) -> SplitTunnelConfig {
        SplitTunnelConfig {
            mode: self.mode,
            cidrs: self.cidrs.clone(),
            domains: self.domains.clone(),
        }
    }
}

/// Everything the details pane shows about one profile.
///
/// Held as a single value rather than as loose parallel fields on [`TuiState`],
/// so the pane can never render one profile's address next to another's
/// diagnostics.
#[derive(Debug, Clone, Default)]
pub struct CachedProfileInfo {
    pub diagnostics: ProfileDiagnostics,
    pub tunnel_address: Option<String>,
    pub tunnel_dns: Option<String>,
    pub gateway: Option<String>,
}

pub struct TuiState {
    pub config_path: PathBuf,
    pub config: AppConfig,
    pub theme: Theme,
    pub rows: Vec<ProfileListRow>,
    pub profile_cache: std::collections::HashMap<String, CachedProfileInfo>,
    pub selected_index: usize,
    pub selected_info: Option<CachedProfileInfo>,
    pub active_profile_name: Option<String>,
    pub active_port: Option<u16>,
    /// The profile [`Self::active_port`] was leased for, so the blocking NAT-PMP
    /// round trip is only repeated when the tunnel actually changes.
    pub active_port_uuid: Option<String>,
    pub public_ip_info: Option<PublicIpInfo>,
    pub download_rate: u64,
    pub upload_rate: u64,
    pub latency_ms: Option<u32>,
    pub last_net_sample: Option<(std::time::Instant, u64, u64)>,
    pub status_message: String,
    /// Whether [`Self::status_message`] reports a failure, so the footer can
    /// style it as one instead of burying it among routine confirmations.
    pub status_is_error: bool,
    pub modal: ActiveModal,
    pub should_quit: bool,
}

impl TuiState {
    pub fn new(config_path: PathBuf, config: AppConfig) -> Self {
        let theme = Theme::from_config(&config.theme);
        Self {
            config_path,
            config,
            theme,
            rows: Vec::new(),
            profile_cache: std::collections::HashMap::new(),
            selected_index: 0,
            selected_info: None,
            active_profile_name: None,
            active_port: None,
            active_port_uuid: None,
            public_ip_info: None,
            download_rate: 0,
            upload_rate: 0,
            latency_ms: None,
            last_net_sample: None,
            status_message: String::new(),
            status_is_error: false,
            modal: ActiveModal::None,
            should_quit: false,
        }
    }

    pub fn update_throughput(&mut self) {
        let now = std::time::Instant::now();
        let (rx, tx) = crate::nm::network_info::read_interface_bytes(None);
        let Some((prev_time, prev_rx, prev_tx)) = self.last_net_sample else {
            self.last_net_sample = Some((now, rx, tx));
            return;
        };

        let elapsed = now.duration_since(prev_time).as_secs_f64();
        if elapsed >= 0.2 {
            self.download_rate = (rx.saturating_sub(prev_rx) as f64 / elapsed).round() as u64;
            self.upload_rate = (tx.saturating_sub(prev_tx) as f64 / elapsed).round() as u64;
            self.last_net_sample = Some((now, rx, tx));
        }
    }

    /// Report a completed action in the footer.
    pub fn set_status(&mut self, message: impl Into<String>) {
        self.status_message = message.into();
        self.status_is_error = false;
    }

    /// Report a failed action in the footer. Kept distinct from
    /// [`Self::set_status`] so an error cannot be mistaken for a success.
    pub fn set_error(&mut self, error: &crate::error::AppError) {
        self.status_message = error.to_string();
        self.status_is_error = true;
    }

    pub fn selected_row(&self) -> Option<&ProfileListRow> {
        self.rows.get(self.selected_index)
    }

    /// The selected profile's `(uuid, name, is_active)`, owned so callers can
    /// mutate `self` while acting on it.
    pub fn selected_identity(&self) -> Option<(String, String, bool)> {
        self.selected_row()
            .map(|row| (row.uuid.clone(), row.name.clone(), row.is_active))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_helpers_cycle_in_both_directions() {
        assert_eq!(wrap_next(0, 3), 1);
        assert_eq!(wrap_next(2, 3), 0);
        assert_eq!(wrap_prev(0, 3), 2);
        assert_eq!(wrap_prev(1, 3), 0);
    }

    #[test]
    fn wrap_helpers_are_safe_on_an_empty_list() {
        // Every list in the UI can be empty (no profiles, no CIDRs), so these
        // must not underflow or divide by zero.
        assert_eq!(wrap_next(0, 0), 0);
        assert_eq!(wrap_prev(0, 0), 0);
    }

    #[test]
    fn split_tunnel_focus_tab_order_round_trips() {
        let mut focus = SplitTunnelFocus::Mode;
        for _ in 0..SplitTunnelFocus::ORDER.len() {
            focus = focus.next();
        }
        assert_eq!(focus, SplitTunnelFocus::Mode);

        // `prev` must retrace `next` exactly, which is what sharing one ORDER
        // guarantees.
        assert_eq!(SplitTunnelFocus::Mode.next().prev(), SplitTunnelFocus::Mode);
        assert_eq!(SplitTunnelFocus::Mode.prev(), SplitTunnelFocus::DomainList);
    }

    #[test]
    fn only_the_two_input_fields_capture_typing() {
        assert!(SplitTunnelFocus::CidrInput.is_text_input());
        assert!(SplitTunnelFocus::DomainInput.is_text_input());
        assert!(!SplitTunnelFocus::Mode.is_text_input());
        assert!(!SplitTunnelFocus::CidrList.is_text_input());
        assert!(!SplitTunnelFocus::DomainList.is_text_input());
    }

    #[test]
    fn palette_filter_matches_title_and_description() {
        let mut cp = CommandPaletteState {
            filter: "lockdown".to_string(),
            ..Default::default()
        };
        assert!(!cp.filtered_items().is_empty());

        cp.filter = "no-such-action".to_string();
        assert!(cp.filtered_items().is_empty());
    }
}
