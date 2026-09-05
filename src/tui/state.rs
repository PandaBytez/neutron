//! State model for the Terminal User Interface.

use std::path::PathBuf;

use crate::app::profile_list::ProfileListRow;
use crate::config::{AppConfig, SplitTunnelConfig, SplitTunnelMode};
use crate::nm::ProfileDiagnostics;
use crate::nm::network_info::PublicIpInfo;
use crate::service::lease::{LeaseState, QbitSyncStatus};
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
pub struct Toast {
    pub message: String,
    pub is_error: bool,
    pub created_at: std::time::Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectingState {
    pub uuid: String,
    pub name: String,
    pub is_disconnect: bool,
    pub started_at: std::time::Instant,
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
                title: "Auto Connect Pool: Exclude or Include Selected Profile",
                description: "Excluded profiles are never picked by the random login selector",
                shortcut: Some("e"),
            },
            CommandPaletteItem {
                id: "favorite",
                title: "Favorite: Star or Unstar Selected Profile",
                description: "Starred favorite profiles appear in the tray indicator quick actions",
                shortcut: Some("f"),
            },
            CommandPaletteItem {
                id: "autoconnect",
                title: "Auto Connect at Login: Toggle",
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
                title: "Lockdown Mode: Toggle Always-On Firewall",
                description: "Block all traffic except the tunnel, its handshake, DNS and the LAN (requires root)",
                shortcut: Some("l"),
            },
            CommandPaletteItem {
                id: "port_forwarding",
                title: "Port Forward: Toggle NAT-PMP",
                description: "Lease an incoming port from the VPN gateway and keep renewing it",
                shortcut: Some("o"),
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
                ("nord", "Nord (Arctic Frost)"),
                ("osaka-jade", "Osaka Jade"),
                ("catppuccin-mocha", "Catppuccin Mocha"),
                ("gruvbox", "Gruvbox Dark"),
                ("monochrome", "Monochrome (High-Contrast)"),
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitTunnelFocus {
    Mode,
    DomainInput,
    DomainList,
    CidrInput,
    CidrList,
}

impl SplitTunnelFocus {
    /// Whether this focus is a text field, in which case printable keys are
    /// typed into the buffer rather than treated as shortcuts.
    pub fn is_text_input(self) -> bool {
        matches!(self, Self::DomainInput | Self::CidrInput)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitTunnelModalState {
    pub mode: SplitTunnelMode,
    pub highlighted_mode: usize,
    pub cidrs: Vec<String>,
    pub domains: Vec<String>,
    pub focus: SplitTunnelFocus,
    pub domain_input: String,
    pub cidr_input: String,
    pub selected_cidr: usize,
    pub selected_domain: usize,
}

impl SplitTunnelModalState {
    pub const MODES: [SplitTunnelMode; 3] = [
        SplitTunnelMode::Disabled,
        SplitTunnelMode::Include,
        SplitTunnelMode::Exclude,
    ];

    pub fn from_config(st: &SplitTunnelConfig) -> Self {
        let highlighted_mode = Self::MODES.iter().position(|&m| m == st.mode).unwrap_or(0);
        Self {
            mode: st.mode,
            highlighted_mode,
            cidrs: st.cidrs.clone(),
            domains: st.domains.clone(),
            focus: SplitTunnelFocus::Mode,
            domain_input: String::new(),
            cidr_input: String::new(),
            selected_cidr: 0,
            selected_domain: 0,
        }
    }

    pub fn selected_highlighted_mode(&self) -> SplitTunnelMode {
        Self::MODES[self.highlighted_mode.min(Self::MODES.len() - 1)]
    }

    pub fn to_config(&self) -> SplitTunnelConfig {
        SplitTunnelConfig {
            mode: self.mode,
            cidrs: self.cidrs.clone(),
            domains: self.domains.clone(),
        }
    }

    pub fn next_panel(&mut self) {
        self.focus = match self.focus {
            SplitTunnelFocus::Mode => SplitTunnelFocus::DomainInput,
            SplitTunnelFocus::DomainInput | SplitTunnelFocus::DomainList => {
                SplitTunnelFocus::CidrInput
            }
            SplitTunnelFocus::CidrInput | SplitTunnelFocus::CidrList => SplitTunnelFocus::Mode,
        };
    }

    pub fn prev_panel(&mut self) {
        self.focus = match self.focus {
            SplitTunnelFocus::Mode => SplitTunnelFocus::CidrInput,
            SplitTunnelFocus::DomainInput | SplitTunnelFocus::DomainList => SplitTunnelFocus::Mode,
            SplitTunnelFocus::CidrInput | SplitTunnelFocus::CidrList => {
                SplitTunnelFocus::DomainInput
            }
        };
    }

    pub fn move_left(&mut self) {
        match self.focus {
            SplitTunnelFocus::Mode => {
                self.highlighted_mode = wrap_prev(self.highlighted_mode, 3);
            }
            SplitTunnelFocus::CidrInput => {
                self.focus = SplitTunnelFocus::DomainInput;
            }
            SplitTunnelFocus::CidrList => {
                self.focus = if self.domains.is_empty() {
                    SplitTunnelFocus::DomainInput
                } else {
                    SplitTunnelFocus::DomainList
                };
            }
            _ => {}
        }
    }

    pub fn move_right(&mut self) {
        match self.focus {
            SplitTunnelFocus::Mode => {
                self.highlighted_mode = wrap_next(self.highlighted_mode, 3);
            }
            SplitTunnelFocus::DomainInput => {
                self.focus = SplitTunnelFocus::CidrInput;
            }
            SplitTunnelFocus::DomainList => {
                self.focus = if self.cidrs.is_empty() {
                    SplitTunnelFocus::CidrInput
                } else {
                    SplitTunnelFocus::CidrList
                };
            }
            _ => {}
        }
    }

    pub fn move_up(&mut self) {
        match self.focus {
            SplitTunnelFocus::Mode => {}
            SplitTunnelFocus::DomainInput | SplitTunnelFocus::CidrInput => {
                self.focus = SplitTunnelFocus::Mode;
            }
            SplitTunnelFocus::DomainList => {
                if self.selected_domain == 0 {
                    self.focus = SplitTunnelFocus::DomainInput;
                } else {
                    self.selected_domain = self.selected_domain.saturating_sub(1);
                }
            }
            SplitTunnelFocus::CidrList => {
                if self.selected_cidr == 0 {
                    self.focus = SplitTunnelFocus::CidrInput;
                } else {
                    self.selected_cidr = self.selected_cidr.saturating_sub(1);
                }
            }
        }
    }

    pub fn move_down(&mut self) {
        match self.focus {
            SplitTunnelFocus::Mode => {
                self.focus = SplitTunnelFocus::DomainInput;
            }
            SplitTunnelFocus::DomainInput => {
                if !self.domains.is_empty() {
                    self.focus = SplitTunnelFocus::DomainList;
                    self.selected_domain = 0;
                }
            }
            SplitTunnelFocus::CidrInput => {
                if !self.cidrs.is_empty() {
                    self.focus = SplitTunnelFocus::CidrList;
                    self.selected_cidr = 0;
                }
            }
            SplitTunnelFocus::DomainList => {
                if !self.domains.is_empty() {
                    self.selected_domain = (self.selected_domain + 1).min(self.domains.len() - 1);
                }
            }
            SplitTunnelFocus::CidrList => {
                if !self.cidrs.is_empty() {
                    self.selected_cidr = (self.selected_cidr + 1).min(self.cidrs.len() - 1);
                }
            }
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
    /// The forwarded-port lease as last published by the tray daemon, or `None`
    /// when it is not publishing one.
    ///
    /// Read rather than obtained: the lease has a renewal timer, and the daemon
    /// owns it because it outlives any TUI session. Asking the gateway here too
    /// would race that timer, push a second copy at qBittorrent, and block the
    /// render thread on a UDP round trip -- and still go stale, since the TUI
    /// only learns of a tunnel change while it happens to be open.
    pub lease: Option<LeaseState>,
    pub public_ip_info: Option<PublicIpInfo>,
    pub download_rate: u64,
    pub upload_rate: u64,
    pub latency_ms: Option<u32>,
    pub last_net_sample: Option<(std::time::Instant, u64, u64)>,
    pub status_message: String,
    /// Whether [`Self::status_message`] reports a failure, so the footer can
    /// style it as one instead of burying it among routine confirmations.
    pub status_is_error: bool,
    pub toast: Option<Toast>,
    pub connecting: Option<ConnectingState>,
    pub connect_tx: Option<std::sync::mpsc::Sender<(String, String, bool)>>,
    pub split_tunnel_tx: Option<std::sync::mpsc::Sender<SplitTunnelConfig>>,
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
            lease: None,
            public_ip_info: None,
            download_rate: 0,
            upload_rate: 0,
            latency_ms: None,
            last_net_sample: None,
            status_message: String::new(),
            status_is_error: false,
            toast: None,
            connecting: None,
            connect_tx: None,
            split_tunnel_tx: None,
            modal: ActiveModal::None,
            should_quit: false,
        }
    }

    pub fn apply_split_tunnel<C: crate::nm::NmClient>(
        &mut self,
        client: &C,
        new_cfg: SplitTunnelConfig,
    ) -> crate::error::AppResult<()> {
        self.config.global_split_tunnel = new_cfg.clone();
        if let Some(ref tx) = self.split_tunnel_tx {
            let _ = tx.send(new_cfg);
            Ok(())
        } else {
            crate::app::split_tunnel::apply_and_persist_global_split_tunnel(
                client,
                &self.config_path,
                &new_cfg,
            )
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
        if elapsed >= 1.5 {
            self.download_rate = (rx.saturating_sub(prev_rx) as f64 / elapsed).round() as u64;
            self.upload_rate = (tx.saturating_sub(prev_tx) as f64 / elapsed).round() as u64;
            self.last_net_sample = Some((now, rx, tx));
        }
    }

    /// Report a completed action in a toast notification.
    pub fn set_status(&mut self, message: impl Into<String>) {
        let msg = message.into();
        self.status_message = msg.clone();
        self.status_is_error = false;
        self.toast = Some(Toast {
            message: msg,
            is_error: false,
            created_at: std::time::Instant::now(),
        });
    }

    /// Report a failed action in a toast notification. Kept distinct from
    /// [`Self::set_status`] so an error cannot be mistaken for a success.
    pub fn set_error(&mut self, error: &crate::error::AppError) {
        let msg = error.to_string();
        self.status_message = msg.clone();
        self.status_is_error = true;
        self.toast = Some(Toast {
            message: msg,
            is_error: true,
            created_at: std::time::Instant::now(),
        });
    }

    /// Return the currently active toast if it has not expired (visible for 3s).
    pub fn active_toast(&self) -> Option<&Toast> {
        match self.toast.as_ref() {
            Some(t) if t.created_at.elapsed() < std::time::Duration::from_secs(3) => Some(t),
            _ => None,
        }
    }

    /// The forwarded port the daemon currently holds, if any.
    ///
    /// `None` covers both "no lease" and "no daemon publishing one"; the two are
    /// the same thing to a reader, since an unpublished lease is not being
    /// renewed and so is not a port anyone can rely on.
    pub fn forwarded_port(&self) -> Option<u16> {
        self.lease.as_ref()?.port
    }

    /// What the daemon's last push to qBittorrent came to, or `None` when it is
    /// not publishing a lease to have pushed.
    pub fn qbit_sync(&self) -> Option<QbitSyncStatus> {
        Some(self.lease.as_ref()?.qbit_sync)
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
    fn split_tunnel_modal_panel_cycling() {
        let mut st = SplitTunnelModalState::from_config(&SplitTunnelConfig::default());
        assert_eq!(st.focus, SplitTunnelFocus::Mode);
        st.next_panel();
        assert_eq!(st.focus, SplitTunnelFocus::DomainInput);
        st.next_panel();
        assert_eq!(st.focus, SplitTunnelFocus::CidrInput);
        st.next_panel();
        assert_eq!(st.focus, SplitTunnelFocus::Mode);

        st.prev_panel();
        assert_eq!(st.focus, SplitTunnelFocus::CidrInput);
        st.prev_panel();
        assert_eq!(st.focus, SplitTunnelFocus::DomainInput);
        st.prev_panel();
        assert_eq!(st.focus, SplitTunnelFocus::Mode);
    }

    #[test]
    fn split_tunnel_modal_arrow_navigation() {
        let mut st = SplitTunnelModalState::from_config(&SplitTunnelConfig::default());
        st.domains.push("github.com".to_string());
        st.domains.push("gitlab.com".to_string());
        st.cidrs.push("10.0.0.0/8".to_string());

        // Mode: Left / Right cycles highlighted mode
        assert_eq!(st.highlighted_mode, 0);
        st.move_right();
        assert_eq!(st.highlighted_mode, 1);
        st.move_left();
        assert_eq!(st.highlighted_mode, 0);

        // Down from Mode enters DomainInput
        st.move_down();
        assert_eq!(st.focus, SplitTunnelFocus::DomainInput);

        // Down from DomainInput enters DomainList
        st.move_down();
        assert_eq!(st.focus, SplitTunnelFocus::DomainList);
        assert_eq!(st.selected_domain, 0);

        // Down navigates items
        st.move_down();
        assert_eq!(st.selected_domain, 1);

        // Right from DomainList switches to CidrList
        st.move_right();
        assert_eq!(st.focus, SplitTunnelFocus::CidrList);
        assert_eq!(st.selected_cidr, 0);

        // Left from CidrList switches back to DomainList
        st.move_left();
        assert_eq!(st.focus, SplitTunnelFocus::DomainList);

        // Up to index 0 then Up returns to DomainInput
        st.selected_domain = 0;
        st.move_up();
        assert_eq!(st.focus, SplitTunnelFocus::DomainInput);

        // Up from DomainInput returns to Mode
        st.move_up();
        assert_eq!(st.focus, SplitTunnelFocus::Mode);
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

    #[test]
    fn toast_expires_after_3_seconds() {
        let mut state = TuiState::new(std::path::PathBuf::from("/tmp/cfg"), AppConfig::default());
        state.set_status("Hello toast");
        assert!(state.active_toast().is_some());
        assert_eq!(state.active_toast().unwrap().message, "Hello toast");
        assert!(!state.active_toast().unwrap().is_error);

        // Manually simulate 4 seconds passing
        if let Some(ref mut toast) = state.toast {
            toast.created_at = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(4))
                .unwrap();
        }
        assert!(state.active_toast().is_none());
    }
}
