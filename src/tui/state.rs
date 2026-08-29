//! State model for the Terminal User Interface.

use std::path::PathBuf;

use crate::app::profile_list::ProfileListRow;
use crate::config::{AppConfig, SplitTunnelConfig, SplitTunnelMode};
use crate::nm::network_info::PublicIpInfo;
use crate::nm::{ProfileDiagnostics, WireguardProfile};
use crate::tui::theme::Theme;

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
    pub fn all_items() -> Vec<CommandPaletteItem> {
        vec![
            CommandPaletteItem {
                id: "theme",
                title: "Theme: Switch Color Palette",
                description: "Change color theme (Osaka Jade, Catppuccin Mocha, Nord, Gruvbox, Mono)",
                shortcut: Some("Ctrl+T"),
            },
            CommandPaletteItem {
                id: "eligible",
                title: "Automation: Select Eligible Profiles for Auto-Connect",
                description: "Toggle whether selected profile is in the random startup pool",
                shortcut: Some("e"),
            },
        ]
    }

    pub fn filtered_items(&self) -> Vec<&CommandPaletteItem> {
        let query = self.filter.trim().to_lowercase();
        if query.is_empty() {
            self.items.iter().collect()
        } else {
            self.items
                .iter()
                .filter(|item| {
                    item.title.to_lowercase().contains(&query)
                        || item.description.to_lowercase().contains(&query)
                })
                .collect()
        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitTunnelFocus {
    Mode,
    CidrInput,
    CidrList,
    DomainInput,
    DomainList,
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
    pub raw_profiles: Vec<WireguardProfile>,
    pub profile_cache: std::collections::HashMap<String, CachedProfileInfo>,
    pub selected_index: usize,
    pub active_profile_name: Option<String>,
    pub active_port: Option<u16>,
    pub public_ip_info: Option<PublicIpInfo>,
    pub download_rate: u64,
    pub upload_rate: u64,
    pub latency_ms: Option<u32>,
    pub last_net_sample: Option<(std::time::Instant, u64, u64)>,
    pub selected_diagnostics: Option<ProfileDiagnostics>,
    pub selected_tunnel_address: Option<String>,
    pub selected_tunnel_dns: Option<String>,
    pub selected_gateway: Option<String>,
    pub status_message: String,
    pub modal: ActiveModal,
    pub should_quit: bool,
    pub spinner_tick: usize,
}

impl TuiState {
    pub fn new(config_path: PathBuf, config: AppConfig) -> Self {
        let theme = Theme::from_config(&config.theme);
        Self {
            config_path,
            config,
            theme,
            rows: Vec::new(),
            raw_profiles: Vec::new(),
            profile_cache: std::collections::HashMap::new(),
            selected_index: 0,
            active_profile_name: None,
            active_port: None,
            public_ip_info: None,
            download_rate: 0,
            upload_rate: 0,
            latency_ms: None,
            last_net_sample: None,
            selected_diagnostics: None,
            selected_tunnel_address: None,
            selected_tunnel_dns: None,
            selected_gateway: None,
            status_message: "Ready. Press [?] for keybindings help.".to_string(),
            modal: ActiveModal::None,
            should_quit: false,
            spinner_tick: 0,
        }
    }

    pub fn update_throughput(&mut self) {
        let now = std::time::Instant::now();
        let (rx, tx) = crate::nm::network_info::read_interface_bytes(None);
        if let Some((prev_time, prev_rx, prev_tx)) = self.last_net_sample {
            let elapsed = now.duration_since(prev_time).as_secs_f64();
            if elapsed >= 0.2 {
                let rx_diff = rx.saturating_sub(prev_rx);
                let tx_diff = tx.saturating_sub(prev_tx);
                self.download_rate = (rx_diff as f64 / elapsed).round() as u64;
                self.upload_rate = (tx_diff as f64 / elapsed).round() as u64;
                self.last_net_sample = Some((now, rx, tx));
            }
        } else {
            self.last_net_sample = Some((now, rx, tx));
        }
    }

    pub fn selected_row(&self) -> Option<&ProfileListRow> {
        self.rows.get(self.selected_index)
    }

    pub fn next_profile(&mut self) {
        if !self.rows.is_empty() {
            self.selected_index = (self.selected_index + 1) % self.rows.len();
        }
    }

    pub fn prev_profile(&mut self) {
        if !self.rows.is_empty() {
            if self.selected_index == 0 {
                self.selected_index = self.rows.len() - 1;
            } else {
                self.selected_index -= 1;
            }
        }
    }
}
