//! State model for the Terminal User Interface.

use std::path::PathBuf;

use crate::app::profile_list::ProfileListRow;
use crate::config::{AppConfig, SplitTunnelConfig, SplitTunnelMode};
use crate::nm::{ProfileDiagnostics, WireguardProfile};
use crate::tui::theme::Theme;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveModal {
    None,
    Help,
    SplitTunnel(SplitTunnelModalState),
    ConfirmDelete { name: String, uuid: String },
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

pub struct TuiState {
    pub config_path: PathBuf,
    pub config: AppConfig,
    pub theme: Theme,
    pub rows: Vec<ProfileListRow>,
    pub raw_profiles: Vec<WireguardProfile>,
    pub selected_index: usize,
    pub active_profile_name: Option<String>,
    pub active_port: Option<u16>,
    pub selected_diagnostics: Option<ProfileDiagnostics>,
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
            selected_index: 0,
            active_profile_name: None,
            active_port: None,
            selected_diagnostics: None,
            status_message: "Ready. Press [?] for keybindings help.".to_string(),
            modal: ActiveModal::None,
            should_quit: false,
            spinner_tick: 0,
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
