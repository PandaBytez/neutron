//! TUI keyboard event handling and state mutations.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::eligibility;
use crate::app::split_tunnel;
use crate::app::sync;
use crate::config::{self, SplitTunnelMode};
use crate::error::AppResult;
use crate::firewall::FirewallClient;
use crate::nm::{self, NmClient};
use crate::tui::state::{ActiveModal, SplitTunnelFocus, TuiState};

pub fn handle_key_event<C>(state: &mut TuiState, client: &C, key: KeyEvent) -> AppResult<()>
where
    C: NmClient + FirewallClient + Clone + Send + 'static,
{
    match state.modal {
        ActiveModal::CommandPalette(_) => {
            handle_command_palette_key(state, client, key)?;
        }
        ActiveModal::ThemePicker(_) => {
            handle_theme_picker_key(state, key)?;
        }
        ActiveModal::Help => handle_help_key(state, key),
        ActiveModal::ConfirmDelete { ref uuid, .. } => {
            let uuid = uuid.clone();
            handle_delete_key(state, client, key, &uuid)?;
        }
        ActiveModal::SplitTunnel(_) => {
            handle_split_tunnel_key(state, client, key)?;
        }
        ActiveModal::None => handle_normal_key(state, client, key)?,
    }
    Ok(())
}

fn handle_help_key(state: &mut TuiState, key: KeyEvent) {
    if matches!(
        key.code,
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') | KeyCode::Enter
    ) {
        state.modal = ActiveModal::None;
    }
}

fn handle_command_palette_key<C>(state: &mut TuiState, client: &C, key: KeyEvent) -> AppResult<()>
where
    C: NmClient + FirewallClient + Clone + Send + 'static,
{
    let mut cp = match &state.modal {
        ActiveModal::CommandPalette(cp) => cp.clone(),
        _ => return Ok(()),
    };

    match key.code {
        KeyCode::Esc => {
            state.modal = ActiveModal::None;
        }
        KeyCode::Up => {
            let filtered_len = cp.filtered_items().len();
            if filtered_len > 0 {
                if cp.selected_index == 0 {
                    cp.selected_index = filtered_len - 1;
                } else {
                    cp.selected_index -= 1;
                }
            }
            state.modal = ActiveModal::CommandPalette(cp);
        }
        KeyCode::Down => {
            let filtered_len = cp.filtered_items().len();
            if filtered_len > 0 {
                cp.selected_index = (cp.selected_index + 1) % filtered_len;
            }
            state.modal = ActiveModal::CommandPalette(cp);
        }
        KeyCode::Backspace => {
            cp.filter.pop();
            cp.selected_index = 0;
            state.modal = ActiveModal::CommandPalette(cp);
        }
        KeyCode::Char(c) => {
            cp.filter.push(c);
            cp.selected_index = 0;
            state.modal = ActiveModal::CommandPalette(cp);
        }
        KeyCode::Enter => {
            let filtered = cp.filtered_items();
            if let Some(item) = filtered.get(cp.selected_index) {
                let action_id = item.id;
                state.modal = ActiveModal::None;
                execute_palette_action(state, client, action_id)?;
            } else {
                state.modal = ActiveModal::None;
            }
        }
        _ => {}
    }

    Ok(())
}

fn execute_palette_action<C>(state: &mut TuiState, client: &C, id: &str) -> AppResult<()>
where
    C: NmClient + FirewallClient + Clone + Send + 'static,
{
    match id {
        "theme" => {
            state.modal = ActiveModal::ThemePicker(crate::tui::state::ThemePickerState::default());
        }
        "connect" => {
            if let Some(row) = state.selected_row() {
                let uuid = row.uuid.clone();
                let name = row.name.clone();
                client.switch_to(&uuid)?;
                state.status_message = format!("Connected '{name}'.");
                reload_profiles(state, client)?;
            }
        }
        "disconnect" => {
            client.disconnect_active()?;
            state.status_message = "Disconnected active VPN.".to_string();
            reload_profiles(state, client)?;
        }
        "switch" => {
            if let Some(row) = state.selected_row() {
                let uuid = row.uuid.clone();
                let name = row.name.clone();
                client.switch_to(&uuid)?;
                state.status_message = format!("Switched to '{name}'.");
                reload_profiles(state, client)?;
            }
        }
        "split_tunnel" => {
            state.modal =
                ActiveModal::SplitTunnel(crate::tui::state::SplitTunnelModalState::from_config(
                    &state.config.global_split_tunnel,
                ));
        }
        "kill_switch" => {
            let new_kill = !state.config.kill_switch_enabled;
            crate::app::set_global_kill_switch(client, &state.config_path, new_kill)?;
            state.config.kill_switch_enabled = new_kill;
            let verb = if new_kill { "Enabled" } else { "Disabled" };
            state.status_message = format!("{verb} Kill Switch.");
        }
        "lockdown" => {
            let new_lock = !state.config.lockdown_enabled;
            crate::app::set_global_lockdown(client, &state.config_path, new_lock)?;
            state.config.lockdown_enabled = new_lock;
            let verb = if new_lock { "Enabled" } else { "Disabled" };
            state.status_message = format!("{verb} Lockdown Mode.");
        }
        "autoconnect" => {
            let new_auto = !state.config.general.autoconnect_at_login;
            crate::service::set_autoconnect_at_login(client, &state.config_path, new_auto)?;
            state.config.general.autoconnect_at_login = new_auto;
            state.config.autoconnect_at_boot = new_auto;
            let verb = if new_auto { "Enabled" } else { "Disabled" };
            state.status_message = format!("{verb} Auto-Connect at Login.");
        }
        "eligible" => {
            if let Some(row) = state.selected_row() {
                let uuid = row.uuid.clone();
                let name = row.name.clone();
                let new_eligible = !row.eligible;
                let mut app_cfg = config::load(&state.config_path)?;
                let changed = eligibility::set_profile_eligible(
                    &mut app_cfg.excluded_profile_ids,
                    &uuid,
                    new_eligible,
                );
                if changed {
                    config::save(&state.config_path, &app_cfg)?;
                    state.config = app_cfg;
                    let verb = if new_eligible { "Eligible" } else { "Excluded" };
                    state.status_message = format!("{verb} '{name}' for startup pool.");
                    reload_profiles(state, client)?;
                }
            }
        }
        "sync" => {
            let report = sync::sync_profiles_dir(client, &state.config)?;
            reload_profiles(state, client)?;
            state.status_message = format!(
                "Synced drop directory ({} imported).",
                report.imported.len()
            );
        }
        "delete" => {
            if let Some(row) = state.selected_row() {
                state.modal = ActiveModal::ConfirmDelete {
                    name: row.name.clone(),
                    uuid: row.uuid.clone(),
                };
            }
        }
        "help" => {
            state.modal = ActiveModal::Help;
        }
        "quit" => {
            state.should_quit = true;
        }
        _ => {}
    }
    Ok(())
}

fn handle_theme_picker_key(state: &mut TuiState, key: KeyEvent) -> AppResult<()> {
    let mut tp = match &state.modal {
        ActiveModal::ThemePicker(tp) => tp.clone(),
        _ => return Ok(()),
    };

    match key.code {
        KeyCode::Esc => {
            state.modal = ActiveModal::None;
        }
        KeyCode::Up => {
            if !tp.themes.is_empty() {
                if tp.selected_index == 0 {
                    tp.selected_index = tp.themes.len() - 1;
                } else {
                    tp.selected_index -= 1;
                }
            }
            state.modal = ActiveModal::ThemePicker(tp);
        }
        KeyCode::Down => {
            if !tp.themes.is_empty() {
                tp.selected_index = (tp.selected_index + 1) % tp.themes.len();
            }
            state.modal = ActiveModal::ThemePicker(tp);
        }
        KeyCode::Enter => {
            if let Some((preset, label)) = tp.themes.get(tp.selected_index) {
                state.config.theme.preset = preset.to_string();
                let _ = config::save(&state.config_path, &state.config);
                state.theme = crate::tui::theme::Theme::from_config(&state.config.theme);
                state.status_message = format!("Applied theme: {label}");
            }
            state.modal = ActiveModal::None;
        }
        _ => {}
    }

    Ok(())
}

fn handle_delete_key<C: NmClient>(
    state: &mut TuiState,
    client: &C,
    key: KeyEvent,
    uuid: &str,
) -> AppResult<()> {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
            client.delete_profile(uuid)?;
            state.status_message = "Profile deleted.".to_string();
            state.modal = ActiveModal::None;
            reload_profiles(state, client)?;
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            state.modal = ActiveModal::None;
            state.status_message = "Deletion cancelled.".to_string();
        }
        _ => {}
    }
    Ok(())
}

fn handle_normal_key<C>(state: &mut TuiState, client: &C, key: KeyEvent) -> AppResult<()>
where
    C: NmClient + FirewallClient + Clone + Send + 'static,
{
    // Global quit
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        state.should_quit = true;
        return Ok(());
    }

    // Command Palette (Ctrl+P or :)
    if (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('p'))
        || key.code == KeyCode::Char(':')
    {
        state.modal =
            ActiveModal::CommandPalette(crate::tui::state::CommandPaletteState::default());
        return Ok(());
    }

    // Theme Picker (Ctrl+T)
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('t') {
        state.modal = ActiveModal::ThemePicker(crate::tui::state::ThemePickerState::default());
        return Ok(());
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            state.should_quit = true;
        }
        KeyCode::Up | KeyCode::Char('p') => {
            state.prev_profile();
            update_diagnostics(state, client);
        }
        KeyCode::Down | KeyCode::Char('n') => {
            state.next_profile();
            update_diagnostics(state, client);
        }
        KeyCode::Char(' ') | KeyCode::Enter => {
            if let Some(row) = state.selected_row() {
                let uuid = row.uuid.clone();
                let is_active = row.is_active;
                let name = row.name.clone();
                if is_active {
                    client.disconnect_active()?;
                    state.status_message = format!("Disconnected '{name}'.");
                } else {
                    client.switch_to(&uuid)?;
                    state.status_message = format!("Connected '{name}'.");
                }
                reload_profiles(state, client)?;
            }
        }
        KeyCode::Char('s') => {
            if let Some(row) = state.selected_row() {
                let uuid = row.uuid.clone();
                let name = row.name.clone();
                client.switch_to(&uuid)?;
                state.status_message = format!("Switched to '{name}'.");
                reload_profiles(state, client)?;
            }
        }
        KeyCode::Char('e') => {
            if let Some(row) = state.selected_row() {
                let uuid = row.uuid.clone();
                let name = row.name.clone();
                let new_eligible = !row.eligible;
                let mut app_cfg = config::load(&state.config_path)?;
                let changed = eligibility::set_profile_eligible(
                    &mut app_cfg.excluded_profile_ids,
                    &uuid,
                    new_eligible,
                );
                if changed {
                    config::save(&state.config_path, &app_cfg)?;
                    state.config = app_cfg;
                    let verb = if new_eligible { "Eligible" } else { "Excluded" };
                    state.status_message = format!("{verb} '{name}' for random startup.");
                    reload_profiles(state, client)?;
                }
            }
        }
        KeyCode::Char('a') => {
            let new_auto = !state.config.general.autoconnect_at_login;
            crate::service::set_autoconnect_at_login(client, &state.config_path, new_auto)?;
            state.config.general.autoconnect_at_login = new_auto;
            state.config.autoconnect_at_boot = new_auto;
            let verb = if new_auto { "Enabled" } else { "Disabled" };
            state.status_message = format!("{verb} Auto-Connect at Login.");
        }
        KeyCode::Char('k') => {
            let new_kill = !state.config.kill_switch_enabled;
            crate::app::set_global_kill_switch(client, &state.config_path, new_kill)?;
            state.config.kill_switch_enabled = new_kill;
            let verb = if new_kill { "Enabled" } else { "Disabled" };
            state.status_message = format!("{verb} Kill Switch (All profiles).");
        }
        KeyCode::Char('l') => {
            let new_lock = !state.config.lockdown_enabled;
            crate::app::set_global_lockdown(client, &state.config_path, new_lock)?;
            state.config.lockdown_enabled = new_lock;
            let verb = if new_lock { "Enabled" } else { "Disabled" };
            state.status_message = format!("{verb} Lockdown Mode.");
        }
        KeyCode::Char('t') => {
            state.modal =
                ActiveModal::SplitTunnel(crate::tui::state::SplitTunnelModalState::from_config(
                    &state.config.global_split_tunnel,
                ));
        }
        KeyCode::Char('r') => {
            let report = sync::sync_profiles_dir(client, &state.config)?;
            reload_profiles(state, client)?;
            if !report.imported.is_empty() {
                state.status_message = format!(
                    "Synced drop directory: imported {} profiles.",
                    report.imported.len()
                );
            } else {
                state.status_message = "Refreshed profiles.".to_string();
            }
        }
        KeyCode::Char('d') | KeyCode::Delete => {
            if let Some(row) = state.selected_row() {
                state.modal = ActiveModal::ConfirmDelete {
                    name: row.name.clone(),
                    uuid: row.uuid.clone(),
                };
            }
        }
        KeyCode::Char('?') | KeyCode::Char('h') => {
            state.modal = ActiveModal::Help;
        }
        _ => {}
    }
    Ok(())
}

fn handle_split_tunnel_key<C: NmClient>(
    state: &mut TuiState,
    client: &C,
    key: KeyEvent,
) -> AppResult<()> {
    let ActiveModal::SplitTunnel(ref mut st) = state.modal else {
        return Ok(());
    };

    // Global save & apply
    if (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s'))
        || (key.code == KeyCode::F(2))
    {
        let new_cfg = st.to_config();
        split_tunnel::apply_and_persist_global_split_tunnel(client, &state.config_path, &new_cfg)?;
        state.config.global_split_tunnel = new_cfg;
        state.modal = ActiveModal::None;
        state.status_message = "Saved & applied global split tunneling.".to_string();
        return Ok(());
    }

    if key.code == KeyCode::Esc {
        state.modal = ActiveModal::None;
        state.status_message = "Split tunneling changes discarded.".to_string();
        return Ok(());
    }

    match key.code {
        KeyCode::Tab => {
            st.focus = match st.focus {
                SplitTunnelFocus::Mode => SplitTunnelFocus::CidrInput,
                SplitTunnelFocus::CidrInput => SplitTunnelFocus::CidrList,
                SplitTunnelFocus::CidrList => SplitTunnelFocus::DomainInput,
                SplitTunnelFocus::DomainInput => SplitTunnelFocus::DomainList,
                SplitTunnelFocus::DomainList => SplitTunnelFocus::Mode,
            };
        }
        KeyCode::BackTab => {
            st.focus = match st.focus {
                SplitTunnelFocus::Mode => SplitTunnelFocus::DomainList,
                SplitTunnelFocus::CidrInput => SplitTunnelFocus::Mode,
                SplitTunnelFocus::CidrList => SplitTunnelFocus::CidrInput,
                SplitTunnelFocus::DomainInput => SplitTunnelFocus::CidrList,
                SplitTunnelFocus::DomainList => SplitTunnelFocus::DomainInput,
            };
        }
        KeyCode::Char('1')
            if st.focus != SplitTunnelFocus::CidrInput
                && st.focus != SplitTunnelFocus::DomainInput =>
        {
            st.focus = SplitTunnelFocus::CidrInput;
        }
        KeyCode::Char('2')
            if st.focus != SplitTunnelFocus::CidrInput
                && st.focus != SplitTunnelFocus::DomainInput =>
        {
            st.focus = SplitTunnelFocus::DomainInput;
        }
        KeyCode::Char('m')
            if st.focus != SplitTunnelFocus::CidrInput
                && st.focus != SplitTunnelFocus::DomainInput =>
        {
            st.mode = match st.mode {
                SplitTunnelMode::Disabled => SplitTunnelMode::Include,
                SplitTunnelMode::Include => SplitTunnelMode::Exclude,
                SplitTunnelMode::Exclude => SplitTunnelMode::Disabled,
            };
        }
        KeyCode::Enter => match st.focus {
            SplitTunnelFocus::CidrInput => {
                if let Ok((normalized, _)) =
                    nm::split_tunnel::parse_and_normalize_cidr(&st.input_buffer)
                {
                    if !st.cidrs.contains(&normalized) {
                        st.cidrs.push(normalized);
                    }
                    st.input_buffer.clear();
                }
            }
            SplitTunnelFocus::DomainInput => {
                let trimmed = st.input_buffer.trim().to_lowercase();
                if !trimmed.is_empty() && !st.domains.contains(&trimmed) {
                    st.domains.push(trimmed);
                }
                st.input_buffer.clear();
            }
            _ => {}
        },
        KeyCode::Backspace => {
            if st.focus == SplitTunnelFocus::CidrInput || st.focus == SplitTunnelFocus::DomainInput
            {
                st.input_buffer.pop();
            }
        }
        KeyCode::Up => match st.focus {
            SplitTunnelFocus::CidrList if !st.cidrs.is_empty() => {
                if st.selected_cidr == 0 {
                    st.selected_cidr = st.cidrs.len() - 1;
                } else {
                    st.selected_cidr -= 1;
                }
            }
            SplitTunnelFocus::DomainList if !st.domains.is_empty() => {
                if st.selected_domain == 0 {
                    st.selected_domain = st.domains.len() - 1;
                } else {
                    st.selected_domain -= 1;
                }
            }
            _ => {}
        },
        KeyCode::Down => match st.focus {
            SplitTunnelFocus::CidrList if !st.cidrs.is_empty() => {
                st.selected_cidr = (st.selected_cidr + 1) % st.cidrs.len();
            }
            SplitTunnelFocus::DomainList if !st.domains.is_empty() => {
                st.selected_domain = (st.selected_domain + 1) % st.domains.len();
            }
            _ => {}
        },
        KeyCode::Delete => match st.focus {
            SplitTunnelFocus::CidrList if !st.cidrs.is_empty() => {
                st.cidrs.remove(st.selected_cidr);
                if st.selected_cidr >= st.cidrs.len() && !st.cidrs.is_empty() {
                    st.selected_cidr = st.cidrs.len() - 1;
                }
            }
            SplitTunnelFocus::DomainList if !st.domains.is_empty() => {
                st.domains.remove(st.selected_domain);
                if st.selected_domain >= st.domains.len() && !st.domains.is_empty() {
                    st.selected_domain = st.domains.len() - 1;
                }
            }
            _ => {}
        },
        KeyCode::Char('x')
            if st.focus == SplitTunnelFocus::CidrList
                || st.focus == SplitTunnelFocus::DomainList =>
        {
            match st.focus {
                SplitTunnelFocus::CidrList if !st.cidrs.is_empty() => {
                    st.cidrs.remove(st.selected_cidr);
                    if st.selected_cidr >= st.cidrs.len() && !st.cidrs.is_empty() {
                        st.selected_cidr = st.cidrs.len() - 1;
                    }
                }
                SplitTunnelFocus::DomainList if !st.domains.is_empty() => {
                    st.domains.remove(st.selected_domain);
                    if st.selected_domain >= st.domains.len() && !st.domains.is_empty() {
                        st.selected_domain = st.domains.len() - 1;
                    }
                }
                _ => {}
            }
        }
        KeyCode::Char(c)
            if st.focus == SplitTunnelFocus::CidrInput
                || st.focus == SplitTunnelFocus::DomainInput =>
        {
            st.input_buffer.push(c);
        }
        _ => {}
    }

    Ok(())
}

pub fn reload_profiles<C: NmClient>(state: &mut TuiState, client: &C) -> AppResult<()> {
    let profiles = client.list_wireguard_profiles()?;
    let app_cfg = config::load(&state.config_path)?;
    state.config = app_cfg.clone();

    state.rows = crate::app::profile_list::build_rows(
        &profiles,
        &app_cfg.excluded_profile_ids,
        &app_cfg.profile_custom_info,
    );
    state.raw_profiles = profiles;

    let active = state.rows.iter().find(|r| r.is_active);
    state.active_profile_name = active.map(|r| r.name.clone());

    if let Some(active_row) = active
        && let Some(addr) = client.tunnel_address(&active_row.uuid)
        && let Some(gw) = crate::portforward::gateway_for_address(&addr)
        && let Ok(port) = crate::portforward::request_mapping(gw)
    {
        state.active_port = Some(port);
    } else {
        state.active_port = None;
    }

    if state.selected_index >= state.rows.len() && !state.rows.is_empty() {
        state.selected_index = state.rows.len() - 1;
    }

    // Refresh active profile in cache to capture live transfer/handshake
    if let Some(active_row) = active {
        state.profile_cache.remove(&active_row.uuid);
    }

    update_diagnostics(state, client);
    Ok(())
}

pub fn update_diagnostics<C: NmClient>(state: &mut TuiState, client: &C) {
    let row_info = state.selected_row().map(|r| (r.uuid.clone(), r.is_active));
    if let Some((uuid, is_active)) = row_info {
        if let Some(cached) = state.profile_cache.get(&uuid) {
            state.selected_tunnel_address = cached.tunnel_address.clone();
            state.selected_tunnel_dns = cached.tunnel_dns.clone();
            state.selected_gateway = cached.gateway.clone();
            state.selected_diagnostics = Some(cached.diagnostics.clone());
        } else {
            let tunnel_addr = client.tunnel_address(&uuid);
            let tunnel_dns = client.tunnel_dns(&uuid);
            let gateway = tunnel_addr
                .as_deref()
                .and_then(crate::portforward::gateway_for_address)
                .map(|ip| ip.to_string());
            let diag = client
                .get_profile_diagnostics(&uuid, is_active)
                .unwrap_or_default();

            state.selected_tunnel_address = tunnel_addr.clone();
            state.selected_tunnel_dns = tunnel_dns.clone();
            state.selected_gateway = gateway.clone();
            state.selected_diagnostics = Some(diag.clone());

            state.profile_cache.insert(
                uuid,
                crate::tui::state::CachedProfileInfo {
                    diagnostics: diag,
                    tunnel_address: tunnel_addr,
                    tunnel_dns,
                    gateway,
                },
            );
        }
    } else {
        state.selected_tunnel_address = None;
        state.selected_tunnel_dns = None;
        state.selected_gateway = None;
        state.selected_diagnostics = None;
    }
}
