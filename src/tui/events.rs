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

    update_diagnostics(state, client);
    Ok(())
}

fn update_diagnostics<C: NmClient>(state: &mut TuiState, client: &C) {
    if let Some(row) = state.selected_row()
        && let Ok(diag) = client.get_profile_diagnostics(&row.uuid, row.is_active)
    {
        state.selected_diagnostics = Some(diag);
        return;
    }
    state.selected_diagnostics = None;
}
