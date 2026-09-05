//! TUI keyboard event handling and state mutations.
//!
//! Every user-visible action is implemented exactly once, in [`execute_action`],
//! and reached through an action id. Keys map to those ids in [`action_for_key`]
//! and the command palette lists them in
//! [`CommandPaletteState::all_items`](crate::tui::state::CommandPaletteState::all_items),
//! so a binding and a palette entry are two views of one implementation rather
//! than two copies of it.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::eligibility;
use crate::app::split_tunnel;
use crate::app::sync;
use crate::config::{self, SplitTunnelMode};
use crate::error::AppResult;
use crate::firewall::FirewallClient;
use crate::nm::{self, NmClient};
use crate::tui::state::{
    ActiveModal, CachedProfileInfo, CommandPaletteState, SplitTunnelFocus, ThemePickerState,
    TuiState, wrap_next, wrap_prev,
};

/// The client capabilities every action needs. Named once so the bound does not
/// have to be repeated on each handler.
pub trait ActionClient: NmClient + FirewallClient + Clone + Send + 'static {}
impl<C: NmClient + FirewallClient + Clone + Send + 'static> ActionClient for C {}

pub fn handle_key_event<C: ActionClient>(
    state: &mut TuiState,
    client: &C,
    key: KeyEvent,
) -> AppResult<()> {
    match state.modal {
        ActiveModal::CommandPalette(_) => handle_command_palette_key(state, client, key)?,
        ActiveModal::ThemePicker(_) => handle_theme_picker_key(state, key),
        ActiveModal::Help => handle_help_key(state, key),
        ActiveModal::ConfirmDelete { ref uuid, .. } => {
            let uuid = uuid.clone();
            handle_delete_key(state, client, key, &uuid)?;
        }
        ActiveModal::SplitTunnel(_) => handle_split_tunnel_key(state, client, key)?,
        ActiveModal::None => handle_normal_key(state, client, key)?,
    }
    Ok(())
}

/// Map a main-view key press to an action id.
///
/// Returns `None` for list navigation and unbound keys, which
/// [`handle_normal_key`] deals with directly.
fn action_for_key(key: KeyEvent) -> Option<&'static str> {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            KeyCode::Char('c') => Some("quit"),
            KeyCode::Char('p') => Some("palette"),
            KeyCode::Char('t') => Some("theme"),
            _ => None,
        };
    }

    match key.code {
        KeyCode::Char(':') => Some("palette"),
        KeyCode::Char(' ') | KeyCode::Enter => Some("toggle"),
        KeyCode::Char('s') => Some("switch"),
        KeyCode::Char('e') => Some("eligible"),
        KeyCode::Char('f') | KeyCode::Char('*') | KeyCode::Char('v') => Some("favorite"),
        KeyCode::Char('t') => Some("split_tunnel"),
        KeyCode::Char('k') => Some("kill_switch"),
        KeyCode::Char('l') => Some("lockdown"),
        KeyCode::Char('o') => Some("port_forwarding"),
        KeyCode::Char('a') => Some("autoconnect"),
        KeyCode::Char('r') => Some("sync"),
        KeyCode::Char('d') | KeyCode::Delete => Some("delete"),
        KeyCode::Char('?') | KeyCode::Char('h') => Some("help"),
        KeyCode::Char('q') | KeyCode::Esc => Some("quit"),
        _ => None,
    }
}

fn handle_normal_key<C: ActionClient>(
    state: &mut TuiState,
    client: &C,
    key: KeyEvent,
) -> AppResult<()> {
    // Navigation first: `p`/`n` are list movement, so they must not be read as
    // action keys. Modified presses are never navigation -- `Ctrl+P` is the
    // command palette.
    if !key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Up | KeyCode::Char('p') => {
                state.selected_index = wrap_prev(state.selected_index, state.rows.len());
                update_diagnostics(state, client);
                return Ok(());
            }
            KeyCode::Down | KeyCode::Char('n') => {
                state.selected_index = wrap_next(state.selected_index, state.rows.len());
                update_diagnostics(state, client);
                return Ok(());
            }
            _ => {}
        }
    }

    match action_for_key(key) {
        Some(action) => execute_action(state, client, action),
        None => Ok(()),
    }
}

/// Run the action named by `id`. This is the single implementation of every
/// action; both the key map and the command palette dispatch through it.
pub fn execute_action<C: ActionClient>(
    state: &mut TuiState,
    client: &C,
    id: &str,
) -> AppResult<()> {
    match id {
        "palette" => state.modal = ActiveModal::CommandPalette(CommandPaletteState::default()),
        "theme" => state.modal = ActiveModal::ThemePicker(ThemePickerState::default()),
        "help" => state.modal = ActiveModal::Help,
        "quit" => state.should_quit = true,
        "split_tunnel" => {
            state.modal =
                ActiveModal::SplitTunnel(crate::tui::state::SplitTunnelModalState::from_config(
                    &state.config.global_split_tunnel,
                ));
        }
        "toggle" => {
            if state.connecting.is_some() {
                return Ok(());
            }
            if let Some((uuid, name, is_active)) = state.selected_identity() {
                if let Some(ref tx) = state.connect_tx {
                    state.connecting = Some(crate::tui::state::ConnectingState {
                        uuid: uuid.clone(),
                        name: name.clone(),
                        is_disconnect: is_active,
                        started_at: std::time::Instant::now(),
                    });
                    let _ = tx.send((uuid, name, !is_active));
                } else {
                    if is_active {
                        client.disconnect_active()?;
                        state.set_status(format!("Disconnected '{name}'."));
                    } else {
                        client.switch_to(&uuid)?;
                        state.set_status(format!("Connected '{name}'."));
                    }
                    reload_profiles(state, client)?;
                }
            }
        }
        "switch" => {
            if state.connecting.is_some() {
                return Ok(());
            }
            if let Some((uuid, name, is_active)) = state.selected_identity() {
                if is_active {
                    return Ok(());
                }
                if let Some(ref tx) = state.connect_tx {
                    state.connecting = Some(crate::tui::state::ConnectingState {
                        uuid: uuid.clone(),
                        name: name.clone(),
                        is_disconnect: false,
                        started_at: std::time::Instant::now(),
                    });
                    let _ = tx.send((uuid, name, true));
                } else {
                    client.switch_to(&uuid)?;
                    state.set_status(format!("Switched to '{name}'."));
                    reload_profiles(state, client)?;
                }
            }
        }
        "disconnect" => {
            if state.connecting.is_some() {
                return Ok(());
            }
            let name = state
                .active_profile_name
                .clone()
                .unwrap_or_else(|| "VPN".to_string());
            if let Some(ref tx) = state.connect_tx {
                state.connecting = Some(crate::tui::state::ConnectingState {
                    uuid: String::new(),
                    name: name.clone(),
                    is_disconnect: true,
                    started_at: std::time::Instant::now(),
                });
                let _ = tx.send((String::new(), name, false));
            } else {
                client.disconnect_active()?;
                state.set_status("Disconnected active VPN.");
                reload_profiles(state, client)?;
            }
        }
        "eligible" => {
            let Some(row) = state.selected_row() else {
                return Ok(());
            };
            let (uuid, name, new_eligible) = (row.uuid.clone(), row.name.clone(), !row.eligible);
            let mut app_cfg = config::load(&state.config_path)?;
            if eligibility::set_profile_eligible(
                &mut app_cfg.excluded_profile_ids,
                &uuid,
                new_eligible,
            ) {
                config::save(&state.config_path, &app_cfg)?;
                let verb = if new_eligible { "Eligible" } else { "Excluded" };
                state.set_status(format!("{verb} '{name}' for startup pool."));
                reload_profiles(state, client)?;
            }
        }
        "favorite" => {
            let Some(row) = state.selected_row() else {
                return Ok(());
            };
            let (uuid, name, was_fav) = (row.uuid.clone(), row.name.clone(), row.is_favorite);
            let mut app_cfg = config::load(&state.config_path)?;
            if was_fav {
                app_cfg.favorite_profile_ids.remove(&uuid);
            } else {
                app_cfg.favorite_profile_ids.insert(uuid.clone());
            }
            config::save(&state.config_path, &app_cfg)?;
            state.config = app_cfg;
            reload_profiles(state, client)?;
            let msg = if was_fav {
                format!("Removed '{name}' from favorites.")
            } else {
                format!("Starred '{name}' as favorite.")
            };
            state.set_status(msg);
        }
        "kill_switch" => {
            let enable = !state.config.kill_switch_enabled;
            crate::app::set_global_kill_switch(client, &state.config_path, enable)?;
            state.config.kill_switch_enabled = enable;
            state.set_status(format!(
                "{} Kill Switch (all profiles).",
                enabled_verb(enable)
            ));
        }
        "lockdown" => {
            let enable = !state.config.lockdown_enabled;
            crate::app::set_global_lockdown(client, &state.config_path, enable)?;
            state.config.lockdown_enabled = enable;
            state.set_status(format!("{} Lockdown Mode.", enabled_verb(enable)));
        }
        "autoconnect" => {
            let enable = !state.config.general.autoconnect_at_login;
            crate::service::set_autoconnect_at_login(client, &state.config_path, enable)?;
            state.config.general.autoconnect_at_login = enable;
            state.set_status(format!("{} Auto Connect at Login.", enabled_verb(enable)));
        }
        "port_forwarding" => {
            let enable = !state.config.port_forwarding.enabled;
            // Persisted before the reload below, which re-reads the config from
            // disk into `state.config` and would otherwise revert the toggle.
            let mut app_cfg = config::load(&state.config_path)?;
            app_cfg.port_forwarding.enabled = enable;
            config::save(&state.config_path, &app_cfg)?;
            state.config.port_forwarding.enabled = enable;

            // The lease belongs to a tunnel, not to the toggle. Forgetting which
            // tunnel owns it makes the reload re-evaluate: it asks the gateway
            // for a port when this turned forwarding on, and drops the port it
            // is showing when this turned it off.
            state.active_port_uuid = None;
            reload_profiles(state, client)?;

            state.set_status(format!("{} NAT-PMP Port Forwarding.", enabled_verb(enable)));
        }
        "sync" => {
            let report = sync::sync_profiles_dir(client, &state.config)?;
            // The profile set may have changed, so the lockdown allow-list is
            // stale: a freshly imported profile has no rule and would be
            // blocked by the terminal REJECT.
            crate::app::rebuild_lockdown_if_enabled(client, &state.config_path)?;
            reload_profiles(state, client)?;
            if report.imported.is_empty() {
                state.set_status("Refreshed profiles.");
            } else {
                state.set_status(format!(
                    "Synced drop directory: imported {} profiles.",
                    report.imported.len()
                ));
            }
        }
        #[cfg(feature = "qbittorrent")]
        "qbit_sync" => {
            if let Some(port) = state.active_port {
                let iface = state
                    .selected_info
                    .as_ref()
                    .and_then(|info| info.diagnostics.interface_name.as_str().into());
                let mut qclient = crate::portforward::qbittorrent::QBittorrentClient::new(
                    &state.config.qbittorrent,
                );
                match qclient.sync_port(port, iface) {
                    Ok(rep) => {
                        state.set_status(format!(
                            "qBittorrent synced: port {} applied.",
                            rep.new_port
                        ));
                    }
                    Err(err) => {
                        state.set_status(format!("qBittorrent sync failed: {err}"));
                    }
                }
            } else {
                state.set_status(
                    "No forwarded port available (connect to a VPN with NAT-PMP first).",
                );
            }
        }
        #[cfg(feature = "qbittorrent")]
        "qbit_toggle" => {
            let enable = !state.config.qbittorrent.enabled;
            let mut app_cfg = config::load(&state.config_path)?;
            app_cfg.qbittorrent.enabled = enable;
            config::save(&state.config_path, &app_cfg)?;
            state.config.qbittorrent.enabled = enable;
            state.set_status(format!(
                "{} qBittorrent Port Forward Auto-Sync.",
                enabled_verb(enable)
            ));
        }
        "delete" => {
            if let Some(row) = state.selected_row() {
                state.modal = ActiveModal::ConfirmDelete {
                    name: row.name.clone(),
                    uuid: row.uuid.clone(),
                };
            }
        }
        // Not silently ignored: an id in the palette or the key map that the
        // dispatcher does not implement is a wiring mistake, and swallowing it
        // makes the action look broken rather than misconfigured.
        unknown => {
            return Err(crate::error::AppError::Config(format!(
                "unknown action id '{unknown}'"
            )));
        }
    }
    Ok(())
}

fn enabled_verb(enabled: bool) -> &'static str {
    if enabled { "Enabled" } else { "Disabled" }
}

fn handle_help_key(state: &mut TuiState, key: KeyEvent) {
    if matches!(
        key.code,
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') | KeyCode::Enter
    ) {
        state.modal = ActiveModal::None;
    }
}

fn handle_command_palette_key<C: ActionClient>(
    state: &mut TuiState,
    client: &C,
    key: KeyEvent,
) -> AppResult<()> {
    let ActiveModal::CommandPalette(ref mut cp) = state.modal else {
        return Ok(());
    };

    match key.code {
        KeyCode::Esc => state.modal = ActiveModal::None,
        KeyCode::Up => cp.selected_index = wrap_prev(cp.selected_index, cp.filtered_items().len()),
        KeyCode::Down => {
            cp.selected_index = wrap_next(cp.selected_index, cp.filtered_items().len())
        }
        KeyCode::Backspace => {
            cp.filter.pop();
            cp.selected_index = 0;
        }
        KeyCode::Char(c) => {
            cp.filter.push(c);
            cp.selected_index = 0;
        }
        KeyCode::Enter => {
            let action = cp
                .filtered_items()
                .get(cp.selected_index)
                .map(|item| item.id);
            state.modal = ActiveModal::None;
            if let Some(action) = action {
                execute_action(state, client, action)?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn handle_theme_picker_key(state: &mut TuiState, key: KeyEvent) {
    let ActiveModal::ThemePicker(ref mut tp) = state.modal else {
        return;
    };

    match key.code {
        KeyCode::Esc => state.modal = ActiveModal::None,
        KeyCode::Up => tp.selected_index = wrap_prev(tp.selected_index, tp.themes.len()),
        KeyCode::Down => tp.selected_index = wrap_next(tp.selected_index, tp.themes.len()),
        KeyCode::Enter => {
            let selected = tp.themes.get(tp.selected_index).copied();
            state.modal = ActiveModal::None;
            if let Some((preset, label)) = selected {
                state.config.theme.preset = preset.to_string();
                let _ = config::save(&state.config_path, &state.config);
                state.theme = crate::tui::theme::Theme::from_config(&state.config.theme);
                state.set_status(format!("Applied theme: {label}"));
            }
        }
        _ => {}
    }
}

fn handle_delete_key<C: ActionClient>(
    state: &mut TuiState,
    client: &C,
    key: KeyEvent,
    uuid: &str,
) -> AppResult<()> {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
            client.delete_profile(uuid)?;
            state.modal = ActiveModal::None;
            state.set_status("Profile deleted.");
            // The deleted profile's interface and endpoint rules are now stale.
            crate::app::rebuild_lockdown_if_enabled(client, &state.config_path)?;
            reload_profiles(state, client)?;
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            state.modal = ActiveModal::None;
            state.set_status("Deletion cancelled.");
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

    // Global save & apply.
    if (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s'))
        || key.code == KeyCode::F(2)
    {
        let new_cfg = st.to_config();
        split_tunnel::apply_and_persist_global_split_tunnel(client, &state.config_path, &new_cfg)?;
        state.config.global_split_tunnel = new_cfg;
        state.modal = ActiveModal::None;
        state.set_status("Saved & applied global split tunneling.");
        return Ok(());
    }

    if key.code == KeyCode::Esc {
        state.modal = ActiveModal::None;
        state.set_status("Split tunneling changes discarded.");
        return Ok(());
    }

    let typing = st.focus.is_text_input();

    match key.code {
        KeyCode::Tab => st.focus = st.focus.next(),
        KeyCode::BackTab => st.focus = st.focus.prev(),
        KeyCode::Char('1') if !typing => st.focus = SplitTunnelFocus::CidrInput,
        KeyCode::Char('2') if !typing => st.focus = SplitTunnelFocus::DomainInput,
        KeyCode::Char('m') if !typing => {
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
                if let Some(domain) = nm::split_tunnel::normalize_domain(&st.input_buffer) {
                    if !st.domains.contains(&domain) {
                        st.domains.push(domain);
                    }
                    st.input_buffer.clear();
                }
            }
            _ => {}
        },
        KeyCode::Backspace if typing => {
            st.input_buffer.pop();
        }
        KeyCode::Up => match st.focus {
            SplitTunnelFocus::CidrList => {
                st.selected_cidr = wrap_prev(st.selected_cidr, st.cidrs.len())
            }
            SplitTunnelFocus::DomainList => {
                st.selected_domain = wrap_prev(st.selected_domain, st.domains.len())
            }
            _ => {}
        },
        KeyCode::Down => match st.focus {
            SplitTunnelFocus::CidrList => {
                st.selected_cidr = wrap_next(st.selected_cidr, st.cidrs.len())
            }
            SplitTunnelFocus::DomainList => {
                st.selected_domain = wrap_next(st.selected_domain, st.domains.len())
            }
            _ => {}
        },
        KeyCode::Delete | KeyCode::Char('x') if !typing => match st.focus {
            SplitTunnelFocus::CidrList => remove_selected(&mut st.cidrs, &mut st.selected_cidr),
            SplitTunnelFocus::DomainList => {
                remove_selected(&mut st.domains, &mut st.selected_domain)
            }
            _ => {}
        },
        KeyCode::Char(c) if typing => st.input_buffer.push(c),
        _ => {}
    }

    Ok(())
}

/// Drop `list[*selected]`, keeping `*selected` inside the shortened list.
fn remove_selected(list: &mut Vec<String>, selected: &mut usize) {
    if *selected >= list.len() {
        return;
    }
    list.remove(*selected);
    *selected = (*selected).min(list.len().saturating_sub(1));
}

/// Push a newly leased forwarded port to qBittorrent.
///
/// Gated behind the `qbittorrent` feature: this fires automatically whenever the
/// port changes, so a broken integration would reach out to a third-party Web
/// API on every reconnect. Compiled out unless the feature is enabled.
#[cfg(feature = "qbittorrent")]
fn sync_qbittorrent_port<C: NmClient>(state: &TuiState, client: &C, uuid: &str, port: u16) {
    if !state.config.qbittorrent.enabled {
        return;
    }
    let interface = client
        .get_profile_diagnostics(uuid, true)
        .ok()
        .map(|diagnostics| diagnostics.interface_name);
    let mut qclient =
        crate::portforward::qbittorrent::QBittorrentClient::new(&state.config.qbittorrent);
    let _ = qclient.sync_port(port, interface.as_deref());
}

/// No-op when the `qbittorrent` feature is disabled.
#[cfg(not(feature = "qbittorrent"))]
fn sync_qbittorrent_port<C: NmClient>(_: &TuiState, _: &C, _: &str, _: u16) {}

/// Read everything the details pane shows for one profile.
///
/// Shared by the on-demand path and the background cache warmer so both always
/// populate the same fields.
pub fn fetch_profile_info<C: NmClient>(
    client: &C,
    uuid: &str,
    is_active: bool,
) -> CachedProfileInfo {
    let tunnel_address = client.tunnel_address(uuid);
    let gateway = tunnel_address
        .as_deref()
        .and_then(crate::portforward::gateway_for_address)
        .map(|gateway| gateway.to_string());

    CachedProfileInfo {
        diagnostics: client
            .get_profile_diagnostics(uuid, is_active)
            .unwrap_or_default(),
        tunnel_dns: client.tunnel_dns(uuid),
        tunnel_address,
        gateway,
    }
}

pub fn reload_profiles<C: NmClient>(state: &mut TuiState, client: &C) -> AppResult<()> {
    let profiles = client.list_wireguard_profiles()?;
    let app_cfg = config::load(&state.config_path)?;

    state.rows = crate::app::profile_list::build_rows(
        &profiles,
        &app_cfg.excluded_profile_ids,
        &app_cfg.favorite_profile_ids,
        &app_cfg.profile_custom_info,
    );
    state.config = app_cfg;

    let active = state.rows.iter().find(|row| row.is_active);
    state.active_profile_name = active.map(|row| row.name.clone());

    // Requesting a mapping is a blocking UDP round trip on the render thread,
    // and `reload_profiles` runs on every NetworkManager event -- which arrive
    // in bursts while a tunnel comes up. Only ask when the tunnel changed.
    let active_uuid = active.map(|row| row.uuid.clone());
    if state.config.port_forwarding.enabled {
        if active_uuid != state.active_port_uuid {
            let old_port = state.active_port;
            state.active_port_uuid = active_uuid.clone();
            state.active_port = active_uuid
                .as_ref()
                .and_then(|uuid| client.tunnel_address(uuid))
                .as_deref()
                .and_then(crate::portforward::port_for_tunnel_address);

            if state.active_port != old_port
                && let Some(port) = state.active_port
                && let Some(ref uuid) = active_uuid
            {
                sync_qbittorrent_port(state, client, uuid, port);
            }
        }
    } else {
        state.active_port_uuid = None;
        state.active_port = None;
    }

    if state.selected_index >= state.rows.len() {
        state.selected_index = state.rows.len().saturating_sub(1);
    }

    // Drop the active profile's cache entry so its live transfer counters and
    // handshake time are re-read rather than served stale.
    if let Some(uuid) = active.map(|row| row.uuid.clone()) {
        state.profile_cache.remove(&uuid);
    }

    update_diagnostics(state, client);
    Ok(())
}

pub fn update_diagnostics<C: NmClient>(state: &mut TuiState, client: &C) {
    let Some((uuid, _, is_active)) = state.selected_identity() else {
        state.selected_info = None;
        return;
    };

    let info = match state.profile_cache.get(&uuid) {
        Some(cached) => cached.clone(),
        None => {
            let fetched = fetch_profile_info(client, &uuid, is_active);
            state.profile_cache.insert(uuid, fetched.clone());
            fetched
        }
    };

    state.selected_info = Some(info);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::state::CommandPaletteState;

    #[test]
    fn every_action_the_key_map_produces_is_offered_by_the_palette() {
        // Regression: the palette listed 2 of the 13 implemented actions, so
        // most of the dispatcher was unreachable from it and had been
        // copy-pasted into the key handler instead.
        let palette_ids: Vec<&str> = CommandPaletteState::all_items()
            .into_iter()
            .map(|item| item.id)
            .collect();

        for key in [
            KeyCode::Char(' '),
            KeyCode::Char('s'),
            KeyCode::Char('e'),
            KeyCode::Char('f'),
            KeyCode::Char('*'),
            KeyCode::Char('v'),
            KeyCode::Char('t'),
            KeyCode::Char('k'),
            KeyCode::Char('l'),
            KeyCode::Char('o'),
            KeyCode::Char('a'),
            KeyCode::Char('r'),
            KeyCode::Char('d'),
            KeyCode::Char('?'),
            KeyCode::Char('q'),
        ] {
            let action = action_for_key(KeyEvent::new(key, KeyModifiers::NONE))
                .unwrap_or_else(|| panic!("{key:?} should be bound to an action"));
            assert!(
                palette_ids.contains(&action),
                "action '{action}' is reachable by key but missing from the palette"
            );
        }
    }

    #[test]
    fn palette_does_not_offer_an_entry_for_opening_itself() {
        // Every other id is exercised for real by `tests/tui_actions.rs`.
        for item in CommandPaletteState::all_items() {
            assert_ne!(item.id, "palette");
        }
    }

    #[test]
    fn port_forwarding_is_off_until_the_policy_is_turned_on() {
        // NAT-PMP leases are renewed on a timer against the provider's gateway,
        // so they are opt-in: a user who never asked for a forwarded port must
        // never have one requested on their behalf.
        assert!(
            !crate::config::AppConfig::default().port_forwarding.enabled,
            "port forwarding must default to off"
        );
    }

    #[test]
    fn toggling_port_forwarding_persists_and_drops_a_stale_lease() {
        let client = crate::testing::MockNmClient::new(vec![crate::testing::profile(
            "wg-eu",
            "uuid-eu",
            crate::nm::ProfileState::Active,
        )]);
        let path = crate::testing::temp_config_path("tui-port-forwarding");
        crate::config::save(&path, &crate::config::AppConfig::default())
            .expect("config should save");
        let mut state = TuiState::new(path.clone(), crate::config::AppConfig::default());

        execute_action(&mut state, &client, "port_forwarding").expect("toggle should succeed");
        assert!(state.config.port_forwarding.enabled);
        assert!(
            crate::config::load(&path)
                .expect("config should load")
                .port_forwarding
                .enabled,
            "the toggle must survive a restart, not just live in memory"
        );

        // A port shown while the policy was on must not linger once it is off:
        // it would advertise a mapping nothing is renewing any more.
        state.active_port = Some(51820);
        execute_action(&mut state, &client, "port_forwarding").expect("toggle should succeed");

        assert!(!state.config.port_forwarding.enabled);
        assert_eq!(state.active_port, None, "a stale lease must be cleared");
        assert!(
            !crate::config::load(&path)
                .expect("config should load")
                .port_forwarding
                .enabled
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn toggling_favorite_persists_and_updates_row() {
        let client = crate::testing::MockNmClient::new(vec![crate::testing::profile(
            "wg-star",
            "uuid-star",
            crate::nm::ProfileState::Inactive,
        )]);
        let path = crate::testing::temp_config_path("tui-favorite");
        crate::config::save(&path, &crate::config::AppConfig::default())
            .expect("config should save");
        let mut state = TuiState::new(path.clone(), crate::config::AppConfig::default());
        reload_profiles(&mut state, &client).unwrap();

        assert!(!state.rows[0].is_favorite);

        execute_action(&mut state, &client, "favorite").expect("favorite toggle should succeed");
        assert!(state.rows[0].is_favorite);
        assert!(
            crate::config::load(&path)
                .unwrap()
                .favorite_profile_ids
                .contains("uuid-star")
        );

        execute_action(&mut state, &client, "favorite").expect("favorite untoggle should succeed");
        assert!(!state.rows[0].is_favorite);
        assert!(
            !crate::config::load(&path)
                .unwrap()
                .favorite_profile_ids
                .contains("uuid-star")
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_unimplemented_action_id_is_reported_rather_than_ignored() {
        let client = crate::testing::MockNmClient::new(Vec::new());
        let mut state = TuiState::new(
            std::path::PathBuf::from("/nonexistent/config.toml"),
            crate::config::AppConfig::default(),
        );

        let result = execute_action(&mut state, &client, "no-such-action");

        assert!(
            matches!(result, Err(crate::error::AppError::Config(ref m)) if m.contains("no-such-action")),
            "got: {result:?}"
        );
    }

    #[test]
    fn control_p_and_colon_both_open_the_palette() {
        assert_eq!(
            action_for_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL)),
            Some("palette")
        );
        assert_eq!(
            action_for_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE)),
            Some("palette")
        );
    }

    #[test]
    fn plain_p_and_n_are_navigation_not_actions() {
        // `p`/`n` move the selection, so they must not collide with an action.
        assert_eq!(
            action_for_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE)),
            None
        );
    }

    #[test]
    fn remove_selected_clamps_the_index_into_the_shortened_list() {
        let mut list = vec!["a".to_string(), "b".to_string(), "c".to_string()];

        let mut selected = 2;
        remove_selected(&mut list, &mut selected);
        assert_eq!(list, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(selected, 1, "the last entry stays selected after removal");

        let mut selected = 0;
        remove_selected(&mut list, &mut selected);
        remove_selected(&mut list, &mut selected);
        assert!(list.is_empty());
        assert_eq!(selected, 0);

        // Removing from an empty list is a no-op rather than a panic.
        remove_selected(&mut list, &mut selected);
        assert!(list.is_empty());
    }

    #[test]
    fn modal_command_palette_key_events() {
        let client = crate::testing::MockNmClient::new(Vec::new());
        let path = crate::testing::temp_config_path("test-modal-cp");
        let mut state = TuiState::new(path.clone(), crate::config::AppConfig::default());
        state.modal = ActiveModal::CommandPalette(CommandPaletteState::default());

        // Typing characters filters
        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
        )
        .unwrap();
        if let ActiveModal::CommandPalette(ref cp) = state.modal {
            assert_eq!(cp.filter, "q");
        } else {
            panic!("expected CommandPalette modal");
        }

        // Backspace pops
        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
        )
        .unwrap();
        if let ActiveModal::CommandPalette(ref cp) = state.modal {
            assert_eq!(cp.filter, "");
        }

        // Down/Up arrows wrap
        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
        )
        .unwrap();
        if let ActiveModal::CommandPalette(ref cp) = state.modal {
            assert_eq!(cp.selected_index, 1);
        }

        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
        )
        .unwrap();
        if let ActiveModal::CommandPalette(ref cp) = state.modal {
            assert_eq!(cp.selected_index, 0);
        }

        // Esc closes
        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        )
        .unwrap();
        assert_eq!(state.modal, ActiveModal::None);

        crate::testing::remove_temp_config(&path);
    }

    #[test]
    fn modal_theme_picker_key_events() {
        let client = crate::testing::MockNmClient::new(Vec::new());
        let path = crate::testing::temp_config_path("test-modal-theme");
        let mut state = TuiState::new(path.clone(), crate::config::AppConfig::default());
        state.modal = ActiveModal::ThemePicker(ThemePickerState::default());

        // Down arrow changes selection
        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
        )
        .unwrap();
        if let ActiveModal::ThemePicker(ref tp) = state.modal {
            assert_eq!(tp.selected_index, 1);
        }

        // Enter applies theme and closes modal
        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        )
        .unwrap();
        assert_eq!(state.modal, ActiveModal::None);
        assert_eq!(state.config.theme.preset, "osaka-jade");

        crate::testing::remove_temp_config(&path);
    }

    #[test]
    fn modal_help_key_events() {
        let client = crate::testing::MockNmClient::new(Vec::new());
        let path = crate::testing::temp_config_path("test-modal-help");
        let mut state = TuiState::new(path.clone(), crate::config::AppConfig::default());

        for key in [
            KeyCode::Esc,
            KeyCode::Char('q'),
            KeyCode::Char('?'),
            KeyCode::Enter,
        ] {
            state.modal = ActiveModal::Help;
            handle_key_event(&mut state, &client, KeyEvent::new(key, KeyModifiers::NONE)).unwrap();
            assert_eq!(state.modal, ActiveModal::None);
        }

        crate::testing::remove_temp_config(&path);
    }

    #[test]
    fn modal_delete_key_events() {
        let client = crate::testing::MockNmClient::new(vec![crate::testing::profile(
            "wg-del",
            "uuid-del",
            crate::nm::ProfileState::Inactive,
        )]);
        let path = crate::testing::temp_config_path("test-modal-del");
        let mut state = TuiState::new(path.clone(), crate::config::AppConfig::default());

        // 'n' cancels
        state.modal = ActiveModal::ConfirmDelete {
            name: "wg-del".to_string(),
            uuid: "uuid-del".to_string(),
        };
        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
        )
        .unwrap();
        assert_eq!(state.modal, ActiveModal::None);
        assert!(state.status_message.contains("cancelled"));

        // 'y' confirms delete
        state.modal = ActiveModal::ConfirmDelete {
            name: "wg-del".to_string(),
            uuid: "uuid-del".to_string(),
        };
        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE),
        )
        .unwrap();
        assert_eq!(state.modal, ActiveModal::None);
        assert!(state.status_message.contains("deleted"));

        crate::testing::remove_temp_config(&path);
    }

    #[test]
    fn modal_split_tunnel_key_events() {
        let client = crate::testing::MockNmClient::new(Vec::new());
        let path = crate::testing::temp_config_path("test-modal-st");
        let mut state = TuiState::new(path.clone(), crate::config::AppConfig::default());
        state.modal =
            ActiveModal::SplitTunnel(crate::tui::state::SplitTunnelModalState::from_config(
                &crate::config::SplitTunnelConfig::default(),
            ));

        // 'm' toggles mode: Disabled -> Include -> Exclude -> Disabled
        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE),
        )
        .unwrap();
        if let ActiveModal::SplitTunnel(ref st) = state.modal {
            assert_eq!(st.mode, SplitTunnelMode::Include);
        }

        // '1' focuses CidrInput
        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE),
        )
        .unwrap();
        if let ActiveModal::SplitTunnel(ref st) = state.modal {
            assert_eq!(st.focus, SplitTunnelFocus::CidrInput);
        }

        // Type CIDR "10.0.0.0/8" and press Enter
        for c in "10.0.0.0/8".chars() {
            handle_key_event(
                &mut state,
                &client,
                KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
            )
            .unwrap();
        }
        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        )
        .unwrap();
        if let ActiveModal::SplitTunnel(ref st) = state.modal {
            assert_eq!(st.cidrs, vec!["10.0.0.0/8".to_string()]);
            assert_eq!(st.input_buffer, "");
        }

        // '2' focuses DomainInput
        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
        )
        .unwrap();
        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
        )
        .unwrap();
        if let ActiveModal::SplitTunnel(ref st) = state.modal {
            assert_eq!(st.focus, SplitTunnelFocus::DomainInput);
        }

        // Type domain "example.com" and press Enter
        for c in "example.com".chars() {
            handle_key_event(
                &mut state,
                &client,
                KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
            )
            .unwrap();
        }
        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        )
        .unwrap();
        if let ActiveModal::SplitTunnel(ref st) = state.modal {
            assert_eq!(st.domains, vec!["example.com".to_string()]);
        }

        // Ctrl+S saves and applies
        handle_key_event(
            &mut state,
            &client,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
        )
        .unwrap();
        assert_eq!(state.modal, ActiveModal::None);
        assert_eq!(
            state.config.global_split_tunnel.mode,
            SplitTunnelMode::Include
        );

        crate::testing::remove_temp_config(&path);
    }
}
