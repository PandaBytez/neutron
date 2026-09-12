//! Terminal User Interface (TUI) for Neutron.

pub mod events;
pub mod state;
pub mod theme;
pub mod ui;

fn spawn_worker<T: Send + 'static, R: Send + 'static>(
    mut work: impl FnMut(T) -> R + Send + 'static,
) -> (std::sync::mpsc::Sender<T>, std::sync::mpsc::Receiver<R>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        while let Ok(request) = rx.recv() {
            if result_tx.send(work(request)).is_err() {
                break;
            }
        }
    });
    (tx, result_rx)
}

use std::io::stdout;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::config;
use crate::error::AppResult;
use crate::firewall::FirewallClient;
use crate::nm::NmClient;
use crate::tui::state::TuiState;

/// RAII guard ensuring raw mode and alternate screen are restored on any exit path.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen, Show);
    }
}

pub fn run<C>(client: C) -> AppResult<()>
where
    C: NmClient + FirewallClient + Clone + Send + Sync + 'static,
{
    // Load config before modifying terminal attributes so malformed config
    // returns early without touching terminal mode (BUG-013).
    let config_path = config::default_config_path()?;
    let app_cfg = config::load(&config_path)?;
    let mut state = TuiState::new(config_path, app_cfg);

    enable_raw_mode()?;
    let _guard = TerminalGuard;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, Hide)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen, Show);
        default_panic(info);
    }));

    // Channel for async public IP updates (in-flight atomic prevents thread storms - BUG-037)
    let (ip_tx, ip_rx) = std::sync::mpsc::channel();
    let ip_coord = PublicIpLookupCoordinator::new(ip_tx);
    ip_coord.request_refresh();

    let (lat_tx, lat_rx) = std::sync::mpsc::channel();
    let lat_tx_clone = lat_tx.clone();
    thread::spawn(move || {
        loop {
            if let Some(ms) = crate::nm::network_info::sample_latency() {
                let _ = lat_tx_clone.send(ms);
            }
            thread::sleep(Duration::from_secs(3));
        }
    });

    let initial_refresh_needed = true;
    // Read once up front so the first frame shows the daemon's lease rather than
    // reporting it missing until the first periodic tick.
    events::refresh_lease(&mut state);

    if let Some(active_idx) = state.rows.iter().position(|r| r.is_active) {
        state.selected_index = active_idx;
    } else {
        state.selected_index = 0;
    }
    events::update_diagnostics(&mut state, &client);

    let (cache_tx, cache_rx) = std::sync::mpsc::channel();
    let cache_tx_for_rows = cache_tx.clone();
    let client_for_cache = client.clone();
    let rows_to_cache: Vec<(String, bool)> = state
        .rows
        .iter()
        .map(|r| (r.uuid.clone(), r.is_active))
        .collect();
    thread::spawn(move || {
        for (uuid, is_active) in rows_to_cache {
            let info = events::fetch_profile_info(&client_for_cache, &uuid, is_active);
            let _ = cache_tx_for_rows.send((uuid, info));
        }
    });

    let (diag_req_tx, diag_req_rx) = std::sync::mpsc::channel::<(String, bool)>();
    state.diag_tx = Some(diag_req_tx);
    let client_for_diag = client.clone();
    let cache_tx_for_diag = cache_tx.clone();
    thread::spawn(move || {
        while let Ok((uuid, is_active)) = diag_req_rx.recv() {
            let info = events::fetch_profile_info(&client_for_diag, &uuid, is_active);
            let _ = cache_tx_for_diag.send((uuid, info));
        }
    });

    let (action_tx, action_rx) = std::sync::mpsc::channel::<crate::tui::state::AsyncAction>();
    let (action_res_tx, action_res_rx) =
        std::sync::mpsc::channel::<crate::tui::state::AsyncActionResult>();
    state.action_tx = Some(action_tx);

    let client_for_action = client.clone();
    let config_path_for_action = state.config_path.clone();
    thread::spawn(move || {
        if let Err(error) = crate::service::reconcile_autoconnect_at_login(&config_path_for_action)
        {
            let _ = action_res_tx.send(crate::tui::state::AsyncActionResult::Sync(Err(error)));
        }
        while let Ok(action) = action_rx.recv() {
            let res = match action {
                crate::tui::state::AsyncAction::KillSwitch(enable) => {
                    let r = crate::app::set_global_kill_switch(
                        &client_for_action,
                        &config_path_for_action,
                        enable,
                    );
                    crate::tui::state::AsyncActionResult::KillSwitch { enable, result: r }
                }
                crate::tui::state::AsyncAction::Lockdown(enable) => {
                    let r = crate::app::set_global_lockdown(
                        &client_for_action,
                        &config_path_for_action,
                        enable,
                    );
                    crate::tui::state::AsyncActionResult::Lockdown { enable, result: r }
                }
                crate::tui::state::AsyncAction::Autoconnect(enable) => {
                    let r = crate::service::set_autoconnect_at_login(
                        &client_for_action,
                        &config_path_for_action,
                        enable,
                    );
                    crate::tui::state::AsyncActionResult::Autoconnect { enable, result: r }
                }
                crate::tui::state::AsyncAction::Sync => {
                    let r = (|| {
                        let cfg = crate::config::load(&config_path_for_action)?;
                        let report = crate::app::sync::sync_profiles_dir(&client_for_action, &cfg)?;
                        crate::app::rebuild_lockdown_if_enabled(
                            &client_for_action,
                            &config_path_for_action,
                        )?;
                        Ok(report)
                    })();
                    crate::tui::state::AsyncActionResult::Sync(r)
                }
                crate::tui::state::AsyncAction::Delete(uuid) => {
                    let r = (|| {
                        client_for_action.delete_profile(&uuid)?;
                        crate::app::rebuild_lockdown_if_enabled(
                            &client_for_action,
                            &config_path_for_action,
                        )?;
                        Ok(uuid)
                    })();
                    crate::tui::state::AsyncActionResult::Delete(r)
                }
            };
            let _ = action_res_tx.send(res);
        }
    });
    if state.config.general.auto_sync_profiles
        && let Some(tx) = &state.action_tx
    {
        let _ = tx.send(crate::tui::state::AsyncAction::Sync);
    }

    let (connect_tx, connect_rx) = std::sync::mpsc::channel::<(String, String, bool)>();
    let (conn_res_tx, conn_res_rx) = std::sync::mpsc::channel::<(String, AppResult<()>, bool)>();
    state.connect_tx = Some(connect_tx);

    let client_for_conn = client.clone();
    let path_for_conn = state.config_path.clone();
    thread::spawn(move || {
        while let Ok((uuid, name, is_connect)) = connect_rx.recv() {
            let res = if is_connect {
                client_for_conn.switch_to(&uuid)
            } else {
                client_for_conn.disconnect_active()
            };
            let reconciliation =
                crate::app::rebuild_lockdown_if_enabled(&client_for_conn, &path_for_conn);
            let res = res.and(reconciliation);
            let _ = conn_res_tx.send((name, res, is_connect));
        }
    });

    let (split_tunnel_tx, split_tunnel_rx) =
        std::sync::mpsc::channel::<crate::config::SplitTunnelConfig>();
    let (st_res_tx, st_res_rx) =
        std::sync::mpsc::channel::<(crate::config::SplitTunnelConfig, AppResult<()>)>();
    state.split_tunnel_tx = Some(split_tunnel_tx);

    let client_for_st = client.clone();
    let config_path_for_st = state.config_path.clone();
    thread::spawn(move || {
        while let Ok(mut cfg) = split_tunnel_rx.recv() {
            // Coalesce rapid updates: drain to the latest config
            while let Ok(newer_cfg) = split_tunnel_rx.try_recv() {
                cfg = newer_cfg;
            }
            let res = if cfg.mode.is_enabled() {
                crate::app::split_tunnel::apply_and_persist_global_split_tunnel(
                    &client_for_st,
                    &config_path_for_st,
                    &cfg,
                )
            } else {
                let current = crate::config::load(&config_path_for_st);
                let mode_changed = current
                    .map(|c| c.global_split_tunnel.mode != cfg.mode)
                    .unwrap_or(false);
                if mode_changed {
                    crate::app::split_tunnel::apply_and_persist_global_split_tunnel(
                        &client_for_st,
                        &config_path_for_st,
                        &cfg,
                    )
                } else {
                    crate::config::update(&config_path_for_st, |c| {
                        c.global_split_tunnel = cfg.clone()
                    })
                    .map(|_| ())
                }
            };
            let _ = st_res_tx.send((cfg, res));
        }
    });

    crate::service::indicator::ensure_indicator_daemon_running();

    let monitor_events = Arc::new(AtomicU64::new(0));
    let monitor_events_clone = monitor_events.clone();
    let monitor_child: MonitorChild = Arc::new(Mutex::new(MonitorSlot::Unset));
    let monitor_child_for_thread = monitor_child.clone();
    let monitor_thread = thread::spawn(move || {
        start_nm_monitor_loop(monitor_events_clone, monitor_child_for_thread);
    });

    // Keep event-loop errors from skipping terminal and child-process cleanup.
    let outcome = run_event_loop(
        &mut terminal,
        &mut state,
        &client,
        &ip_coord,
        &ip_rx,
        &lat_rx,
        &cache_rx,
        &conn_res_rx,
        &st_res_rx,
        &action_res_rx,
        &monitor_events,
        initial_refresh_needed,
    );

    stop_nm_monitor(&monitor_child);
    let _ = monitor_thread.join();
    restore_terminal(&mut terminal);
    outcome
}

/// The `nmcli monitor` child state, shared so shutdown is synchronized without leaking.
#[derive(Default)]
enum MonitorSlot {
    #[default]
    Unset,
    Active(std::process::Child),
    Shutdown,
}

type MonitorChild = Arc<Mutex<MonitorSlot>>;

/// Kill the `nmcli monitor` child and reap it, or mark shutdown so a late spawn aborts.
fn stop_nm_monitor(child: &MonitorChild) {
    if let Ok(mut slot) = child.lock() {
        let prev = std::mem::replace(&mut *slot, MonitorSlot::Shutdown);
        if let MonitorSlot::Active(mut process) = prev {
            let _ = process.kill();
            // Reaped rather than just killed, so the process does not linger as a
            // zombie for as long as the parent lives.
            let _ = process.wait();
        }
    }
}

/// Restore the terminal to a usable state. Best-effort and infallible: this
/// runs while unwinding from an error, and failing to undo one step must not
/// prevent the others -- a half-restored terminal is what leaves a shell
/// unusable.
fn restore_terminal<B: ratatui::backend::Backend + std::io::Write>(terminal: &mut Terminal<B>) {
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen, Show);
    let _ = terminal.show_cursor();
}

#[allow(clippy::too_many_arguments)]
fn run_event_loop<C, B>(
    terminal: &mut Terminal<B>,
    state: &mut TuiState,
    client: &C,
    ip_coord: &PublicIpLookupCoordinator,
    ip_rx: &std::sync::mpsc::Receiver<(u64, Option<crate::nm::network_info::PublicIpInfo>)>,
    lat_rx: &std::sync::mpsc::Receiver<u32>,
    cache_rx: &std::sync::mpsc::Receiver<(String, crate::tui::state::CachedProfileInfo)>,
    conn_res_rx: &std::sync::mpsc::Receiver<(String, AppResult<()>, bool)>,
    st_res_rx: &std::sync::mpsc::Receiver<(crate::config::SplitTunnelConfig, AppResult<()>)>,
    action_res_rx: &std::sync::mpsc::Receiver<crate::tui::state::AsyncActionResult>,
    monitor_events: &Arc<AtomicU64>,
    initial_refresh_needed: bool,
) -> AppResult<()>
where
    C: NmClient + FirewallClient + Clone + Send + Sync + 'static,
    B: ratatui::backend::Backend,
{
    let mut last_seen_event = 0_u64;
    let mut needs_profile_refresh = initial_refresh_needed;
    let mut last_diag_sample = std::time::Instant::now();
    let refresh_client = client.clone();
    let refresh_path = state.config_path.clone();
    let (refresh_tx, snapshot_rx) = spawn_worker(move |()| {
        refresh_client
            .list_wireguard_profiles()
            .and_then(|profiles| config::load(&refresh_path).map(|cfg| (profiles, cfg)))
    });
    let mut refresh_in_flight = false;
    let mut retry_at = std::time::Instant::now();

    while !state.should_quit {
        // Drain any incoming public IP updates from background worker, checking generation (BUG-037)
        while let Ok((generation_id, info)) = ip_rx.try_recv() {
            if generation_id == ip_coord.generation.load(Ordering::SeqCst) {
                state.public_ip_info = info;
            }
        }

        // Drain any incoming latency updates
        while let Ok(ms) = lat_rx.try_recv() {
            state.latency_ms = Some(ms);
        }

        // Drain any background profile cache updates
        while let Ok((uuid, info)) = cache_rx.try_recv() {
            let matches_sel = state
                .selected_identity()
                .map(|(u, _, _)| u == uuid)
                .unwrap_or(false);
            if matches_sel {
                state.selected_info = Some(info.clone());
            }
            state.profile_cache.insert(uuid, info);
        }

        // Drain any incoming background connection/disconnection results
        while let Ok((name, res, is_connect)) = conn_res_rx.try_recv() {
            state.connecting = None;
            match res {
                Ok(()) => {
                    if is_connect {
                        state.set_status(format!("Connected '{name}'."));
                    } else {
                        state.set_status(format!("Disconnected '{name}'."));
                        state.public_ip_info = None;
                    }
                    ip_coord.request_refresh();
                    needs_profile_refresh = true;
                }
                Err(err) => {
                    state.set_error(&err);
                    needs_profile_refresh = true;
                }
            }
        }

        // Drain any incoming background split tunneling application results (BUG-063)
        while let Ok((applied_cfg, res)) = st_res_rx.try_recv() {
            state.finish_split(applied_cfg, res);
        }

        // Drain any incoming background action results
        while let Ok(action_res) = action_res_rx.try_recv() {
            match action_res {
                crate::tui::state::AsyncActionResult::KillSwitch { enable, result } => match result
                {
                    Ok(()) => {
                        state
                            .uncertain_policies
                            .remove(&crate::error::Policy::KillSwitch);
                        state.config.kill_switch_enabled = enable;
                        state.set_status(format!(
                            "{} saved Kill Switch policy; reconnect to apply routing/DNS changes.",
                            events::enabled_verb(enable)
                        ));
                    }
                    Err(err) => {
                        state.set_error(&err);
                        if let Ok(persisted) = crate::config::load(&state.config_path) {
                            state.config.kill_switch_enabled = persisted.kill_switch_enabled;
                        }
                    }
                },
                crate::tui::state::AsyncActionResult::Lockdown { enable, result } => match result {
                    Ok(()) => {
                        state
                            .uncertain_policies
                            .remove(&crate::error::Policy::Lockdown);
                        state.config.lockdown_enabled = enable;
                        state
                            .set_status(format!("{} Lockdown Mode.", events::enabled_verb(enable)));
                    }
                    Err(err) => {
                        state.set_error(&err);
                        if let Ok(persisted) = crate::config::load(&state.config_path) {
                            state.config.lockdown_enabled = persisted.lockdown_enabled;
                        }
                    }
                },
                crate::tui::state::AsyncActionResult::Autoconnect { enable, result } => {
                    match result {
                        Ok(()) => {
                            state.config.general.autoconnect_at_login = enable;
                            state.set_status(format!(
                                "{} Auto Connect at Login.",
                                events::enabled_verb(enable)
                            ));
                        }
                        Err(err) => {
                            state.set_error(&err);
                            if let Ok(persisted) = crate::config::load(&state.config_path) {
                                state.config.general.autoconnect_at_login =
                                    persisted.general.autoconnect_at_login;
                            }
                        }
                    }
                }
                crate::tui::state::AsyncActionResult::Sync(result) => match result {
                    Ok(report) => {
                        needs_profile_refresh = true;
                        if !report.errors.is_empty() {
                            state.set_error(&crate::error::AppError::Config(
                                report.errors.join("; "),
                            ));
                        } else if report.imported.is_empty() {
                            state.set_status("Refreshed profiles.");
                        } else {
                            state.set_status(format!(
                                "Imported {} new profile(s).",
                                report.imported.len()
                            ));
                        }
                    }
                    Err(err) => state.set_error(&err),
                },
                crate::tui::state::AsyncActionResult::Delete(result) => match result {
                    Ok(_) => {
                        state.set_status("Profile deleted.");
                        needs_profile_refresh = true;
                    }
                    Err(err) => state.set_error(&err),
                },
            }
        }

        // Periodically refresh active profile diagnostics / total data every 1.5s in sync with throughput rates
        if last_diag_sample.elapsed() >= Duration::from_millis(1500) {
            last_diag_sample = std::time::Instant::now();

            // The lease is renewed on the daemon's own clock, not in response to
            // anything NetworkManager reports, so it has to be re-read on a tick
            // rather than only when the profile list changes.
            events::refresh_lease(state);

            if let Some((uuid, _, true)) = state.selected_identity() {
                if let Some(ref tx) = state.diag_tx {
                    let _ = tx.send((uuid, true));
                } else {
                    state.profile_cache.remove(&uuid);
                    events::update_diagnostics(state, client);
                }
            }
        }

        // Update real-time bandwidth throughput rates (1.5s sampling)
        state.update_throughput();

        // Draw frame (ignore transient interrupted errors)
        if let Err(err) = terminal.draw(|frame| {
            ui::render(frame, state);
        }) && err.kind() != std::io::ErrorKind::Interrupted
        {
            tracing::warn!("terminal draw error: {err}");
        }

        // Check if NetworkManager emitted connection change events
        let current_nm_event = monitor_events.load(Ordering::Relaxed);
        if std::mem::take(&mut state.profile_refresh_requested) {
            needs_profile_refresh = true;
        }
        if current_nm_event != last_seen_event {
            last_seen_event = current_nm_event;
            needs_profile_refresh = true;
        }

        while let Ok(result) = snapshot_rx.try_recv() {
            refresh_in_flight = false;
            let prev_active_uuid = state.active_profile_uuid.clone();
            match result {
                Ok((profiles, cfg)) => {
                    events::apply_profile_snapshot(state, profiles, cfg);
                    events::update_diagnostics(state, client);
                    if state.active_profile_uuid != prev_active_uuid {
                        if state.active_profile_uuid.is_none() {
                            state.public_ip_info = None;
                        }
                        ip_coord.request_refresh();
                    }
                }
                Err(err) => {
                    // Do not drop the refresh requirement on transient errors (BUG-048)
                    state.set_error(&err);
                    needs_profile_refresh = true;
                    retry_at = std::time::Instant::now() + Duration::from_secs(1);
                }
            }
        }
        if needs_profile_refresh
            && !refresh_in_flight
            && std::time::Instant::now() >= retry_at
            && refresh_tx.send(()).is_ok()
        {
            needs_profile_refresh = false;
            refresh_in_flight = true;
        }

        // Poll for user keyboard input with 50ms timeout (smooth 20 FPS refresh)
        match event::poll(Duration::from_millis(50)) {
            Ok(true) => match event::read() {
                Ok(Event::Key(key)) => {
                    if let Err(error) = events::handle_key_event(state, client, key) {
                        state.set_error(&error);
                    }
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    tracing::warn!("crossterm event read error: {e}");
                }
            },
            Ok(false) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                tracing::warn!("crossterm event poll error: {e}");
            }
        }
    }

    Ok(())
}

fn start_nm_monitor_loop(events: Arc<AtomicU64>, slot: MonitorChild) {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let mut child = match Command::new("nmcli")
        .arg("monitor")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
    };

    // Hand the child to the main thread so it can be killed on exit. If the
    // main thread has already initiated shutdown, kill and reap immediately.
    if let Ok(mut lock) = slot.lock() {
        if matches!(*lock, MonitorSlot::Shutdown) {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        *lock = MonitorSlot::Active(child);
    }

    let reader = BufReader::new(stdout);
    for line in reader.lines().map_while(Result::ok) {
        if crate::app::refresh_sync::should_refresh_from_nm_monitor_line(&line) {
            events.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Clone)]
pub(crate) struct PublicIpLookupCoordinator {
    tx: std::sync::mpsc::Sender<(u64, Option<crate::nm::network_info::PublicIpInfo>)>,
    generation: Arc<AtomicU64>,
    worker_state: Arc<Mutex<(bool, bool)>>,
}

impl PublicIpLookupCoordinator {
    fn new(
        tx: std::sync::mpsc::Sender<(u64, Option<crate::nm::network_info::PublicIpInfo>)>,
    ) -> Self {
        Self {
            tx,
            generation: Arc::new(AtomicU64::new(0)),
            worker_state: Arc::new(Mutex::new((false, false))),
        }
    }

    fn request_refresh(&self) {
        self.request_with(crate::nm::network_info::fetch_public_ip_info);
    }

    fn request_with(
        &self,
        mut fetch: impl FnMut() -> Option<crate::nm::network_info::PublicIpInfo> + Send + 'static,
    ) {
        let mut state = self.worker_state.lock().expect("IP worker state poisoned");
        let current_gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        if state.0 {
            state.1 = true;
            return;
        }
        state.0 = true;

        let coord = self.clone();
        thread::spawn(move || {
            let mut generation_id = current_gen;
            loop {
                let info = fetch();
                if generation_id == coord.generation.load(Ordering::SeqCst) {
                    let _ = coord.tx.send((generation_id, info));
                }
                let mut state = coord.worker_state.lock().expect("IP worker state poisoned");
                if state.1 {
                    state.1 = false;
                    generation_id = coord.generation.load(Ordering::SeqCst);
                } else {
                    state.0 = false;
                    break;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_worker_can_block_while_ui_processes_input_and_then_retry() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let mut first = true;
        let (tx, rx) = spawn_worker(move |()| -> AppResult<()> {
            if first {
                first = false;
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Err(crate::error::AppError::CommandFailed(
                    "transient failure".into(),
                ))
            } else {
                Ok(())
            }
        });
        tx.send(()).unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let path = crate::testing::temp_config_path("blocked-worker");
        let mut state = TuiState::new(path, config::AppConfig::default());
        events::handle_key_event(
            &mut state,
            &crate::testing::MockNmClient::default(),
            crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::Char('q'),
                crossterm::event::KeyModifiers::NONE,
            ),
        )
        .unwrap();
        assert!(state.should_quit);
        assert!(rx.try_recv().is_err());
        release_tx.send(()).unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap().is_err());
        tx.send(()).unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap().is_ok());
    }

    #[test]
    fn in_flight_guard_prevents_concurrent_ip_lookups() {
        let (tx, rx) = std::sync::mpsc::channel();
        let coord = PublicIpLookupCoordinator::new(tx);
        // Simulate in-flight worker
        coord.worker_state.lock().unwrap().0 = true;
        coord.request_refresh();
        // Request marked pending without spawning extra concurrent worker
        assert!(coord.worker_state.lock().unwrap().1);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn delayed_lookup_coalesces_and_discards_stale_replies() {
        let (tx, rx) = std::sync::mpsc::channel();
        let coord = PublicIpLookupCoordinator::new(tx);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let mut first = true;
        coord.request_with(move || {
            if first {
                first = false;
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            }
            None
        });
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        coord.request_with(|| panic!("must coalesce into existing worker"));
        coord.request_with(|| panic!("must coalesce into existing worker"));
        release_tx.send(()).unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap().0, 3);
        // Repeated requests racing worker completion must each eventually finish.
        for _ in 0..100 {
            coord.request_with(|| None);
            let generation = coord.generation.load(Ordering::SeqCst);
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(2)).unwrap().0,
                generation
            );
        }
    }

    #[test]
    fn shutdown_before_monitor_publication_reaps_child() {
        let slot: MonitorChild = Arc::new(Mutex::new(MonitorSlot::Unset));
        // Main thread requests shutdown first
        stop_nm_monitor(&slot);

        // Child process spawns subsequently
        let mut child = std::process::Command::new("sleep")
            .arg("10")
            .spawn()
            .expect("sleep should spawn");

        if let Ok(mut lock) = slot.lock() {
            if matches!(*lock, MonitorSlot::Shutdown) {
                let _ = child.kill();
                let _ = child.wait();
            } else {
                *lock = MonitorSlot::Active(child);
                return;
            }
        }

        // Verify child was killed and waited on (reaped)
        match child.try_wait() {
            Ok(Some(status)) => assert!(!status.success()),
            other => panic!("expected child to be reaped, got {other:?}"),
        }
    }
}
