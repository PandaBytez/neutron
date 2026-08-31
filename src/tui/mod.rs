//! Terminal User Interface (TUI) for Neutron.

pub mod events;
pub mod state;
pub mod theme;
pub mod ui;

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

pub fn run<C>(client: C) -> AppResult<()>
where
    C: NmClient + FirewallClient + Clone + Send + Sync + 'static,
{
    // Setup terminal
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, Hide)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    // Set panic hook so terminal is restored cleanly if a panic occurs
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen, Show);
        default_panic(info);
    }));

    let config_path = config::default_config_path()?;
    let app_cfg = config::load(&config_path)?;
    let mut state = TuiState::new(config_path, app_cfg);

    // Channel for async public IP updates
    let (ip_tx, ip_rx) = std::sync::mpsc::channel();
    spawn_public_ip_lookup(ip_tx.clone());

    // Channel for async latency updates
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

    // Initial drop directory sync & profile loading
    if state.config.general.auto_sync_profiles {
        let _ = crate::app::sync::sync_profiles_dir(&client, &state.config);
    }
    let _ = events::reload_profiles(&mut state, &client);

    // Initial focus on active profile (or index 0) once at TUI startup
    if let Some(active_idx) = state.rows.iter().position(|r| r.is_active) {
        state.selected_index = active_idx;
    } else {
        state.selected_index = 0;
    }
    events::update_diagnostics(&mut state, &client);

    // Channel for background profile cache warming
    let (cache_tx, cache_rx) = std::sync::mpsc::channel();
    let client_for_cache = client.clone();
    let rows_to_cache: Vec<(String, bool)> = state
        .rows
        .iter()
        .map(|r| (r.uuid.clone(), r.is_active))
        .collect();
    thread::spawn(move || {
        for (uuid, is_active) in rows_to_cache {
            let info = events::fetch_profile_info(&client_for_cache, &uuid, is_active);
            let _ = cache_tx.send((uuid, info));
        }
    });

    // Channel for non-blocking asynchronous connection requests & worker replies
    let (connect_tx, connect_rx) = std::sync::mpsc::channel::<(String, String, bool)>();
    let (conn_res_tx, conn_res_rx) = std::sync::mpsc::channel::<(String, AppResult<()>, bool)>();
    state.connect_tx = Some(connect_tx);

    let client_for_conn = client.clone();
    thread::spawn(move || {
        while let Ok((uuid, name, is_connect)) = connect_rx.recv() {
            let res = if is_connect {
                client_for_conn.switch_to(&uuid)
            } else {
                client_for_conn.disconnect_active()
            };
            let _ = conn_res_tx.send((name, res, is_connect));
        }
    });

    // Ensure background indicator daemon is running (spawn once if not already active)
    crate::service::indicator::ensure_indicator_daemon_running();

    // NetworkManager monitor event counter
    let monitor_events = Arc::new(AtomicU64::new(0));
    let monitor_events_clone = monitor_events.clone();
    let monitor_child: MonitorChild = Arc::new(Mutex::new(None));
    let monitor_child_for_thread = monitor_child.clone();
    let _monitor_thread = thread::spawn(move || {
        start_nm_monitor_loop(monitor_events_clone, monitor_child_for_thread);
    });

    // The loop body is wrapped so the terminal is restored on *every* exit
    // path. A `?` inside it (a failed draw or a lost stdin) previously skipped
    // the restore below and left the shell in raw mode with no cursor -- the
    // user's terminal was unusable until they blindly typed `reset`.
    let outcome = run_event_loop(
        &mut terminal,
        &mut state,
        &client,
        &ip_tx,
        &ip_rx,
        &lat_rx,
        &cache_rx,
        &conn_res_rx,
        &monitor_events,
    );

    stop_nm_monitor(&monitor_child);
    restore_terminal(&mut terminal);
    outcome
}

/// The `nmcli monitor` child, shared so the main thread can stop it on exit.
type MonitorChild = Arc<Mutex<Option<std::process::Child>>>;

/// Kill the `nmcli monitor` child and reap it.
///
/// The monitor is a separate process, not just a thread, so letting the reader
/// thread end does not stop it: it keeps running with a closed pipe. Every TUI
/// session used to leave one behind, so a few launches accumulated a handful of
/// orphaned `nmcli monitor` processes that outlived the app indefinitely.
fn stop_nm_monitor(child: &MonitorChild) {
    if let Ok(mut slot) = child.lock()
        && let Some(mut child) = slot.take()
    {
        let _ = child.kill();
        // Reaped rather than just killed, so the process does not linger as a
        // zombie for as long as the parent lives.
        let _ = child.wait();
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
    ip_tx: &std::sync::mpsc::Sender<crate::nm::network_info::PublicIpInfo>,
    ip_rx: &std::sync::mpsc::Receiver<crate::nm::network_info::PublicIpInfo>,
    lat_rx: &std::sync::mpsc::Receiver<u32>,
    cache_rx: &std::sync::mpsc::Receiver<(String, crate::tui::state::CachedProfileInfo)>,
    conn_res_rx: &std::sync::mpsc::Receiver<(String, AppResult<()>, bool)>,
    monitor_events: &Arc<AtomicU64>,
) -> AppResult<()>
where
    C: NmClient + FirewallClient + Clone + Send + Sync + 'static,
    B: ratatui::backend::Backend,
{
    let mut last_seen_event = 0_u64;
    let mut last_diag_sample = std::time::Instant::now();

    while !state.should_quit {
        // Drain any incoming public IP updates from background worker
        while let Ok(info) = ip_rx.try_recv() {
            state.public_ip_info = Some(info);
        }

        // Drain any incoming latency updates
        while let Ok(ms) = lat_rx.try_recv() {
            state.latency_ms = Some(ms);
        }

        // Drain any background profile cache updates
        while let Ok((uuid, info)) = cache_rx.try_recv() {
            state.profile_cache.entry(uuid).or_insert(info);
        }

        // Drain any incoming background connection/disconnection results
        while let Ok((name, res, is_connect)) = conn_res_rx.try_recv() {
            state.connecting = None;
            match res {
                Ok(()) => {
                    if is_connect {
                        state.set_status(format!("Connected '{name}'."));
                        spawn_public_ip_lookup(ip_tx.clone());
                    } else {
                        state.set_status(format!("Disconnected '{name}'."));
                    }
                    let _ = events::reload_profiles(state, client);
                    events::update_diagnostics(state, client);
                }
                Err(err) => {
                    state.set_error(&err);
                    let _ = events::reload_profiles(state, client);
                }
            }
        }

        // Periodically refresh active profile diagnostics / total data every 1.5s in sync with throughput rates
        if last_diag_sample.elapsed() >= Duration::from_millis(1500) {
            last_diag_sample = std::time::Instant::now();
            if let Some((uuid, _, true)) = state.selected_identity() {
                state.profile_cache.remove(&uuid);
                events::update_diagnostics(state, client);
            }
        }

        // Update real-time bandwidth throughput rates (1.5s sampling)
        state.update_throughput();

        // Draw frame (ignore transient interrupted errors)
        if let Err(err) = terminal.draw(|frame| {
            ui::render(frame, state);
        }) {
            if err.kind() != std::io::ErrorKind::Interrupted {
                tracing::warn!("terminal draw error: {err}");
            }
        }

        // Check if NetworkManager emitted connection change events
        let current_nm_event = monitor_events.load(Ordering::Relaxed);
        if current_nm_event != last_seen_event {
            last_seen_event = current_nm_event;
            let _ = events::reload_profiles(state, client);
            spawn_public_ip_lookup(ip_tx.clone());
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

    let Some(stdout) = child.stdout.take() else {
        return;
    };

    // Hand the child to the main thread so it can be killed on exit. This
    // thread only owns the pipe from here on.
    if let Ok(mut slot) = slot.lock() {
        *slot = Some(child);
    }

    let reader = BufReader::new(stdout);
    for line in reader.lines().map_while(Result::ok) {
        if crate::app::refresh_sync::should_refresh_from_nm_monitor_line(&line) {
            events.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn spawn_public_ip_lookup(tx: std::sync::mpsc::Sender<crate::nm::network_info::PublicIpInfo>) {
    thread::spawn(move || {
        if let Some(info) = crate::nm::network_info::fetch_public_ip_info() {
            let _ = tx.send(info);
        }
    });
}
