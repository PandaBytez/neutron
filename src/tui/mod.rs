//! Terminal User Interface (TUI) for Neutron.

pub mod events;
pub mod state;
pub mod theme;
pub mod ui;

use std::io::stdout;
use std::sync::Arc;
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
            let tunnel_addr = client_for_cache.tunnel_address(&uuid);
            let tunnel_dns = client_for_cache.tunnel_dns(&uuid);
            let gateway = tunnel_addr
                .as_deref()
                .and_then(crate::portforward::gateway_for_address)
                .map(|ip| ip.to_string());
            let diag = client_for_cache
                .get_profile_diagnostics(&uuid, is_active)
                .unwrap_or_default();
            let _ = cache_tx.send((
                uuid,
                crate::tui::state::CachedProfileInfo {
                    diagnostics: diag,
                    tunnel_address: tunnel_addr,
                    tunnel_dns,
                    gateway,
                },
            ));
        }
    });

    // Ensure background indicator daemon is running (spawn once if not already active)
    if !crate::service::indicator::is_indicator_running()
        && let Ok(exe) = std::env::current_exe()
    {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("indicator")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                unsafe extern "C" {
                    fn setsid() -> i32;
                }
                setsid();
                Ok(())
            });
        }
        let _ = cmd.spawn();
    }

    // NetworkManager monitor event counter
    let monitor_events = Arc::new(AtomicU64::new(0));
    let monitor_events_clone = monitor_events.clone();
    let _monitor_thread = thread::spawn(move || {
        start_nm_monitor_loop(monitor_events_clone);
    });

    let mut last_seen_event = 0_u64;

    // Main TUI Event Loop
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

        // Update real-time bandwidth throughput rates
        state.update_throughput();

        // Draw frame
        terminal.draw(|frame| {
            ui::render(frame, &state);
        })?;

        // Check if NetworkManager emitted connection change events
        let current_nm_event = monitor_events.load(Ordering::Relaxed);
        if current_nm_event != last_seen_event {
            last_seen_event = current_nm_event;
            let _ = events::reload_profiles(&mut state, &client);
            spawn_public_ip_lookup(ip_tx.clone());
        }

        // Poll for user keyboard input with 50ms timeout (smooth 20 FPS refresh)
        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
        {
            events::handle_key_event(&mut state, &client, key)?;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, Show)?;
    terminal.show_cursor()?;

    Ok(())
}

fn start_nm_monitor_loop(events: Arc<AtomicU64>) {
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
