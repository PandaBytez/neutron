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
    C: NmClient + FirewallClient + Clone + Send + 'static,
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

    // Initial drop directory sync & profile loading
    if state.config.general.auto_sync_profiles {
        let _ = crate::app::sync::sync_profiles_dir(&client, &state.config);
    }
    let _ = events::reload_profiles(&mut state, &client);

    // NetworkManager monitor event counter
    let monitor_events = Arc::new(AtomicU64::new(0));
    let monitor_events_clone = monitor_events.clone();
    let _monitor_thread = thread::spawn(move || {
        start_nm_monitor_loop(monitor_events_clone);
    });

    let mut last_seen_event = 0_u64;

    // Main TUI Event Loop
    while !state.should_quit {
        // Draw frame
        terminal.draw(|frame| {
            ui::render(frame, &state);
        })?;

        // Check if NetworkManager emitted connection change events
        let current_nm_event = monitor_events.load(Ordering::Relaxed);
        if current_nm_event != last_seen_event {
            last_seen_event = current_nm_event;
            let _ = events::reload_profiles(&mut state, &client);
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
