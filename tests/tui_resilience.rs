//! The interface must survive a failing action.
//!
//! Regression: the event loop propagated every action error with `?`, so any
//! failure tore the whole TUI down and dropped the user back to a bare shell --
//! taking the message that explained the failure with it. A tunnel that
//! connects but carries no traffic made that path routine rather than rare.
//!
//! An action failing is ordinary: an unreachable server, a profile
//! NetworkManager rejects, a dismissed privilege prompt. It belongs in the
//! footer, not in an exit.

use neutron::config::{self, AppConfig, SplitTunnelConfig, SplitTunnelMode};
use neutron::error::AppError;
use neutron::nm::ProfileState;
use neutron::testing::{self, MockNmClient, profile};
use neutron::tui::events::{execute_action, handle_key_event};
use neutron::tui::state::{ActiveModal, SplitTunnelModalState, TuiState};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn state_for(client: &MockNmClient, label: &str) -> (TuiState, std::path::PathBuf) {
    let path = testing::temp_config_path(label);
    config::save(&path, &AppConfig::default()).expect("config should save");
    let mut state = TuiState::new(path.clone(), AppConfig::default());
    let _ = neutron::tui::events::reload_profiles(&mut state, client);
    (state, path)
}

/// Drive the key handler the way the event loop does, and report whether the
/// session would have survived.
fn press(state: &mut TuiState, client: &MockNmClient, code: KeyCode) -> Result<(), AppError> {
    handle_key_event(state, client, KeyEvent::new(code, KeyModifiers::NONE))
}

#[test]
fn an_unhealthy_tunnel_is_reported_in_the_footer_not_fatal() {
    let client = MockNmClient::new(vec![profile("wg-eu", "uuid-eu", ProfileState::Inactive)])
        .fail_unhealthy();
    let (mut state, path) = state_for(&client, "tui-unhealthy");

    // Space = connect the selected profile.
    let result = press(&mut state, &client, KeyCode::Char(' '));

    assert!(
        result.is_err(),
        "the failure must still reach the caller so the loop can display it"
    );

    // The loop's contract: turn that error into a status line and keep going.
    state.set_error(&result.unwrap_err());

    assert!(state.status_is_error, "it must be styled as a failure");
    assert!(
        state.status_message.contains("no traffic is passing"),
        "the diagnosis must survive: {}",
        state.status_message
    );
    assert!(
        !state.should_quit,
        "a failed connection must not end the session"
    );

    testing::remove_temp_config(&path);
}

#[test]
fn the_session_survives_repeated_failures() {
    // The user retries; each attempt must leave the interface usable.
    let client = MockNmClient::new(vec![
        profile("wg-eu", "uuid-eu", ProfileState::Inactive),
        profile("wg-us", "uuid-us", ProfileState::Inactive),
    ])
    .fail_unhealthy();
    let (mut state, path) = state_for(&client, "tui-retry");

    for _ in 0..5 {
        if let Err(error) = press(&mut state, &client, KeyCode::Char(' ')) {
            state.set_error(&error);
        }
        assert!(!state.should_quit, "the session must stay alive");
    }

    // Navigation still works afterwards, so the interface is genuinely usable.
    press(&mut state, &client, KeyCode::Down).expect("navigation should not fail");
    assert_eq!(state.selected_index, 1);

    testing::remove_temp_config(&path);
}

#[test]
fn a_successful_action_clears_a_previous_error() {
    let client = MockNmClient::new(vec![profile("wg-eu", "uuid-eu", ProfileState::Inactive)]);
    let (mut state, path) = state_for(&client, "tui-clear");

    state.set_error(&AppError::TunnelUnhealthy("stale failure".to_string()));
    assert!(state.status_is_error);

    // Any action that reports success must clear the error styling, or a stale
    // failure keeps being shown next to a working connection.
    execute_action(&mut state, &client, "switch").expect("switch should succeed");

    assert!(
        !state.status_is_error,
        "a success must not stay styled as a failure"
    );
    assert!(!state.status_message.contains("stale failure"));

    testing::remove_temp_config(&path);
}

#[test]
fn quit_still_works_after_a_failure() {
    // The escape hatch must survive too -- previously the crash *was* the exit,
    // so this was never exercised.
    let client = MockNmClient::new(vec![profile("wg-eu", "uuid-eu", ProfileState::Inactive)])
        .fail_unhealthy();
    let (mut state, path) = state_for(&client, "tui-quit");

    if let Err(error) = press(&mut state, &client, KeyCode::Char(' ')) {
        state.set_error(&error);
    }
    assert!(!state.should_quit);

    press(&mut state, &client, KeyCode::Char('q')).expect("quit should not fail");
    assert!(state.should_quit, "the user must still be able to leave");

    testing::remove_temp_config(&path);
}

#[test]
fn a_failed_connection_leaves_no_profile_marked_active() {
    // The rollback must be reflected in what the UI shows, or the list claims a
    // connection that was torn down.
    let client = MockNmClient::new(vec![profile("wg-eu", "uuid-eu", ProfileState::Inactive)])
        .fail_unhealthy();
    let (mut state, path) = state_for(&client, "tui-rollback");

    if let Err(error) = press(&mut state, &client, KeyCode::Char(' ')) {
        state.set_error(&error);
    }

    assert_eq!(client.active_uuid(), None, "the tunnel must be rolled back");
    let _ = neutron::tui::events::reload_profiles(&mut state, &client);
    assert!(
        !state.rows.iter().any(|row| row.is_active),
        "no profile may be shown as connected after a failed activation"
    );

    testing::remove_temp_config(&path);
}

#[test]
fn malformed_config_fails_cleanly_at_startup() {
    let sandbox = testing::scratch_dir("tui-malformed-config");
    let config_dir = sandbox.join("neutron");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.toml");
    std::fs::write(&config_path, "invalid toml content [[[").unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_neutron"))
        .arg("tui")
        .env("XDG_CONFIG_HOME", &sandbox)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "malformed config must fail startup"
    );
    assert!(
        !output
            .stdout
            .windows(8)
            .any(|bytes| bytes == b"\x1b[?1049h"),
        "startup must not enter the alternate screen"
    );
    let _ = std::fs::remove_dir_all(&sandbox);
}

#[test]
fn async_actions_do_not_block_event_loop_when_backend_blocks() {
    let client = MockNmClient::new(vec![profile("wg-eu", "uuid-eu", ProfileState::Inactive)]);
    let (mut state, path) = state_for(&client, "tui-async-no-block");

    let (action_tx, action_rx) = std::sync::mpsc::channel();
    state.action_tx = Some(action_tx);

    // Trigger kill-switch toggle - must not block on any backend call
    press(&mut state, &client, KeyCode::Char('k')).expect("action should succeed");
    assert!(
        state.status_message.contains("Kill Switch policy"),
        "status must report in-flight async action"
    );
    // Verify task arrived on channel
    let task = action_rx
        .try_recv()
        .expect("task must be dispatched to worker channel");
    match task {
        neutron::tui::state::AsyncAction::KillSwitch(enable) => assert!(enable),
        other => panic!("expected KillSwitch task, got {other:?}"),
    }

    // Trigger lockdown toggle
    press(&mut state, &client, KeyCode::Char('l')).expect("action should succeed");
    let task2 = action_rx
        .try_recv()
        .expect("task must be dispatched to worker channel");
    match task2 {
        neutron::tui::state::AsyncAction::Lockdown(enable) => assert!(enable),
        other => panic!("expected Lockdown task, got {other:?}"),
    }

    // Interface remains responsive to quit
    press(&mut state, &client, KeyCode::Char('q')).expect("quit should succeed");
    assert!(
        state.should_quit,
        "event loop processes quit without waiting for blocked worker"
    );

    testing::remove_temp_config(&path);
}

#[test]
fn transient_list_failure_retains_refresh_and_eventually_reloads() {
    let client = MockNmClient::new(vec![profile("wg-eu", "uuid-eu", ProfileState::Inactive)])
        .with_transient_list_failure(1);
    let path = testing::temp_config_path("tui-transient-list");
    config::save(&path, &AppConfig::default()).unwrap();
    let mut state = TuiState::new(path.clone(), AppConfig::default());

    // First reload fails transiently
    let first = neutron::tui::events::reload_profiles(&mut state, &client);
    assert!(first.is_err(), "first reload should fail transiently");
    state.set_error(&first.unwrap_err());
    assert!(state.status_is_error, "error surfaced on failure");

    // Without any new external event, retrying reload succeeds
    let second = neutron::tui::events::reload_profiles(&mut state, &client);
    assert!(
        second.is_ok(),
        "second reload should succeed after transient error clears"
    );
    assert_eq!(state.rows.len(), 1, "profile list recovered");

    testing::remove_temp_config(&path);
}

#[test]
fn manual_qbit_sync_queues_the_lease_snapshot_and_survives_a_stopped_worker() {
    use neutron::service::lease::LeaseState;
    use neutron::tui::state::{ActiveModal, AsyncAction, CommandPaletteState};

    let client = MockNmClient::default();
    let (mut state, path) = state_for(&client, "tui-qbit-async");
    state.config.port_forwarding.mode = config::PortForwardMode::ForwardAndSync;
    // An invalid IPv6 authority fails before network IO if a push is attempted.
    state.config.qbittorrent.url = "http://[invalid".into();
    state.config.qbittorrent.username = Some("snapshot-user".into());
    let expected_config = state.config.qbittorrent.clone();
    state.lease = Some(LeaseState {
        profile_uuid: Some("uuid-lease".into()),
        port: Some(51820),
        ..Default::default()
    });
    state.active_profile_uuid = Some("uuid-not-the-lease".into());
    let (tx, rx) = std::sync::mpsc::channel();
    state.action_tx = Some(tx);
    state.modal = ActiveModal::CommandPalette(CommandPaletteState {
        filter: "qBittorrent: Sync Forwarded Port Now".into(),
        ..Default::default()
    });

    press(&mut state, &client, KeyCode::Enter).expect("queueing must not call the WebUI");
    assert!(!state.status_is_error);
    assert!(state.status_message.contains("in background"));
    assert!(state.pending.is_some());
    state.lease = None;
    state.config.qbittorrent.username = None;
    match rx.try_recv().expect("manual sync must reach the worker") {
        AsyncAction::QbitSync { uuid, port, config } => {
            assert_eq!(uuid, "uuid-lease");
            assert_eq!(port, 51820);
            assert_eq!(config, expected_config);
        }
        other => panic!("expected QbitSync task, got {other:?}"),
    }
    press(&mut state, &client, KeyCode::Char('q')).unwrap();
    assert!(
        state.should_quit,
        "input must not wait for worker completion"
    );

    state.end_pending();
    drop(rx);
    state.lease = Some(LeaseState {
        profile_uuid: Some("uuid-lease".into()),
        port: Some(51820),
        ..Default::default()
    });
    execute_action(&mut state, &client, "qbit_sync").unwrap();
    assert!(state.status_is_error);
    assert!(state.status_message.contains("worker has stopped"));
    assert!(state.pending.is_none());

    testing::remove_temp_config(&path);
}

#[test]
fn spinner_actions_do_not_overwrite_or_queue_overlapping_requests() {
    use neutron::service::lease::LeaseState;
    use neutron::tui::state::AsyncAction;

    let client = MockNmClient::default();
    let (mut state, path) = state_for(&client, "tui-spinner-overlap");
    state.lease = Some(LeaseState {
        profile_uuid: Some("uuid-lease".into()),
        port: Some(51820),
        ..Default::default()
    });
    let (tx, rx) = std::sync::mpsc::channel();
    state.action_tx = Some(tx);

    for first in ["lockdown", "qbit_sync"] {
        execute_action(&mut state, &client, first).unwrap();
        match (first, rx.try_recv().unwrap()) {
            ("lockdown", AsyncAction::Lockdown(_))
            | ("qbit_sync", AsyncAction::QbitSync { .. }) => {}
            other => panic!("unexpected request: {other:?}"),
        }
        let pending = state.pending.as_ref().unwrap();
        let label = pending.label.clone();
        let started_at = pending.started_at;
        let status = state.status_message.clone();
        for overlapping in ["lockdown", "qbit_sync"] {
            execute_action(&mut state, &client, overlapping).unwrap();
            assert_eq!(state.pending.as_ref().unwrap().label, label);
            assert_eq!(state.pending.as_ref().unwrap().started_at, started_at);
            assert_eq!(state.status_message, status);
            assert!(matches!(
                rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
        }
        state.end_pending();
    }

    testing::remove_temp_config(&path);
}

#[test]
fn split_worker_failure_reconciles_modal_and_pending_state() {
    let client = MockNmClient::new(vec![profile("wg-eu", "uuid-eu", ProfileState::Inactive)]);
    let path = testing::temp_config_path("tui-split-reconcile");
    let initial_cfg = AppConfig::default();
    config::save(&path, &initial_cfg).unwrap();
    let mut state = TuiState::new(path.clone(), initial_cfg);

    let (st_tx, st_rx) = std::sync::mpsc::channel();
    state.split_tunnel_tx = Some(st_tx);

    // Open modal with default config
    state.modal = neutron::tui::state::ActiveModal::SplitTunnel(
        neutron::tui::state::SplitTunnelModalState::from_config(&state.config.global_split_tunnel),
    );

    // Apply a new config that will fail in the worker
    let mut rejected_cfg = state.config.global_split_tunnel.clone();
    rejected_cfg.mode = neutron::config::SplitTunnelMode::Include;
    rejected_cfg.cidrs.push("192.168.1.0/24".to_string());

    state.apply_split_tunnel(&client, rejected_cfg).unwrap();
    let (original, pending) = st_rx.recv().unwrap();
    assert_eq!(original, config::SplitTunnelConfig::default());
    assert_eq!(pending.cidrs, vec!["192.168.1.0/24".to_string()]);

    // Background reload happens while modal is open - must preserve modal edit state
    neutron::tui::events::reload_profiles(&mut state, &client).unwrap();
    assert_eq!(
        state.config.global_split_tunnel.cidrs,
        vec!["192.168.1.0/24".to_string()]
    );

    state.finish_split(pending, Err(AppError::CommandFailed("rejected".into())));
    assert!(state.pending_split.is_none());
    assert!(state.config.global_split_tunnel.cidrs.is_empty());
    if let neutron::tui::state::ActiveModal::SplitTunnel(modal) = &state.modal {
        assert!(modal.cidrs.is_empty());
    } else {
        panic!("modal should remain open");
    }

    testing::remove_temp_config(&path);
}

#[test]
fn stale_split_snapshot_reloads_without_overwriting_cli_exclusions() {
    for queued in [false, true] {
        let client = MockNmClient::default();
        let (mut state, path) = state_for(&client, "tui-split-conflict");
        execute_action(&mut state, &client, "split_tunnel").unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        if queued {
            state.split_tunnel_tx = Some(tx);
        }
        neutron::app::split_tunnel::set_global_mode(&client, &path, SplitTunnelMode::Exclude)
            .unwrap();
        let (persisted, _) =
            neutron::app::split_tunnel::add_global_cidr(&client, &path, "192.0.2.0/24").unwrap();
        assert_eq!(persisted.mode, SplitTunnelMode::Exclude);
        config::update(&path, |cfg| {
            cfg.excluded_profile_ids.insert("cli-excluded".into());
        })
        .unwrap();
        neutron::tui::events::reload_profiles(&mut state, &client).unwrap();
        assert_eq!(
            state.config.global_split_tunnel,
            SplitTunnelConfig::default()
        );
        let calls_before = client.split_tunnel_calls().len();

        // Apply through keyboard dispatch, using the modal's stale snapshot.
        if queued {
            press(&mut state, &client, KeyCode::Enter).unwrap();
            let (original, edited) = rx.try_recv().unwrap();
            assert_eq!(original, SplitTunnelConfig::default());
            let result = neutron::app::split_tunnel::apply_split_config_if_unchanged(
                &client, &path, &original, &edited,
            );
            assert!(result.is_err());
            state.finish_split(edited, result);
        } else {
            assert!(press(&mut state, &client, KeyCode::Enter).is_err());
        }
        assert!(state.status_is_error);
        assert!(state.status_message.contains("changed in another writer"));
        assert!(state.pending_split.is_none());
        assert_eq!(state.config.global_split_tunnel, persisted);
        assert_eq!(client.split_tunnel_calls().len(), calls_before);
        assert_eq!(config::load(&path).unwrap().global_split_tunnel, persisted);
        assert!(
            config::load(&path)
                .unwrap()
                .excluded_profile_ids
                .contains("cli-excluded")
        );
        assert_eq!(
            state.modal,
            ActiveModal::SplitTunnel(SplitTunnelModalState::from_config(&persisted),)
        );
        testing::remove_temp_config(&path);
    }
}

#[test]
fn rapid_split_edits_queue_each_predecessor_and_ignore_older_replies() {
    let client = MockNmClient::default();
    let (mut state, path) = state_for(&client, "tui-split-chain");
    let original = state.config.global_split_tunnel.clone();
    let first = SplitTunnelConfig {
        mode: SplitTunnelMode::Include,
        cidrs: vec!["192.0.2.0/24".into()],
        domains: Vec::new(),
    };
    let mut second = first.clone();
    second.cidrs.push("198.51.100.0/24".into());
    let (tx, rx) = std::sync::mpsc::channel();
    state.split_tunnel_tx = Some(tx);
    state.apply_split_tunnel(&client, first.clone()).unwrap();
    state.apply_split_tunnel(&client, second.clone()).unwrap();

    for (base, edited) in [(original, first.clone()), (first, second.clone())] {
        let (captured, requested) = rx.try_recv().unwrap();
        assert_eq!(captured, base);
        assert_eq!(requested, edited);
        let result = neutron::app::split_tunnel::apply_split_config_if_unchanged(
            &client, &path, &captured, &requested,
        );
        assert!(result.is_ok(), "{result:?}");
        let older_reply = requested != second;
        state.finish_split(requested, result);
        assert_eq!(state.config.global_split_tunnel, second);
        assert_eq!(state.pending_split.is_some(), older_reply);
    }
    assert!(state.pending_split.is_none());
    assert_eq!(config::load(&path).unwrap().global_split_tunnel, second);
    assert_eq!(client.split_tunnel_calls().len(), 2);
    testing::remove_temp_config(&path);
}

#[test]
fn stopped_split_worker_reloads_persisted_settings_and_modal() {
    let client = MockNmClient::default();
    let (mut state, path) = state_for(&client, "tui-split-stopped");
    let (tx, rx) = std::sync::mpsc::channel();
    state.split_tunnel_tx = Some(tx);
    let edited = SplitTunnelConfig {
        cidrs: vec!["192.0.2.0/24".into()],
        ..Default::default()
    };
    state.apply_split_tunnel(&client, edited.clone()).unwrap();
    assert!(state.pending_split.is_some());
    drop(rx);
    state.modal = ActiveModal::SplitTunnel(SplitTunnelModalState::from_config(&edited));
    assert!(state.apply_split_tunnel(&client, edited).is_err());
    assert!(state.status_is_error);
    assert!(state.pending_split.is_none());
    assert_eq!(
        state.config.global_split_tunnel,
        SplitTunnelConfig::default()
    );
    assert_eq!(
        state.modal,
        ActiveModal::SplitTunnel(SplitTunnelModalState::from_config(
            &SplitTunnelConfig::default()
        ),)
    );
    testing::remove_temp_config(&path);
}

#[test]
fn terminal_controls_are_escaped_without_changing_unicode_or_backend_values() {
    let hostile = "caf\u{e9}\x1b]52;c;payload\x07\r\n\u{202e}";
    let client = MockNmClient::new(vec![profile(hostile, "uuid-raw", ProfileState::Inactive)]);
    let (mut state, path) = state_for(&client, "tui-terminal-safe");
    let safe = neutron::process::terminal_safe(hostile);
    state.set_status(hostile);
    assert_eq!(state.status_message, safe);
    assert_eq!(state.active_toast().unwrap().message, safe);
    state.set_error(&AppError::Config(hostile.into()));
    assert!(state.status_message.contains(&safe));
    assert!(!state.status_message.chars().any(char::is_control));

    let (tx, rx) = std::sync::mpsc::channel();
    state.connect_tx = Some(tx);
    press(&mut state, &client, KeyCode::Char(' ')).unwrap();
    assert_eq!(
        rx.try_recv().unwrap(),
        ("uuid-raw".into(), hostile.into(), true)
    );
    assert_eq!(state.rows[0].name, hostile);
    assert_eq!(state.connecting.as_ref().unwrap().name, hostile);
    state.connecting = None;
    state.toast = None;
    let mut modal = SplitTunnelModalState::from_config(&SplitTunnelConfig::default());
    modal.domain_input = hostile.into();
    state.modal = ActiveModal::SplitTunnel(modal);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(180, 45)).unwrap();
    terminal
        .draw(|frame| neutron::tui::ui::render(frame, &state))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let screen: String = buffer.content.iter().map(|cell| cell.symbol()).collect();
    assert!(
        screen.contains("caf\u{e9}\\u{1b}]52;c;payload\\u{7}"),
        "{screen}"
    );
    assert!(!screen.chars().any(char::is_control));
    assert!(!screen.contains('\u{202e}'));
    if let ActiveModal::SplitTunnel(modal) = &state.modal {
        assert_eq!(modal.domain_input, hostile);
    } else {
        panic!("split modal must remain open");
    }
    testing::remove_temp_config(&path);
}
