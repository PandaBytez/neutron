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

use neutron::config::{self, AppConfig};
use neutron::error::AppError;
use neutron::nm::ProfileState;
use neutron::testing::{self, MockNmClient, profile};
use neutron::tui::events::{execute_action, handle_key_event};
use neutron::tui::state::TuiState;

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
