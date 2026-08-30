//! Every action the command palette offers must be one the dispatcher actually
//! implements.
//!
//! This is the invariant the key map, the palette and `execute_action` are three
//! views of; before they were unified the palette listed 2 of 13 actions and the
//! rest had been copy-pasted into the key handler.
//!
//! Lives in its own integration test binary because it redirects
//! `XDG_CONFIG_HOME`: the `autoconnect` action writes a desktop autostart entry,
//! which must never land in the developer's real home directory.

use neutron::config::{self, AppConfig};
use neutron::nm::ProfileState;
use neutron::testing::{self, MockNmClient, profile};
use neutron::tui::events::execute_action;
use neutron::tui::state::{ActiveModal, CommandPaletteState, TuiState};

#[test]
fn every_palette_action_is_implemented_by_the_dispatcher() {
    let sandbox = std::env::temp_dir().join(format!(
        "neutron-actions-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos()
    ));
    std::fs::create_dir_all(&sandbox).expect("sandbox should be created");

    // SAFETY: this file holds a single test, so it is the only thread reading
    // the environment. `autostart::dir()` and `default_config_path()` both
    // resolve through here, so nothing escapes the sandbox.
    unsafe { std::env::set_var("XDG_CONFIG_HOME", &sandbox) };

    let client = MockNmClient::new(vec![
        profile("wg-eu", "uuid-eu", ProfileState::Active),
        profile("wg-us", "uuid-us", ProfileState::Inactive),
    ]);
    let config_path = testing::temp_config_path("actions");
    config::save(&config_path, &AppConfig::default()).expect("config should save");

    let mut state = TuiState::new(config_path.clone(), AppConfig::default());
    neutron::tui::events::reload_profiles(&mut state, &client).expect("profiles should load");

    for item in CommandPaletteState::all_items() {
        // Actions are independent, so reset what a previous one may have left
        // behind rather than rebuilding the (network-touching) state each time.
        state.modal = ActiveModal::None;
        state.should_quit = false;

        execute_action(&mut state, &client, item.id).unwrap_or_else(|error| {
            panic!(
                "palette action '{}' ({}) is not implemented by execute_action: {error}",
                item.id, item.title
            )
        });
    }

    unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    testing::remove_temp_config(&config_path);
    let _ = std::fs::remove_dir_all(&sandbox);
}
