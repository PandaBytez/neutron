//! End-to-end cover for the auto-connect pool: the `e` action excludes the
//! selected profile, and the login selector then refuses to pick it.

use neutron::config::{self, AppConfig};
use neutron::nm::{NmClient, ProfileState};
use neutron::service::{self, StartupRandomResult};
use neutron::testing::{self, MockNmClient, profile};
use neutron::tui::events::execute_action;
use neutron::tui::state::TuiState;

fn state_with(path: &std::path::Path, client: &MockNmClient) -> TuiState {
    let cfg = config::load(path).expect("config should load");
    let mut state = TuiState::new(path.to_path_buf(), cfg);
    neutron::tui::events::reload_profiles(&mut state, client).expect("profiles should load");
    state
}

#[test]
fn e_excludes_the_selected_profile_from_the_auto_connect_pool() {
    let client = MockNmClient::new(vec![
        profile("wg-eu", "uuid-eu", ProfileState::Inactive),
        profile("wg-us", "uuid-us", ProfileState::Inactive),
    ]);
    let path = testing::temp_config_path("pool-exclude");
    config::save(&path, &AppConfig::default()).expect("config should save");

    let mut state = state_with(&path, &client);
    // Rows are sorted by name, so index 0 is `wg-eu`.
    state.selected_index = 0;
    assert!(
        state
            .selected_row()
            .expect("a row should be selected")
            .eligible,
        "profiles start in the pool"
    );

    execute_action(&mut state, &client, "eligible").expect("excluding should succeed");

    let persisted = config::load(&path).expect("config should load");
    assert!(
        persisted.excluded_profile_ids.contains("uuid-eu"),
        "the marked profile must be recorded as excluded"
    );
    assert!(
        !persisted.excluded_profile_ids.contains("uuid-us"),
        "only the marked profile may be excluded"
    );
    assert!(
        !state.rows[0].eligible,
        "the list must show the profile as out of the pool"
    );

    // The selector must now never choose it, however many times it runs.
    for _ in 0..25 {
        let _ = client.disconnect_active();
        let result = service::run_startup_random_with_path(&client, &path)
            .expect("a profile should still be selectable");
        assert!(matches!(
            result,
            StartupRandomResult::Connected(ref name) if name == "wg-us"
        ));
    }

    testing::remove_temp_config(&path);
}

#[test]
fn e_puts_an_excluded_profile_back_into_the_pool() {
    let client = MockNmClient::new(vec![profile("wg-eu", "uuid-eu", ProfileState::Inactive)]);
    let path = testing::temp_config_path("pool-include");
    config::save(&path, &AppConfig::default()).expect("config should save");

    let mut state = state_with(&path, &client);
    execute_action(&mut state, &client, "eligible").expect("excluding should succeed");
    assert!(
        config::load(&path)
            .expect("config should load")
            .excluded_profile_ids
            .contains("uuid-eu")
    );

    execute_action(&mut state, &client, "eligible").expect("re-including should succeed");

    assert!(
        config::load(&path)
            .expect("config should load")
            .excluded_profile_ids
            .is_empty(),
        "toggling again must return the profile to the pool"
    );
    assert!(state.rows[0].eligible);

    testing::remove_temp_config(&path);
}

#[test]
fn excluding_every_profile_leaves_the_selector_with_nothing_to_pick() {
    let client = MockNmClient::new(vec![profile("wg-eu", "uuid-eu", ProfileState::Inactive)]);
    let path = testing::temp_config_path("pool-empty");
    config::save(&path, &AppConfig::default()).expect("config should save");

    let mut state = state_with(&path, &client);
    execute_action(&mut state, &client, "eligible").expect("excluding should succeed");

    // An empty pool is reported, not silently treated as "connect anything".
    assert!(service::run_startup_random_with_path(&client, &path).is_err());
    assert!(client.connected_profiles().is_empty());

    testing::remove_temp_config(&path);
}
