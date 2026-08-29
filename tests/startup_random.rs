use std::collections::BTreeSet;
use std::path::Path;

use neutron::config::{self, AppConfig};
use neutron::error::AppError;
use neutron::nm::ProfileState;
use neutron::service;
use neutron::testing::{self, MockNmClient};

#[test]
fn integration_connects_and_updates_last_profile() {
    let client = MockNmClient::new(vec![testing::profile(
        "wg-us",
        "uuid-1",
        ProfileState::Inactive,
    )]);
    let config_path = testing::temp_config_path("integration-connect");
    write_config(&config_path, AppConfig::default());

    let selected = service::run_startup_random_with_path(&client, &config_path)
        .expect("startup random should connect");

    assert!(matches!(
        selected,
        service::StartupRandomResult::Connected(name) if name == "wg-us"
    ));
    assert_eq!(client.connected_profiles(), vec!["uuid-1".to_string()]);
    let persisted = config::load(&config_path).expect("config should be readable");
    assert_eq!(persisted.last_random_profile_id.as_deref(), Some("uuid-1"));
    testing::remove_temp_config(&config_path);
}

#[test]
fn integration_returns_error_when_nothing_is_eligible() {
    let client = MockNmClient::new(vec![testing::profile(
        "wg-us",
        "uuid-1",
        ProfileState::Inactive,
    )]);
    let config_path = testing::temp_config_path("integration-none-eligible");
    write_config(
        &config_path,
        AppConfig {
            // Opt-out: excluding the only profile leaves nothing eligible.
            excluded_profile_ids: BTreeSet::from(["uuid-1".to_string()]),
            ..AppConfig::default()
        },
    );

    let result = service::run_startup_random_with_path(&client, &config_path);

    assert!(matches!(result, Err(AppError::NoEligibleProfile)));
    assert!(client.connected_profiles().is_empty());
    testing::remove_temp_config(&config_path);
}

#[test]
fn integration_skips_when_profile_is_already_active() {
    let client = MockNmClient::new(vec![testing::profile(
        "wg-us",
        "uuid-1",
        ProfileState::Active,
    )]);
    let config_path = testing::temp_config_path("integration-already-active");

    let result = service::run_startup_random_with_path(&client, &config_path)
        .expect("startup random should skip and not fail");

    assert!(matches!(
        result,
        service::StartupRandomResult::SkippedAlreadyActive
    ));
    assert!(client.connected_profiles().is_empty());
    testing::remove_temp_config(&config_path);
}

#[test]
fn integration_retries_all_eligible_profiles_when_connections_fail() {
    let client = MockNmClient::with_failures(
        vec![
            testing::profile("wg-fail", "uuid-fail", ProfileState::Inactive),
            testing::profile("wg-fail-2", "uuid-fail-2", ProfileState::Inactive),
        ],
        &["uuid-fail", "uuid-fail-2"],
    );
    let config_path = testing::temp_config_path("integration-retries");
    write_config(&config_path, AppConfig::default());

    let result = service::run_startup_random_with_path(&client, &config_path);

    assert!(matches!(result, Err(AppError::NmCommandFailed(_))));
    assert!(client.connected_profiles().is_empty());
    assert_eq!(client.attempted_profiles().len(), 2);
    testing::remove_temp_config(&config_path);
}

fn write_config(path: &Path, app_cfg: AppConfig) {
    config::save(path, &app_cfg).expect("config should be written");
}
