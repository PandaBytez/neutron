use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use wireguard_manager::config::{self, AppConfig};
use wireguard_manager::error::AppError;
use wireguard_manager::nm::{ProfileState, WireguardProfile};
use wireguard_manager::service;
use wireguard_manager::testing::MockNmClient;

#[test]
fn integration_connects_and_updates_last_profile() {
    let client = MockNmClient::new(vec![profile("wg-us", "uuid-1", ProfileState::Inactive)]);
    let config_path = unique_test_config_path();
    write_config(
        &config_path,
        AppConfig {
            eligible_profile_ids: BTreeSet::from(["uuid-1".to_string()]),
            last_random_profile_id: None,
        },
    );

    let selected = service::run_startup_random_with_path(&client, &config_path)
        .expect("startup random should connect");

    assert!(matches!(
        selected,
        service::StartupRandomResult::Connected(name) if name == "wg-us"
    ));
    assert_eq!(client.connected_profiles(), vec!["uuid-1".to_string()]);
    let persisted = config::load(&config_path).expect("config should be readable");
    assert_eq!(persisted.last_random_profile_id.as_deref(), Some("uuid-1"));
    cleanup_test_artifacts(&config_path);
}

#[test]
fn integration_returns_error_when_nothing_is_eligible() {
    let client = MockNmClient::new(vec![profile("wg-us", "uuid-1", ProfileState::Inactive)]);
    let config_path = unique_test_config_path();
    write_config(
        &config_path,
        AppConfig {
            eligible_profile_ids: BTreeSet::from(["uuid-eu".to_string()]),
            last_random_profile_id: None,
        },
    );

    let result = service::run_startup_random_with_path(&client, &config_path);

    assert!(matches!(result, Err(AppError::NoEligibleProfile)));
    assert!(client.connected_profiles().is_empty());
    cleanup_test_artifacts(&config_path);
}

#[test]
fn integration_skips_when_profile_is_already_active() {
    let client = MockNmClient::new(vec![profile("wg-us", "uuid-1", ProfileState::Active)]);
    let config_path = unique_test_config_path();

    let result = service::run_startup_random_with_path(&client, &config_path)
        .expect("startup random should skip and not fail");

    assert!(matches!(
        result,
        service::StartupRandomResult::SkippedAlreadyActive
    ));
    assert!(client.connected_profiles().is_empty());
}

#[test]
fn integration_retries_all_eligible_profiles_when_connections_fail() {
    let client = MockNmClient::with_failures(
        vec![
            profile("wg-fail", "uuid-fail", ProfileState::Inactive),
            profile("wg-fail-2", "uuid-fail-2", ProfileState::Inactive),
        ],
        &["uuid-fail", "uuid-fail-2"],
    );
    let config_path = unique_test_config_path();
    write_config(
        &config_path,
        AppConfig {
            eligible_profile_ids: BTreeSet::from([
                "uuid-fail".to_string(),
                "uuid-fail-2".to_string(),
            ]),
            last_random_profile_id: None,
        },
    );

    let result = service::run_startup_random_with_path(&client, &config_path);

    assert!(matches!(result, Err(AppError::NmCommandFailed(_))));
    assert!(client.connected_profiles().is_empty());
    assert_eq!(client.attempted_profiles().len(), 2);
    cleanup_test_artifacts(&config_path);
}

fn profile(name: &str, uuid: &str, state: ProfileState) -> WireguardProfile {
    WireguardProfile {
        name: name.to_string(),
        uuid: uuid.to_string(),
        state,
    }
}

fn write_config(path: &Path, app_cfg: AppConfig) {
    config::save(path, &app_cfg).expect("config should be written");
}

fn unique_test_config_path() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir()
        .join(format!("wireguard-manager-integration-tests-{suffix}"))
        .join("config.json")
}

fn cleanup_test_artifacts(path: &Path) {
    if let Some(parent) = path.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}
