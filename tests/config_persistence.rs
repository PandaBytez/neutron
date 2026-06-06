use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use wireguard_manager::config::{self, AppConfig};
use wireguard_manager::error::AppError;

#[test]
fn integration_load_returns_default_when_file_is_missing() {
    let config_path = unique_test_config_path();

    let loaded = config::load(&config_path).expect("missing config should return defaults");

    assert!(loaded.eligible_profile_ids.is_empty());
    assert_eq!(loaded.last_random_profile_id, None);
}

#[test]
fn integration_save_creates_parent_directories_and_roundtrips() {
    let config_path = unique_test_config_path();
    let expected = AppConfig {
        eligible_profile_ids: BTreeSet::from(["uuid-1".to_string(), "uuid-2".to_string()]),
        last_random_profile_id: Some("uuid-2".to_string()),
    };

    config::save(&config_path, &expected).expect("save should succeed");
    let loaded = config::load(&config_path).expect("load should succeed");

    assert_eq!(loaded.eligible_profile_ids, expected.eligible_profile_ids);
    assert_eq!(
        loaded.last_random_profile_id,
        expected.last_random_profile_id
    );
    cleanup_test_artifacts(&config_path);
}

#[test]
fn integration_load_returns_error_on_invalid_json() {
    let config_path = unique_test_config_path();
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).expect("test config directory should be created");
    }
    fs::write(&config_path, "not-json").expect("invalid content should be written");

    let result = config::load(&config_path);

    assert!(matches!(result, Err(AppError::Serde(_))));
    cleanup_test_artifacts(&config_path);
}

#[test]
fn integration_load_supports_legacy_name_based_fields() {
    let config_path = unique_test_config_path();
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).expect("test config directory should be created");
    }
    fs::write(
        &config_path,
        r#"{"eligible_profiles":["wg-us"],"last_random_profile":"wg-us"}"#,
    )
    .expect("legacy config should be written");

    let loaded = config::load(&config_path).expect("legacy config should deserialize");

    assert_eq!(
        loaded.eligible_profile_ids,
        BTreeSet::from(["wg-us".to_string()])
    );
    assert_eq!(loaded.last_random_profile_id.as_deref(), Some("wg-us"));
    cleanup_test_artifacts(&config_path);
}

fn unique_test_config_path() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir()
        .join(format!("wireguard-manager-config-tests-{suffix}"))
        .join("nested")
        .join("config.json")
}

fn cleanup_test_artifacts(path: &Path) {
    if let Some(parent) = path.parent().and_then(|nested| nested.parent()) {
        let _ = fs::remove_dir_all(parent);
    }
}
