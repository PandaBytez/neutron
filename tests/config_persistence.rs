use std::collections::BTreeSet;
use std::fs;

use neutron_vpn::config::{self, AppConfig};
use neutron_vpn::error::AppError;
use neutron_vpn::testing;

#[test]
fn integration_load_returns_default_when_file_is_missing() {
    let config_path = testing::temp_config_path("integration-missing");

    let loaded = config::load(&config_path).expect("missing config should return defaults");

    assert!(loaded.excluded_profile_ids.is_empty());
    assert_eq!(loaded.last_random_profile_id, None);
}

#[test]
fn integration_save_creates_parent_directories_and_roundtrips() {
    let config_path = testing::temp_config_path("integration-roundtrip");
    let expected = AppConfig {
        excluded_profile_ids: BTreeSet::from(["uuid-1".to_string(), "uuid-2".to_string()]),
        last_random_profile_id: Some("uuid-2".to_string()),
        ..AppConfig::default()
    };

    config::save(&config_path, &expected).expect("save should succeed");
    let loaded = config::load(&config_path).expect("load should succeed");

    assert_eq!(loaded.excluded_profile_ids, expected.excluded_profile_ids);
    assert_eq!(
        loaded.last_random_profile_id,
        expected.last_random_profile_id
    );
    testing::remove_temp_config(&config_path);
}

#[test]
fn integration_load_returns_error_on_invalid_json() {
    let config_path = testing::temp_config_path("integration-invalid-json");
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).expect("test config directory should be created");
    }
    fs::write(&config_path, "not-json").expect("invalid content should be written");

    let result = config::load(&config_path);

    assert!(matches!(result, Err(AppError::Serde(_))));
    testing::remove_temp_config(&config_path);
}

#[test]
fn integration_load_supports_legacy_last_random_profile_alias() {
    let config_path = testing::temp_config_path("integration-legacy-alias");
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).expect("test config directory should be created");
    }
    // The pre-rename `last_random_profile` field must still map onto
    // `last_random_profile_id`. The obsolete opt-in `eligible_profiles` field is
    // now ignored (opt-out model: every profile is eligible by default).
    fs::write(
        &config_path,
        r#"{"eligible_profiles":["wg-us"],"last_random_profile":"wg-us"}"#,
    )
    .expect("legacy config should be written");

    let loaded = config::load(&config_path).expect("legacy config should deserialize");

    assert!(loaded.excluded_profile_ids.is_empty());
    assert_eq!(loaded.last_random_profile_id.as_deref(), Some("wg-us"));
    testing::remove_temp_config(&config_path);
}
