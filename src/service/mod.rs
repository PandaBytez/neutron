use std::path::Path;

use rand::Rng;
use tracing::warn;

use crate::config;
use crate::error::{AppError, AppResult};
use crate::nm::NmClient;

pub enum StartupRandomResult {
    Connected(String),
    SkippedAlreadyActive,
}

pub fn run_startup_random<C: NmClient>(client: &C) -> AppResult<StartupRandomResult> {
    let path = config::default_config_path()?;
    run_startup_random_with_path(client, &path)
}

pub fn run_startup_random_with_path<C: NmClient>(
    client: &C,
    path: &Path,
) -> AppResult<StartupRandomResult> {
    run_startup_random_with_selector(client, path, |len| rand::rng().random_range(0..len))
}

fn run_startup_random_with_selector<C, F>(
    client: &C,
    path: &Path,
    mut select_index: F,
) -> AppResult<StartupRandomResult>
where
    C: NmClient,
    F: FnMut(usize) -> usize,
{
    let mut app_cfg = config::load(path)?;

    let profiles = client.list_wireguard_profiles()?;
    if profiles.iter().any(|profile| profile.is_active()) {
        return Ok(StartupRandomResult::SkippedAlreadyActive);
    }

    let mut eligible: Vec<_> = profiles
        .iter()
        .filter(|profile| {
            app_cfg
                .eligible_profile_ids
                .iter()
                .any(|id| id == &profile.uuid)
        })
        .collect();

    if eligible.is_empty() {
        return Err(AppError::NoEligibleProfile);
    }

    if eligible.len() > 1 {
        eligible.retain(|profile| app_cfg.last_random_profile_id.as_ref() != Some(&profile.uuid));
    }

    let mut last_connect_error = None;
    while !eligible.is_empty() {
        let selected = eligible.remove(select_index(eligible.len()));

        match client.connect(&selected.uuid) {
            Ok(()) => {
                app_cfg.last_random_profile_id = Some(selected.uuid.clone());
                if let Err(error) = config::save(path, &app_cfg) {
                    warn!(
                        "startup random connected profile '{}' but failed to persist state: {error}",
                        selected.uuid
                    );
                }

                return Ok(StartupRandomResult::Connected(selected.name.clone()));
            }
            Err(error) => {
                warn!(
                    "startup random failed to connect profile '{}' ({}): {error}",
                    selected.name, selected.uuid
                );
                last_connect_error = Some(error);
            }
        }
    }

    Err(last_connect_error.unwrap_or(AppError::NoEligibleProfile))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::collections::HashSet;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::config::AppConfig;
    use crate::nm::{NmClient, ProfileState, WireguardProfile};

    use super::*;

    struct MockNmClient {
        profiles: Vec<WireguardProfile>,
        attempted: RefCell<Vec<String>>,
        connected: RefCell<Vec<String>>,
        fail_ids: HashSet<String>,
    }

    impl MockNmClient {
        fn new(profiles: Vec<WireguardProfile>) -> Self {
            Self {
                profiles,
                attempted: RefCell::new(Vec::new()),
                connected: RefCell::new(Vec::new()),
                fail_ids: HashSet::new(),
            }
        }

        fn with_failures(profiles: Vec<WireguardProfile>, fail_ids: &[&str]) -> Self {
            Self {
                profiles,
                attempted: RefCell::new(Vec::new()),
                connected: RefCell::new(Vec::new()),
                fail_ids: fail_ids.iter().map(|id| (*id).to_string()).collect(),
            }
        }

        fn connected_profiles(&self) -> Vec<String> {
            self.connected.borrow().clone()
        }

        fn attempted_profiles(&self) -> Vec<String> {
            self.attempted.borrow().clone()
        }
    }

    impl NmClient for MockNmClient {
        fn list_wireguard_profiles(&self) -> AppResult<Vec<WireguardProfile>> {
            Ok(self.profiles.clone())
        }

        fn connect(&self, profile_identifier: &str) -> AppResult<()> {
            self.attempted
                .borrow_mut()
                .push(profile_identifier.to_string());
            if self.fail_ids.contains(profile_identifier) {
                return Err(AppError::NmCommandFailed(format!(
                    "simulated failure for {profile_identifier}"
                )));
            }
            self.connected
                .borrow_mut()
                .push(profile_identifier.to_string());
            Ok(())
        }

        fn disconnect_active(&self) -> AppResult<()> {
            Ok(())
        }

        fn switch_to(&self, _profile_identifier: &str) -> AppResult<()> {
            Ok(())
        }
    }

    #[test]
    fn returns_error_when_profile_already_active() {
        let client = MockNmClient::new(vec![profile("wg-us", "uuid-1", ProfileState::Active)]);
        let config_path = unique_test_config_path();

        let result = run_startup_random_with_path(&client, &config_path);

        assert!(matches!(
            result,
            Ok(StartupRandomResult::SkippedAlreadyActive)
        ));
        assert!(client.connected_profiles().is_empty());
    }

    #[test]
    fn returns_error_when_no_eligible_profile_exists() {
        let client = MockNmClient::new(vec![profile("wg-us", "uuid-1", ProfileState::Inactive)]);
        let config_path = unique_test_config_path();
        write_config(
            &config_path,
            AppConfig {
                eligible_profile_ids: BTreeSet::from(["uuid-eu".to_string()]),
                last_random_profile_id: None,
            },
        );

        let result = run_startup_random_with_path(&client, &config_path);

        assert!(matches!(result, Err(AppError::NoEligibleProfile)));
        assert!(client.connected_profiles().is_empty());
        cleanup_test_artifacts(&config_path);
    }

    #[test]
    fn connects_and_persists_selected_profile() {
        let client = MockNmClient::new(vec![profile("wg-us", "uuid-1", ProfileState::Inactive)]);
        let config_path = unique_test_config_path();
        write_config(
            &config_path,
            AppConfig {
                eligible_profile_ids: BTreeSet::from(["uuid-1".to_string()]),
                last_random_profile_id: None,
            },
        );

        let selected = run_startup_random_with_path(&client, &config_path)
            .expect("startup random should select profile");

        assert!(matches!(
            selected,
            StartupRandomResult::Connected(name) if name == "wg-us"
        ));
        assert_eq!(client.connected_profiles(), vec!["uuid-1".to_string()]);
        let persisted = config::load(&config_path).expect("config should be readable");
        assert_eq!(persisted.last_random_profile_id.as_deref(), Some("uuid-1"));
        cleanup_test_artifacts(&config_path);
    }

    #[test]
    fn avoids_immediate_repeat_when_another_profile_exists() {
        let client = MockNmClient::new(vec![
            profile("wg-us", "uuid-1", ProfileState::Inactive),
            profile("wg-eu", "uuid-2", ProfileState::Inactive),
        ]);
        let config_path = unique_test_config_path();
        write_config(
            &config_path,
            AppConfig {
                eligible_profile_ids: BTreeSet::from(["uuid-1".to_string(), "uuid-2".to_string()]),
                last_random_profile_id: Some("uuid-1".to_string()),
            },
        );

        let selected = run_startup_random_with_path(&client, &config_path)
            .expect("startup random should select non-repeated profile");

        assert!(matches!(
            selected,
            StartupRandomResult::Connected(name) if name == "wg-eu"
        ));
        assert_eq!(client.connected_profiles(), vec!["uuid-2".to_string()]);
        let persisted = config::load(&config_path).expect("config should be readable");
        assert_eq!(persisted.last_random_profile_id.as_deref(), Some("uuid-2"));
        cleanup_test_artifacts(&config_path);
    }

    #[test]
    fn still_returns_connected_when_config_save_fails() {
        let client = MockNmClient::new(vec![profile("wg-us", "uuid-1", ProfileState::Inactive)]);
        let base = std::env::temp_dir().join(format!(
            "wireguard-manager-readonly-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should move forward")
                .as_nanos()
        ));
        fs::create_dir_all(&base).expect("base dir should exist");
        let config_path = base.join("config.json");
        write_config(
            &config_path,
            AppConfig {
                eligible_profile_ids: BTreeSet::from(["uuid-1".to_string()]),
                last_random_profile_id: None,
            },
        );

        let mut perms = fs::metadata(&config_path)
            .expect("config file should exist")
            .permissions();
        perms.set_readonly(true);
        fs::set_permissions(&config_path, perms).expect("should set readonly perms");

        let selected = run_startup_random_with_path(&client, &config_path)
            .expect("connect should succeed even if save fails");

        assert!(matches!(
            selected,
            StartupRandomResult::Connected(name) if name == "wg-us"
        ));
        assert_eq!(client.connected_profiles(), vec!["uuid-1".to_string()]);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
                .expect("should restore file perms for cleanup");
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn retries_other_profile_when_first_connection_fails() {
        let client = MockNmClient::with_failures(
            vec![
                profile("wg-fail", "uuid-fail", ProfileState::Inactive),
                profile("wg-ok", "uuid-ok", ProfileState::Inactive),
            ],
            &["uuid-fail"],
        );
        let config_path = unique_test_config_path();
        write_config(
            &config_path,
            AppConfig {
                eligible_profile_ids: BTreeSet::from([
                    "uuid-fail".to_string(),
                    "uuid-ok".to_string(),
                ]),
                last_random_profile_id: None,
            },
        );

        let selected = run_startup_random_with_selector(&client, &config_path, |_| 0)
            .expect("fallback should connect another profile");

        assert!(matches!(
            selected,
            StartupRandomResult::Connected(name) if name == "wg-ok"
        ));
        assert_eq!(client.connected_profiles(), vec!["uuid-ok".to_string()]);
        assert!(
            client
                .attempted_profiles()
                .iter()
                .any(|attempt| attempt == "uuid-fail")
        );
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
            .join(format!("wireguard-manager-tests-{suffix}"))
            .join("config.json")
    }

    fn cleanup_test_artifacts(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }
}
