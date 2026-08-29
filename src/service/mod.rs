use std::path::Path;

use rand::Rng;
use tracing::warn;

use crate::config;
use crate::error::{AppError, AppResult};
use crate::nm::{NmClient, WireguardProfile};

pub mod autostart;
pub mod indicator;

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

/// Stop NetworkManager from activating any WireGuard profile on its own.
///
/// The app is the single authority on which tunnel is up. NetworkManager
/// defaults `connection.autoconnect` to `yes`, and because each WireGuard
/// profile is its own interface they never compete for a device -- left alone,
/// NM activates *every* profile at boot.
///
/// Selecting a profile by arming one with `autoconnect` was tried and removed:
/// it made NM a second activation authority that could not see what the app had
/// already connected, so an armed profile would come up *alongside* the active
/// one. Activation is now always an explicit `connection up` issued here.
///
/// Best-effort: failures are logged, since callers must still work on a system
/// where the flag could not be cleared.
fn normalize_autoconnect<C: NmClient>(client: &C) {
    if let Err(error) = client.set_autoconnect_all(false) {
        warn!("failed to disable NetworkManager autoconnect: {error}");
    }
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

    // Re-applied on every run so profiles imported out-of-band (via GNOME or
    // `nmcli`, which default autoconnect to on) cannot bring themselves up.
    normalize_autoconnect(client);

    let active_profiles: Vec<_> = profiles.iter().filter(|p| p.is_active()).collect();

    // If exactly one profile is active and it is eligible, leave it untouched:
    // a tunnel that is already up is a deliberate connection, and replacing it
    // would drop traffic to prove a point.
    if active_profiles.len() == 1
        && !app_cfg
            .excluded_profile_ids
            .contains(&active_profiles[0].uuid)
    {
        return Ok(StartupRandomResult::SkippedAlreadyActive);
    }

    // If multiple profiles are active, or the only active profile was excluded,
    // tear down active profiles so we can cleanly select and connect an eligible profile.
    if !active_profiles.is_empty() {
        for _ in 0..active_profiles.len() {
            match client.disconnect_active() {
                Ok(()) => {}
                Err(AppError::NoActiveProfile) => break,
                Err(error) => return Err(error),
            }
        }
    }

    let candidates = ordered_candidates(&profiles, &app_cfg, &mut select_index)?;

    let mut last_connect_error = None;
    for selected in candidates {
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

/// Eligible profiles in the order they should be tried: the ones not used last
/// time first, in random order, then the last-used profile as a fallback.
///
/// Preferring anything over `last_random_profile_id` is what makes the choice
/// *rotate* between runs instead of landing on the same profile repeatedly.
///
/// Returns [`AppError::NoEligibleProfile`] when every profile is excluded.
fn ordered_candidates<'a, F>(
    profiles: &'a [WireguardProfile],
    app_cfg: &config::AppConfig,
    mut select_index: F,
) -> AppResult<Vec<&'a WireguardProfile>>
where
    F: FnMut(usize) -> usize,
{
    let eligible: Vec<_> = profiles
        .iter()
        .filter(|profile| !app_cfg.excluded_profile_ids.contains(&profile.uuid))
        .collect();

    if eligible.is_empty() {
        return Err(AppError::NoEligibleProfile);
    }

    let (mut primary, fallback): (Vec<_>, Vec<_>) = eligible
        .into_iter()
        .partition(|p| app_cfg.last_random_profile_id.as_ref() != Some(&p.uuid));

    let mut candidates = Vec::with_capacity(primary.len() + fallback.len());
    while !primary.is_empty() {
        candidates.push(primary.remove(select_index(primary.len())));
    }
    candidates.extend(fallback);
    Ok(candidates)
}

/// Turn "connect a random profile at login" on or off, and persist the choice.
///
/// Enabling installs the autostart entry that relaunches the app hidden at
/// login; that launch is what performs the connection. Disabling removes it.
/// Neither direction disturbs a tunnel that is already up -- an active profile
/// is a deliberate connection, and toggling a preference is not a request to
/// drop traffic.
pub fn set_autoconnect_at_login<C: NmClient>(
    client: &C,
    path: &Path,
    enable: bool,
) -> AppResult<()> {
    set_autoconnect_at_login_in(client, path, &autostart::dir()?, enable)
}

fn set_autoconnect_at_login_in<C: NmClient>(
    client: &C,
    path: &Path,
    autostart_dir: &Path,
    enable: bool,
) -> AppResult<()> {
    // NetworkManager must never activate a profile by itself in either state:
    // the app is the only thing allowed to decide which tunnel is up.
    client.set_autoconnect_all(false)?;

    if enable {
        autostart::install_in(autostart_dir)?;
    } else {
        autostart::uninstall_in(autostart_dir)?;
    }

    // Persist last: the caller reverts its switch when this errors, so saving
    // before the work could leave the stored state disagreeing with the UI.
    let mut app_cfg = config::load(path)?;
    app_cfg.autoconnect_at_boot = enable;
    config::save(path, &app_cfg)
}

/// Connect one random eligible profile, if the feature is enabled.
///
/// This is the whole auto-connect mechanism: the autostart entry relaunches the
/// app at login and this runs immediately, issuing a direct `connection up`.
/// NetworkManager is never asked to choose -- it only ever activates what it is
/// explicitly told to, which is what keeps the app the single authority over
/// which tunnel is up.
///
/// Does nothing but disable NetworkManager autoconnect when the feature is off,
/// and leaves an already-connected profile alone.
///
/// Returns the name of the profile connected, or `None` when nothing was.
pub fn startup_connect<C: NmClient>(client: &C, path: &Path) -> AppResult<Option<String>> {
    let app_cfg = config::load(path)?;

    if !app_cfg.autoconnect_at_boot {
        normalize_autoconnect(client);
        return Ok(None);
    }

    match run_startup_random_with_path(client, path)? {
        StartupRandomResult::Connected(name) => Ok(Some(name)),
        StartupRandomResult::SkippedAlreadyActive => Ok(None),
    }
}

/// Keep NetworkManager passive without touching connections.
///
/// Used on ordinary app starts and after the profile set changes, so a profile
/// that arrived carrying NetworkManager's `autoconnect=yes` default (a fresh
/// import, or one added through GNOME Settings) cannot bring itself up.
pub fn disable_nm_autoconnect<C: NmClient>(client: &C) {
    normalize_autoconnect(client);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::config::AppConfig;
    use crate::nm::{ProfileState, WireguardProfile};
    use crate::testing::MockNmClient;

    use super::*;

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
                // Opt-out: excluding the only profile leaves nothing eligible.
                excluded_profile_ids: BTreeSet::from(["uuid-1".to_string()]),
                ..AppConfig::default()
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
        write_config(&config_path, AppConfig::default());

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
                last_random_profile_id: Some("uuid-1".to_string()),
                ..AppConfig::default()
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
            "neutron-vpn-readonly-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should move forward")
                .as_nanos()
        ));
        fs::create_dir_all(&base).expect("base dir should exist");
        let config_path = base.join("config.json");
        write_config(&config_path, AppConfig::default());

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
        write_config(&config_path, AppConfig::default());

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

    #[test]
    fn disables_autoconnect_on_every_run() {
        let client = MockNmClient::new(vec![profile("wg-us", "uuid-1", ProfileState::Inactive)]);
        let config_path = unique_test_config_path();
        write_config(&config_path, AppConfig::default());

        run_startup_random_with_path(&client, &config_path)
            .expect("startup random should select profile");

        // NetworkManager is left unable to activate anything by itself; the
        // app issued the one activation explicitly.
        assert_eq!(
            client.autoconnect_calls(),
            vec!["autoconnect-all:off".to_string()]
        );
        assert_eq!(client.connected_profiles(), vec!["uuid-1".to_string()]);
        cleanup_test_artifacts(&config_path);
    }

    #[test]
    fn still_connects_when_arming_fails() {
        // Arming sets up the *next* boot; it is incidental to connecting now,
        // so a rejection from NetworkManager must not fail the connection.
        let client = MockNmClient::new(vec![profile("wg-us", "uuid-1", ProfileState::Inactive)])
            .fail_autoconnect();
        let config_path = unique_test_config_path();
        write_config(&config_path, AppConfig::default());

        let selected = run_startup_random_with_path(&client, &config_path)
            .expect("a failed arming must not abort selection");

        assert!(matches!(selected, StartupRandomResult::Connected(_)));
        assert_eq!(client.connected_profiles(), vec!["uuid-1".to_string()]);
        cleanup_test_artifacts(&config_path);
    }

    #[test]
    fn tears_down_all_active_profiles_before_selecting_one() {
        // Reproduces the autoconnect bug: NetworkManager brought several
        // profiles up at boot. The selector must clear them and restore a single
        // random profile rather than skipping.
        let client = MockNmClient::new(vec![
            profile("wg-us", "uuid-1", ProfileState::Active),
            profile("wg-eu", "uuid-2", ProfileState::Active),
            profile("wg-as", "uuid-3", ProfileState::Inactive),
        ]);
        let config_path = unique_test_config_path();
        write_config(&config_path, AppConfig::default());

        let selected = run_startup_random_with_selector(&client, &config_path, |_| 0)
            .expect("over-connected boot should be reduced to one profile");

        assert!(matches!(selected, StartupRandomResult::Connected(_)));
        // Both active profiles are torn down (one `disconnect` per active
        // profile) before exactly one profile is connected.
        let disconnects = client
            .calls()
            .iter()
            .filter(|call| call.as_str() == "disconnect")
            .count();
        assert_eq!(disconnects, 2);
        assert_eq!(client.connected_profiles().len(), 1);
        cleanup_test_artifacts(&config_path);
    }

    #[test]
    fn falls_back_to_last_random_profile_when_primary_candidates_fail() {
        let client = MockNmClient::with_failures(
            vec![
                profile("wg-fail", "uuid-fail", ProfileState::Inactive),
                profile("wg-last", "uuid-last", ProfileState::Inactive),
            ],
            &["uuid-fail"],
        );
        let config_path = unique_test_config_path();
        write_config(
            &config_path,
            AppConfig {
                last_random_profile_id: Some("uuid-last".to_string()),
                ..AppConfig::default()
            },
        );

        let selected = run_startup_random_with_selector(&client, &config_path, |_| 0)
            .expect("fallback should connect last profile when primary fails");

        assert!(matches!(
            selected,
            StartupRandomResult::Connected(name) if name == "wg-last"
        ));
        assert_eq!(client.connected_profiles(), vec!["uuid-last".to_string()]);
        assert_eq!(
            client.attempted_profiles(),
            vec!["uuid-fail".to_string(), "uuid-last".to_string()]
        );
        cleanup_test_artifacts(&config_path);
    }

    #[test]
    fn disconnects_single_active_profile_if_it_was_excluded() {
        let client = MockNmClient::new(vec![
            profile("wg-excluded", "uuid-excluded", ProfileState::Active),
            profile("wg-eligible", "uuid-eligible", ProfileState::Inactive),
        ]);
        let config_path = unique_test_config_path();
        write_config(
            &config_path,
            AppConfig {
                excluded_profile_ids: BTreeSet::from(["uuid-excluded".to_string()]),
                ..AppConfig::default()
            },
        );

        let selected = run_startup_random_with_selector(&client, &config_path, |_| 0)
            .expect("excluded active profile should be torn down and replaced");

        assert!(matches!(
            selected,
            StartupRandomResult::Connected(name) if name == "wg-eligible"
        ));
        assert!(client.calls().iter().any(|call| call == "disconnect"));
        assert_eq!(
            client.connected_profiles(),
            vec!["uuid-eligible".to_string()]
        );
        cleanup_test_artifacts(&config_path);
    }

    #[test]
    fn skips_the_active_profile_when_one_is_connected() {
        // A single active profile is a deliberate connection: leave it up.
        // Autoconnect is still cleared, which is the repair path for a profile
        // set that carries NetworkManager's `autoconnect=yes` default.
        let client = MockNmClient::new(vec![
            profile("wg-us", "uuid-1", ProfileState::Active),
            profile("wg-eu", "uuid-2", ProfileState::Inactive),
        ]);
        let config_path = unique_test_config_path();

        let result = run_startup_random_with_path(&client, &config_path);

        assert!(matches!(
            result,
            Ok(StartupRandomResult::SkippedAlreadyActive)
        ));
        assert_eq!(
            client.autoconnect_calls(),
            vec!["autoconnect-all:off".to_string()]
        );
        // The single active profile is untouched: nothing is torn down or
        // connected.
        assert!(!client.calls().iter().any(|call| call == "disconnect"));
        assert!(client.connected_profiles().is_empty());
    }

    #[test]
    fn connect_at_boot_defaults_to_on_for_a_fresh_install() {
        // No config file at all: the app's headline feature must be active out
        // of the box rather than silently disabled by a derived `false`.
        let config_path = unique_test_config_path();

        let app_cfg = config::load(&config_path).expect("a missing config should load defaults");

        assert!(app_cfg.autoconnect_at_boot);
    }

    #[test]
    fn startup_connect_connects_one_profile_when_enabled() {
        // The whole auto-connect mechanism: a direct `connection up`, chosen by
        // the app. NetworkManager is only told to stop activating things itself.
        let client = MockNmClient::new(vec![
            profile("wg-us", "uuid-1", ProfileState::Inactive),
            profile("wg-eu", "uuid-2", ProfileState::Inactive),
        ]);
        let config_path = unique_test_config_path();
        write_config(&config_path, AppConfig::default());

        let connected = startup_connect(&client, &config_path).expect("startup connect should run");

        assert!(connected.is_some());
        assert_eq!(
            client.connected_profiles().len(),
            1,
            "exactly one profile may be brought up"
        );
        assert_eq!(
            client.autoconnect_calls(),
            vec!["autoconnect-all:off".to_string()],
            "NetworkManager must never activate a profile by itself"
        );
        cleanup_test_artifacts(&config_path);
    }

    #[test]
    fn startup_connect_does_nothing_but_disable_autoconnect_when_off() {
        let client = MockNmClient::new(vec![profile("wg-us", "uuid-1", ProfileState::Inactive)]);
        let config_path = unique_test_config_path();
        write_config(
            &config_path,
            AppConfig {
                autoconnect_at_boot: false,
                ..AppConfig::default()
            },
        );

        let connected = startup_connect(&client, &config_path).expect("startup connect should run");

        assert!(connected.is_none());
        assert!(
            client.connected_profiles().is_empty(),
            "nothing may be connected while the feature is off"
        );
        assert_eq!(
            client.autoconnect_calls(),
            vec!["autoconnect-all:off".to_string()]
        );
        cleanup_test_artifacts(&config_path);
    }

    #[test]
    fn startup_connect_leaves_an_already_connected_profile_alone() {
        // Relaunching must not drop a tunnel that is already up, and must not
        // add a second one alongside it.
        let client = MockNmClient::new(vec![
            profile("wg-us", "uuid-1", ProfileState::Active),
            profile("wg-eu", "uuid-2", ProfileState::Inactive),
        ]);
        let config_path = unique_test_config_path();
        write_config(&config_path, AppConfig::default());

        let connected = startup_connect(&client, &config_path).expect("startup connect should run");

        assert!(connected.is_none());
        assert!(client.connected_profiles().is_empty());
        assert!(!client.calls().iter().any(|call| call == "disconnect"));
        cleanup_test_artifacts(&config_path);
    }

    #[test]
    fn toggling_auto_connect_installs_and_removes_the_autostart_entry() {
        let client = MockNmClient::new(vec![profile("wg-us", "uuid-1", ProfileState::Inactive)]);
        let config_path = unique_test_config_path();
        let autostart_dir = autostart_test_dir();
        write_config(&config_path, AppConfig::default());

        set_autoconnect_at_login_in(&client, &config_path, &autostart_dir, true)
            .expect("enabling should succeed");
        assert!(autostart::is_installed_in(&autostart_dir));
        assert!(
            config::load(&config_path)
                .expect("config should load")
                .autoconnect_at_boot
        );
        // Toggling a preference must not activate or drop a tunnel.
        assert!(client.connected_profiles().is_empty());
        assert!(!client.calls().iter().any(|call| call == "disconnect"));

        set_autoconnect_at_login_in(&client, &config_path, &autostart_dir, false)
            .expect("disabling should succeed");
        assert!(!autostart::is_installed_in(&autostart_dir));
        assert!(
            !config::load(&config_path)
                .expect("config should load")
                .autoconnect_at_boot
        );

        let _ = std::fs::remove_dir_all(&autostart_dir);
        cleanup_test_artifacts(&config_path);
    }

    /// A throwaway autostart directory, so these tests never write into the
    /// real `~/.config/autostart`.
    fn autostart_test_dir() -> PathBuf {
        crate::testing::temp_config_path("autostart")
            .parent()
            .expect("temp config path always has a parent")
            .to_path_buf()
    }

    fn profile(name: &str, uuid: &str, state: ProfileState) -> WireguardProfile {
        crate::testing::profile(name, uuid, state)
    }

    fn write_config(path: &Path, app_cfg: AppConfig) {
        config::save(path, &app_cfg).expect("config should be written");
    }

    fn unique_test_config_path() -> PathBuf {
        crate::testing::temp_config_path("service")
    }

    fn cleanup_test_artifacts(path: &Path) {
        crate::testing::remove_temp_config(path);
    }
}
