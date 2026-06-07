use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    /// Profiles explicitly excluded from startup-random selection. An empty set
    /// means every WireGuard profile is eligible (opt-out model): profiles are
    /// eligible by default and the user toggles individual ones off.
    #[serde(default)]
    pub excluded_profile_ids: BTreeSet<String>,
    #[serde(default, alias = "last_random_profile")]
    pub last_random_profile_id: Option<String>,
    /// Global kill-switch intent. When enabled, the NetworkManager kill-switch
    /// routing policy is applied to every WireGuard profile (not per-profile).
    #[serde(default)]
    pub kill_switch_enabled: bool,
    /// Global lockdown intent. When enabled, an always-on firewall blocks all
    /// traffic except the WireGuard tunnel, its handshake, and DNS -- enforced
    /// even when no VPN is connected. The firewall rules are the real source of
    /// truth; this flag only remembers the user's intent so the GUI toggle can
    /// show the right state without a privileged query at startup.
    #[serde(default)]
    pub lockdown_enabled: bool,
    /// Last window width remembered between sessions (`None` until first save).
    #[serde(default)]
    pub window_width: Option<i32>,
    /// Last window height remembered between sessions (`None` until first save).
    #[serde(default)]
    pub window_height: Option<i32>,
    /// Custom comments/info from the imported `.conf` file, indexed by profile UUID.
    #[serde(default)]
    pub profile_custom_info: std::collections::BTreeMap<String, String>,
}

pub fn load(path: &Path) -> AppResult<AppConfig> {
    if !path.exists() {
        return Ok(AppConfig::default());
    }

    let data = fs::read_to_string(path)?;
    let parsed = serde_json::from_str::<AppConfig>(&data)?;
    Ok(parsed)
}

pub fn save(path: &Path, config: &AppConfig) -> AppResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(config)?;
    write_atomically(path, &body)?;
    Ok(())
}

/// Drop every piece of Zento-side metadata keyed by `uuid` from the in-memory
/// config: custom info, exclusion membership, and the last-random pointer.
///
/// Returns `true` if anything actually changed, so the caller can skip an
/// unnecessary save. This is a pure mutation and performs no I/O.
pub fn forget_profile(config: &mut AppConfig, uuid: &str) -> bool {
    let mut changed = config.profile_custom_info.remove(uuid).is_some();
    changed |= config.excluded_profile_ids.remove(uuid);
    if config.last_random_profile_id.as_deref() == Some(uuid) {
        config.last_random_profile_id = None;
        changed = true;
    }
    changed
}

fn write_atomically(path: &Path, body: &str) -> io::Result<()> {
    write_atomically_with(path, body, |src, dst| fs::rename(src, dst))
}

fn write_atomically_with<F>(path: &Path, body: &str, rename_fn: F) -> io::Result<()>
where
    F: Fn(&Path, &Path) -> io::Result<()>,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = temporary_path(path);

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    {
        use std::io::Write;
        let mut tmp_file = options.open(&tmp_path)?;
        tmp_file.write_all(body.as_bytes())?;
    }

    match rename_fn(&tmp_path, path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::CrossesDevices => {
            fs::copy(&tmp_path, path)?;
            fs::remove_file(&tmp_path)?;
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_file(&tmp_path);
            Err(error)
        }
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    PathBuf::from(format!("{}.tmp.{stamp}", path.display()))
}

pub fn default_config_path() -> AppResult<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| {
        AppError::Config("could not determine configuration directory".to_string())
    })?;
    Ok(base.join("wireguard-manager").join("config.json"))
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn roundtrips_kill_switch_and_window_size() {
        let path = unique_path("roundtrip");
        let config = AppConfig {
            kill_switch_enabled: true,
            lockdown_enabled: true,
            window_width: Some(1024),
            window_height: Some(768),
            ..AppConfig::default()
        };

        save(&path, &config).expect("config should save");
        let loaded = load(&path).expect("config should load");

        assert!(loaded.kill_switch_enabled);
        assert!(loaded.lockdown_enabled);
        assert_eq!(loaded.window_width, Some(1024));
        assert_eq!(loaded.window_height, Some(768));
        cleanup(&path);
    }

    #[test]
    fn defaults_new_fields_for_legacy_config_without_them() {
        let path = unique_path("legacy-defaults");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent dir should be created");
        }
        // A pre-opt-out config only carried the old opt-in `eligible_profile_ids`
        // field. It must load cleanly: the unknown field is ignored and the new
        // opt-out `excluded_profile_ids` defaults to empty (everything eligible).
        fs::write(&path, r#"{"eligible_profile_ids":["uuid-1"]}"#)
            .expect("legacy config should be written");

        let loaded = load(&path).expect("legacy config should load");

        assert!(loaded.excluded_profile_ids.is_empty());
        assert!(!loaded.kill_switch_enabled);
        assert!(!loaded.lockdown_enabled);
        assert_eq!(loaded.window_width, None);
        assert_eq!(loaded.window_height, None);
        cleanup(&path);
    }

    #[test]
    fn write_atomically_falls_back_when_rename_crosses_devices() {
        let path = unique_path("cross-device");

        write_atomically_with(&path, "payload", |_src, _dst| {
            Err(io::Error::new(io::ErrorKind::CrossesDevices, "simulated"))
        })
        .expect("fallback copy should succeed");

        let content = fs::read_to_string(&path).expect("file should be written");
        assert_eq!(content, "payload");
        cleanup(&path);
    }

    #[test]
    fn write_atomically_cleans_temporary_file_on_rename_error() {
        let path = unique_path("rename-error");

        let result = write_atomically_with(&path, "payload", |_src, _dst| {
            Err(io::Error::other("simulated rename failure"))
        });

        assert!(result.is_err());

        let parent = path.parent().expect("path should have parent");
        let tmp_prefix = format!("{}.tmp.", path.display());
        let leftover = fs::read_dir(parent)
            .expect("parent dir should be readable")
            .filter_map(Result::ok)
            .any(|entry| entry.path().to_string_lossy().starts_with(&tmp_prefix));
        assert!(!leftover, "temporary file should be cleaned up");

        cleanup(&path);
    }

    #[test]
    fn forget_profile_removes_all_metadata_for_uuid() {
        let mut config = AppConfig::default();
        config
            .profile_custom_info
            .insert("uuid-1".to_string(), "# notes".to_string());
        config.excluded_profile_ids.insert("uuid-1".to_string());
        config.last_random_profile_id = Some("uuid-1".to_string());

        let changed = forget_profile(&mut config, "uuid-1");

        assert!(changed);
        assert!(config.profile_custom_info.is_empty());
        assert!(config.excluded_profile_ids.is_empty());
        assert_eq!(config.last_random_profile_id, None);
    }

    #[test]
    fn forget_profile_is_a_noop_for_unknown_uuid() {
        let mut config = AppConfig::default();
        config.excluded_profile_ids.insert("uuid-keep".to_string());
        config.last_random_profile_id = Some("uuid-keep".to_string());

        let changed = forget_profile(&mut config, "uuid-absent");

        assert!(!changed);
        assert!(config.excluded_profile_ids.contains("uuid-keep"));
        assert_eq!(config.last_random_profile_id, Some("uuid-keep".to_string()));
    }

    #[test]
    fn forget_profile_only_clears_the_matching_last_random_pointer() {
        let mut config = AppConfig::default();
        config.last_random_profile_id = Some("uuid-other".to_string());

        // Removing a different profile must leave an unrelated last-random
        // pointer untouched and report no change.
        let changed = forget_profile(&mut config, "uuid-1");

        assert!(!changed);
        assert_eq!(
            config.last_random_profile_id,
            Some("uuid-other".to_string())
        );
    }

    #[test]
    fn forget_profile_reports_change_when_only_exclusion_membership_matches() {
        let mut config = AppConfig::default();
        config.excluded_profile_ids.insert("uuid-1".to_string());

        let changed = forget_profile(&mut config, "uuid-1");

        assert!(changed);
        assert!(config.excluded_profile_ids.is_empty());
    }

    fn unique_path(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("wireguard-manager-config-unit-{label}-{suffix}"))
            .join("config.json")
    }

    fn cleanup(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }
}
