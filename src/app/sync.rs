//! Profile drop-directory scanning and synchronization with NetworkManager.
//!
//! The drop directory (`~/.config/neutron/profiles/`) acts as an inbox for
//! WireGuard `.conf` files. When new configuration files are detected, they are
//! imported into NetworkManager and the source `.conf` files are removed from the
//! drop directory. This ensures NetworkManager remains the single source of truth
//! and prevents deleted profiles from being resurrected on subsequent launches.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::config::{self, AppConfig};
use crate::error::AppResult;
use crate::nm::NmClient;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub imported: Vec<String>,
    pub skipped: usize,
    pub errors: Vec<String>,
}

/// Ensure the profiles directory exists with secure user-only permissions (0700 on Unix).
pub fn ensure_profiles_dir(dir: &Path) -> std::io::Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(())
}

/// Ensure the application directories (~/.config/neutron and profiles inbox) exist
/// with secure user-only permissions (0700 on Unix).
pub fn ensure_app_dirs(config: &AppConfig) -> std::io::Result<()> {
    if let Ok(config_path) = config::default_config_path()
        && let Some(parent) = config_path.parent()
    {
        ensure_profiles_dir(parent)?;
    }
    let dir = config::resolve_profiles_dir(config);
    ensure_profiles_dir(&dir)?;
    Ok(())
}

/// Scan the configured `profiles_dir` inbox and import any new `.conf` files into NetworkManager.
///
/// Successfully imported or already-existing profiles are removed from the inbox directory so that
/// NetworkManager remains the sole source of truth and profile deletions are never overridden.
pub fn sync_profiles_dir<C: NmClient>(client: &C, config: &AppConfig) -> AppResult<SyncReport> {
    let dir = config::resolve_profiles_dir(config);
    let _ = ensure_profiles_dir(&dir);

    if !dir.is_dir() {
        return Ok(SyncReport::default());
    }

    let existing_profiles = client.list_wireguard_profiles()?;
    let existing_names: HashSet<String> = existing_profiles.into_iter().map(|p| p.name).collect();

    let mut report = SyncReport::default();

    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(err) => {
            report.errors.push(format!(
                "Failed to read profiles directory {}: {err}",
                dir.display()
            ));
            return Ok(report);
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("conf") {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();

            if existing_names.contains(&stem) {
                // Already managed by NetworkManager; consume from the inbox
                // so it doesn't linger and resurrect if deleted later.
                let _ = fs::remove_file(&path);
                report.skipped += 1;
                continue;
            }

            match client.import_wireguard_profile(&path) {
                Ok(_) => {
                    report.imported.push(stem);
                    // Consumed on successful import: NetworkManager is now the source of truth.
                    let _ = fs::remove_file(&path);
                }
                Err(err) => {
                    report.errors.push(format!(
                        "{}: {err}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ));
                }
            }
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nm::{ProfileState, WireguardProfile};
    use crate::testing::MockNmClient;

    #[test]
    fn sync_imports_new_conf_files_and_cleans_inbox() {
        let temp_dir = std::env::temp_dir().join(format!(
            "neutron-sync-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();

        let conf1 = temp_dir.join("profile1.conf");
        let conf2 = temp_dir.join("profile2.conf");
        let txt = temp_dir.join("ignore.txt");

        fs::write(&conf1, "[Interface]\nPrivateKey = abc\n").unwrap();
        fs::write(&conf2, "[Interface]\nPrivateKey = def\n").unwrap();
        fs::write(&txt, "not a conf file").unwrap();

        let existing = vec![WireguardProfile {
            name: "profile1".to_string(),
            uuid: "uuid-1".to_string(),
            state: ProfileState::Inactive,
        }];

        let client = MockNmClient::new(existing);
        let config = AppConfig {
            general: config::GeneralConfig {
                profiles_dir: temp_dir.to_string_lossy().to_string(),
                ..Default::default()
            },
            ..Default::default()
        };

        let report = sync_profiles_dir(&client, &config).unwrap();

        assert_eq!(report.skipped, 1);
        assert_eq!(report.imported, vec!["profile2".to_string()]);
        assert!(report.errors.is_empty());

        // Both .conf files should be removed from inbox (consumed into NM)
        assert!(
            !conf1.exists(),
            "already existing profile in NM should be consumed from inbox"
        );
        assert!(
            !conf2.exists(),
            "newly imported profile should be consumed from inbox"
        );
        // Non-conf file remains untouched
        assert!(txt.exists(), "non-conf files should not be removed");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn sync_preserves_conf_files_on_import_failure() {
        let temp_dir = std::env::temp_dir().join(format!(
            "neutron-sync-fail-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();

        let conf = temp_dir.join("broken.conf");
        fs::write(&conf, "invalid").unwrap();

        let client = MockNmClient::default().fail_import();
        let config = AppConfig {
            general: config::GeneralConfig {
                profiles_dir: temp_dir.to_string_lossy().to_string(),
                ..Default::default()
            },
            ..Default::default()
        };

        let report = sync_profiles_dir(&client, &config).unwrap();
        assert_eq!(report.imported.len(), 0);
        assert_eq!(report.errors.len(), 1);
        // Failed import keeps the file so user doesn't lose it
        assert!(conf.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn ensure_app_dirs_creates_profiles_directory() {
        let temp_dir = std::env::temp_dir().join(format!(
            "neutron-ensure-dirs-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let profiles = temp_dir.join("profiles");
        let config = AppConfig {
            general: config::GeneralConfig {
                profiles_dir: profiles.to_string_lossy().to_string(),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(!profiles.exists());
        ensure_app_dirs(&config).unwrap();
        assert!(profiles.is_dir());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
