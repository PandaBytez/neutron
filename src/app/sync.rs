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
use crate::process::terminal_safe;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub imported: Vec<String>,
    pub skipped: usize,
    pub errors: Vec<String>,
}

/// Create the profiles directory, attempting owner-only permissions on Unix.
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

/// Create the config and inbox directories using [`ensure_profiles_dir`].
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
/// Claim files before import so an editor's replacement is never consumed.
pub fn sync_profiles_dir<C: NmClient>(client: &C, config: &AppConfig) -> AppResult<SyncReport> {
    sync_profiles_dir_with(client, config, |path| client.import_wireguard_profile(path))
}

fn sync_profiles_dir_with<C: NmClient>(
    client: &C,
    config: &AppConfig,
    mut import: impl FnMut(&Path) -> AppResult<String>,
) -> AppResult<SyncReport> {
    let dir = config::resolve_profiles_dir(config);
    let _ = ensure_profiles_dir(&dir);

    if !dir.is_dir() {
        return Ok(SyncReport::default());
    }
    let _lock = match config::lock_sidecar(&dir.join("sync"), ".lock") {
        Ok(lock) => lock,
        Err(error) => {
            return Ok(SyncReport {
                errors: vec![format!(
                    "Could not lock profiles directory {}: {error}",
                    terminal_safe(&dir.display().to_string())
                )],
                ..Default::default()
            });
        }
    };

    let existing_profiles = client.list_wireguard_profiles()?;
    let existing_names: HashSet<String> = existing_profiles.into_iter().map(|p| p.name).collect();

    let mut report = SyncReport::default();

    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(err) => {
            report.errors.push(terminal_safe(&format!(
                "Failed to read profiles directory {}: {err}",
                dir.display()
            )));
            return Ok(report);
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if entry.file_type()?.is_file() && path.extension().and_then(|e| e.to_str()) == Some("conf")
        {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();

            if existing_names.contains(&stem) {
                report.errors.push(terminal_safe(&format!(
                    "{}: a profile named '{stem}' already exists in NetworkManager; preserved to prevent data loss",
                    path.file_name().unwrap_or_default().to_string_lossy()
                )));
                report.skipped += 1;
                continue;
            }

            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let processing = dir.join(format!(".import-{}-{stamp}", std::process::id()));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            let claimed = processing.join(entry.file_name());
            if let Err(err) = builder
                .create(&processing)
                .and_then(|_| fs::rename(&path, &claimed))
            {
                let _ = fs::remove_dir(&processing);
                report.errors.push(terminal_safe(&format!(
                    "Could not claim {} for import: {err}",
                    path.display()
                )));
                continue;
            }
            match import(&claimed) {
                Ok(_) => {
                    report.imported.push(stem);
                    if let Err(err) = fs::remove_file(&claimed) {
                        report.errors.push(terminal_safe(&format!(
                            "Failed to remove imported inbox file {}: {err}",
                            claimed.display()
                        )));
                    }
                }
                Err(err) => {
                    // hard_link never overwrites a newer inbox file.
                    if fs::hard_link(&claimed, &path).is_ok() {
                        let _ = fs::remove_file(&claimed);
                    }
                    report.errors.push(terminal_safe(&format!(
                        "{}: {err}; source retained at {}",
                        path.file_name().unwrap_or_default().to_string_lossy(),
                        if claimed.exists() { &claimed } else { &path }.display()
                    )));
                }
            }
            let _ = fs::remove_dir(&processing);
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    #[test]
    fn replacing_an_inbox_file_during_import_preserves_the_replacement_and_failed_snapshot() {
        for fail in [false, true] {
            let dir = crate::testing::scratch_dir("claimed-import");
            let original = dir.join("wg-test.conf");
            std::fs::write(&original, "old contents").unwrap();
            let mut cfg = crate::config::AppConfig::default();
            cfg.general.profiles_dir = dir.to_str().unwrap().into();
            let report = super::sync_profiles_dir_with(
                &crate::testing::MockNmClient::default(),
                &cfg,
                |claimed| {
                    assert_eq!(std::fs::read_to_string(claimed).unwrap(), "old contents");
                    assert_ne!(claimed, original);
                    assert_eq!(claimed.file_name(), original.file_name());
                    std::fs::write(&original, "new contents").unwrap();
                    if fail {
                        Err(crate::error::AppError::Config("import rejected".into()))
                    } else {
                        Ok("imported".into())
                    }
                },
            )
            .unwrap();
            assert_eq!(std::fs::read_to_string(&original).unwrap(), "new contents");
            assert_eq!(report.imported.len(), usize::from(!fail));
            if fail {
                let processing = std::fs::read_dir(&dir)
                    .unwrap()
                    .flatten()
                    .find(|e| e.file_name().to_string_lossy().starts_with(".import-"))
                    .unwrap()
                    .path();
                assert_eq!(
                    std::fs::read_to_string(processing.join("wg-test.conf")).unwrap(),
                    "old contents"
                );
                assert!(report.errors[0].contains("source retained"));
            }
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    use super::*;
    use crate::nm::{ProfileState, WireguardProfile};
    use crate::testing::{MockNmClient, scratch_dir};

    #[test]
    fn security_import_errors_escape_hostile_filenames() {
        let dir = scratch_dir("hostile-inbox");
        let file = dir.join("caf\u{e9}\x1b]52;c;payload\x07.conf");
        fs::write(&file, "invalid").unwrap();
        let config = AppConfig {
            general: config::GeneralConfig {
                profiles_dir: dir.to_string_lossy().into_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        let report = sync_profiles_dir(&MockNmClient::default().fail_import(), &config).unwrap();
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].contains("caf\u{e9}\\u{1b}]52;c;payload\\u{7}"));
        assert!(!report.errors[0].chars().any(char::is_control));
        assert!(file.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sync_imports_new_conf_files_and_cleans_inbox() {
        let temp_dir = scratch_dir("sync");

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
        assert_eq!(report.errors.len(), 1);

        // conf1 should be preserved to prevent overwriting existing profile data
        assert!(
            conf1.exists(),
            "already existing profile in NM should be preserved from deletion"
        );
        // Newly imported conf2 consumed from inbox
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
        let temp_dir = scratch_dir("sync-fail");

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
    fn sync_reports_inbox_files_it_cannot_consume() {
        use crate::testing::running_as_root;
        use std::os::unix::fs::PermissionsExt;

        // Directory permissions do not stop root, so the removal failure
        // below cannot be triggered deterministically as root.
        if running_as_root() {
            eprintln!(
                "Skipping inbox-removal test: running as root ignores directory permissions."
            );
            return;
        }
        let temp_dir = scratch_dir("sync-undeletable");
        let conf = temp_dir.join("stuck.conf");
        fs::write(&conf, "[Interface]\nPrivateKey = abc\n").unwrap();
        // The import itself succeeds (mock); consuming the inbox file fails.
        fs::set_permissions(&temp_dir, fs::Permissions::from_mode(0o555)).unwrap();

        let client = MockNmClient::default();
        let config = AppConfig {
            general: config::GeneralConfig {
                profiles_dir: temp_dir.to_string_lossy().to_string(),
                ..Default::default()
            },
            ..Default::default()
        };

        let report = sync_profiles_dir(&client, &config).unwrap();
        assert!(report.imported.is_empty());
        assert_eq!(report.errors.len(), 1);
        assert!(
            report.errors[0].contains("Could not lock profiles directory"),
            "removal failure must be reported, not swallowed: {:?}",
            report.errors
        );
        assert!(conf.exists(), "an unconsumed inbox file must be kept");

        fs::set_permissions(&temp_dir, fs::Permissions::from_mode(0o755)).unwrap();
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn ensure_profiles_dir_creates_private_directory_and_is_idempotent() {
        let temp_dir = scratch_dir("ensure-dirs");
        let profiles = temp_dir.join("profiles");

        assert!(!profiles.exists());
        ensure_profiles_dir(&profiles).unwrap();
        ensure_profiles_dir(&profiles).unwrap();
        assert!(profiles.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&profiles).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
