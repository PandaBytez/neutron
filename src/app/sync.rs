//! Profile drop-directory scanning and synchronization with NetworkManager.

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

/// Scan the configured `profiles_dir` and import any new `.conf` files into NetworkManager.
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
                report.skipped += 1;
                continue;
            }

            match client.import_wireguard_profile(&path) {
                Ok(_) => {
                    report.imported.push(stem);
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
    fn sync_imports_new_conf_files() {
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

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
