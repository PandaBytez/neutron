use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SplitTunnelMode {
    #[default]
    Disabled,
    /// Include mode: VPN only routes specified CIDRs and resolved domain IPs.
    /// Default internet traffic bypasses the VPN tunnel (`never-default = yes`).
    Include,
    /// Exclude mode: VPN routes general traffic, but specified CIDRs and
    /// resolved domain IPs bypass the VPN tunnel.
    Exclude,
}

impl SplitTunnelMode {
    pub fn is_enabled(&self) -> bool {
        !matches!(self, SplitTunnelMode::Disabled)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SplitTunnelMode::Disabled => "disabled",
            SplitTunnelMode::Include => "include",
            SplitTunnelMode::Exclude => "exclude",
        }
    }
}

impl std::str::FromStr for SplitTunnelMode {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "disabled" | "off" | "none" => Ok(SplitTunnelMode::Disabled),
            "include" | "only" => Ok(SplitTunnelMode::Include),
            "exclude" | "bypass" => Ok(SplitTunnelMode::Exclude),
            other => Err(AppError::Config(format!(
                "invalid split-tunnel mode '{other}'; expected 'disabled', 'include', or 'exclude'"
            ))),
        }
    }
}

impl std::fmt::Display for SplitTunnelMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SplitTunnelConfig {
    #[serde(default)]
    pub mode: SplitTunnelMode,
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
}

impl SplitTunnelConfig {
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty() && self.domains.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_profiles_dir")]
    pub profiles_dir: String,
    #[serde(default = "default_true")]
    pub auto_sync_profiles: bool,
    /// Whether a random eligible profile is connected at login.
    ///
    /// This is the *single* record of that intent: it mirrors whether the
    /// autostart entry is installed (see [`crate::service::autostart`]), and is
    /// what the UI renders. An earlier top-level `autoconnect_at_boot` field
    /// duplicated it and drifted, so it is deliberately not reintroduced; the
    /// alias keeps configs written by those versions loading correctly.
    #[serde(default = "default_true", alias = "autoconnect_at_boot")]
    pub autoconnect_at_login: bool,
    /// Whether a freshly activated tunnel is checked for actually carrying
    /// traffic, and taken back down if it is not.
    ///
    /// On by default: `nmcli` reporting success only means the interface was
    /// created, so without this a dead peer looks like a working connection
    /// while swallowing every packet. Can be turned off for networks where the
    /// probe is unreliable.
    #[serde(default = "default_true")]
    pub verify_tunnel_on_connect: bool,
}

fn default_profiles_dir() -> String {
    "~/.config/neutron/profiles".to_string()
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            profiles_dir: default_profiles_dir(),
            auto_sync_profiles: default_true(),
            autoconnect_at_login: default_true(),
            verify_tunnel_on_connect: default_true(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThemeConfig {
    #[serde(default = "default_theme_preset")]
    pub preset: String,
    #[serde(default)]
    pub active_border: Option<String>,
    #[serde(default)]
    pub status_connected: Option<String>,
    #[serde(default)]
    pub status_disconnected: Option<String>,
    #[serde(default)]
    pub transfer_rx: Option<String>,
    #[serde(default)]
    pub transfer_tx: Option<String>,
}

fn default_theme_preset() -> String {
    "nord".to_string()
}

impl Default for ThemeConfig {
    fn default() -> Self {
        Self {
            preset: default_theme_preset(),
            active_border: None,
            status_connected: None,
            status_disconnected: None,
            transfer_rx: None,
            transfer_tx: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PortForwardConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QBittorrentConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_qbittorrent_url")]
    pub url: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub bind_interface: bool,
}

fn default_qbittorrent_url() -> String {
    "http://127.0.0.1:8080".to_string()
}

impl Default for QBittorrentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_qbittorrent_url(),
            username: None,
            password: None,
            bind_interface: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    /// Global kill-switch intent. When enabled, the NetworkManager kill-switch
    /// routing policy is applied to every WireGuard profile (not per-profile).
    #[serde(default)]
    pub kill_switch_enabled: bool,
    /// Global lockdown intent. When enabled, an always-on firewall blocks all
    /// traffic except the WireGuard tunnel, its handshake, and DNS.
    #[serde(default)]
    pub lockdown_enabled: bool,
    /// Profiles explicitly excluded from startup-random selection.
    #[serde(default)]
    pub excluded_profile_ids: BTreeSet<String>,
    /// Profiles marked as favorites (pinned to tray quick actions).
    #[serde(default, alias = "favorites", alias = "favorite_profiles")]
    pub favorite_profile_ids: BTreeSet<String>,
    #[serde(default, alias = "last_random_profile")]
    pub last_random_profile_id: Option<String>,
    /// Global split tunneling configuration applied across all WireGuard profiles.
    #[serde(default)]
    pub global_split_tunnel: SplitTunnelConfig,
    /// Theme and color customization
    #[serde(default)]
    pub theme: ThemeConfig,
    /// NAT-PMP dynamic port forwarding
    #[serde(default, alias = "port_forward", alias = "portforward")]
    pub port_forwarding: PortForwardConfig,
    /// qBittorrent dynamic port forwarding synchronization
    #[serde(default)]
    pub qbittorrent: QBittorrentConfig,
    /// Custom comments/info from the imported `.conf` file, indexed by profile UUID.
    #[serde(default)]
    pub profile_custom_info: BTreeMap<String, String>,
}

fn default_true() -> bool {
    true
}

pub fn load(path: &Path) -> AppResult<AppConfig> {
    if !path.exists() {
        return Ok(AppConfig::default());
    }

    let data = fs::read_to_string(path)?;
    if path.extension().and_then(|e| e.to_str()) == Some("json") {
        let parsed = serde_json::from_str::<AppConfig>(&data)?;
        Ok(parsed)
    } else {
        let parsed = toml::from_str::<AppConfig>(&data)?;
        Ok(parsed)
    }
}

pub fn save(path: &Path, config: &AppConfig) -> AppResult<()> {
    let body = if path.extension().and_then(|e| e.to_str()) == Some("json") {
        serde_json::to_string_pretty(config)?
    } else {
        toml::to_string_pretty(config)?
    };
    write_atomically(path, &body)?;
    Ok(())
}

/// Drop every piece of Neutron-side metadata keyed by `uuid` from the in-memory config.
pub fn forget_profile(config: &mut AppConfig, uuid: &str) -> bool {
    let mut changed = config.profile_custom_info.remove(uuid).is_some();
    changed |= config.excluded_profile_ids.remove(uuid);
    changed |= config.favorite_profile_ids.remove(uuid);
    if config.last_random_profile_id.as_deref() == Some(uuid) {
        config.last_random_profile_id = None;
        changed = true;
    }
    changed
}

fn write_atomically(path: &Path, body: &str) -> io::Result<()> {
    write_atomically_with(path, body, |src, dst| fs::rename(src, dst))
}

fn write_atomically_with<F>(path: &Path, body: &str, mut rename_fn: F) -> io::Result<()>
where
    F: FnMut(&Path, &Path) -> io::Result<()>,
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

    let candidates = [
        base.join("neutron").join("config.toml"),
        base.join("neutron-vpn").join("config.toml"),
        base.join("neutron").join("config.json"),
        base.join("neutron-vpn").join("config.json"),
        base.join("wireguard-manager").join("config.json"),
    ];

    for candidate in &candidates {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }

    Ok(base.join("neutron").join("config.toml"))
}

/// Resolve the configured profiles drop directory, expanding any leading `~` to the home dir.
pub fn resolve_profiles_dir(config: &AppConfig) -> PathBuf {
    let raw = &config.general.profiles_dir;
    if let Some(home) = dirs::home_dir() {
        if raw == "~" {
            return home;
        }
        if let Some(stripped) = raw.strip_prefix("~/") {
            return home.join(stripped);
        }
    }
    PathBuf::from(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_toml_config() {
        let path = unique_path("roundtrip-toml");
        let config = AppConfig {
            kill_switch_enabled: true,
            lockdown_enabled: true,
            theme: ThemeConfig {
                preset: "nord".to_string(),
                ..Default::default()
            },
            ..AppConfig::default()
        };

        save(&path, &config).expect("config should save to toml");
        let loaded = load(&path).expect("config should load from toml");

        assert!(loaded.kill_switch_enabled);
        assert!(loaded.lockdown_enabled);
        assert_eq!(loaded.theme.preset, "nord");
        cleanup(&path);
    }

    #[test]
    fn roundtrips_legacy_json_config() {
        let path = unique_path("roundtrip-json.json");
        let config = AppConfig {
            kill_switch_enabled: true,
            lockdown_enabled: true,
            ..AppConfig::default()
        };

        save(&path, &config).expect("config should save to json");
        let loaded = load(&path).expect("config should load from json");

        assert!(loaded.kill_switch_enabled);
        assert!(loaded.lockdown_enabled);
        cleanup(&path);
    }

    #[test]
    fn defaults_new_fields_for_legacy_config_without_them() {
        let path = unique_path("legacy-defaults.json");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent dir should be created");
        }
        fs::write(&path, r#"{"eligible_profile_ids":["uuid-1"]}"#)
            .expect("legacy config should be written");

        let loaded = load(&path).expect("legacy config should load");

        assert!(loaded.excluded_profile_ids.is_empty());
        assert!(!loaded.kill_switch_enabled);
        assert!(!loaded.lockdown_enabled);
        assert_eq!(loaded.theme.preset, "nord");
        cleanup(&path);
    }

    #[test]
    fn resolve_profiles_dir_expands_tilde() {
        let config = AppConfig {
            general: GeneralConfig {
                profiles_dir: "~/.config/neutron/profiles".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };

        let resolved = resolve_profiles_dir(&config);
        assert!(!resolved.to_string_lossy().starts_with('~'));
        assert!(resolved.to_string_lossy().ends_with("profiles"));

        let bare_config = AppConfig {
            general: GeneralConfig {
                profiles_dir: "~".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let bare_resolved = resolve_profiles_dir(&bare_config);
        assert!(!bare_resolved.to_string_lossy().starts_with('~'));
        if let Some(home) = dirs::home_dir() {
            assert_eq!(bare_resolved, home);
        }
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
    fn split_tunnel_mode_parsing_and_display() {
        assert_eq!(
            "include".parse::<SplitTunnelMode>().unwrap(),
            SplitTunnelMode::Include
        );
        assert_eq!(
            "exclude".parse::<SplitTunnelMode>().unwrap(),
            SplitTunnelMode::Exclude
        );
        assert_eq!(
            "disabled".parse::<SplitTunnelMode>().unwrap(),
            SplitTunnelMode::Disabled
        );
        assert_eq!(
            "off".parse::<SplitTunnelMode>().unwrap(),
            SplitTunnelMode::Disabled
        );
        assert_eq!(
            "bypass".parse::<SplitTunnelMode>().unwrap(),
            SplitTunnelMode::Exclude
        );
        assert_eq!(
            "only".parse::<SplitTunnelMode>().unwrap(),
            SplitTunnelMode::Include
        );
        assert!("invalid".parse::<SplitTunnelMode>().is_err());

        assert_eq!(SplitTunnelMode::Include.to_string(), "include");
        assert_eq!(SplitTunnelMode::Exclude.to_string(), "exclude");
        assert_eq!(SplitTunnelMode::Disabled.to_string(), "disabled");
    }

    #[test]
    fn roundtrips_qbittorrent_config() {
        let path = unique_path("qbittorrent-config");
        let config = AppConfig {
            qbittorrent: QBittorrentConfig {
                enabled: true,
                url: "http://192.168.1.50:8080".to_string(),
                username: Some("admin".to_string()),
                password: Some("secret123".to_string()),
                bind_interface: true,
            },
            ..AppConfig::default()
        };

        save(&path, &config).expect("config should save");
        let loaded = load(&path).expect("config should load");

        assert!(loaded.qbittorrent.enabled);
        assert_eq!(loaded.qbittorrent.url, "http://192.168.1.50:8080");
        assert_eq!(loaded.qbittorrent.username.as_deref(), Some("admin"));
        assert_eq!(loaded.qbittorrent.password.as_deref(), Some("secret123"));
        assert!(loaded.qbittorrent.bind_interface);
        cleanup(&path);
    }

    #[test]
    fn roundtrips_port_forwarding_config() {
        let path = unique_path("port-forwarding-config");
        let default_cfg = AppConfig::default();
        assert!(!default_cfg.port_forwarding.enabled);

        let config = AppConfig {
            port_forwarding: PortForwardConfig { enabled: true },
            ..AppConfig::default()
        };

        save(&path, &config).expect("config should save");
        let loaded = load(&path).expect("config should load");
        assert!(loaded.port_forwarding.enabled);
        cleanup(&path);
    }

    #[test]
    fn write_atomically_handles_cross_device_rename_fallback() {
        let path = unique_path("atomic-cross-dev");
        let body = "test content for cross-device fallback";

        // Simulate CrossesDevices error on rename
        let mut rename_called = false;
        let res = write_atomically_with(&path, body, |src, _dst| {
            rename_called = true;
            assert!(src.exists());
            Err(io::Error::from(io::ErrorKind::CrossesDevices))
        });

        assert!(
            res.is_ok(),
            "cross-device error should be handled by copy fallback"
        );
        assert!(rename_called);
        assert!(path.exists());
        assert_eq!(fs::read_to_string(&path).unwrap(), body);
        cleanup(&path);
    }

    #[test]
    fn write_atomically_cleans_up_tmp_on_rename_failure() {
        let path = unique_path("atomic-fail-cleanup");
        let body = "test content for failure cleanup";

        let mut observed_tmp = None;
        let res = write_atomically_with(&path, body, |src, _| {
            observed_tmp = Some(src.to_path_buf());
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        });

        assert!(res.is_err());
        let tmp = observed_tmp.expect("tmp path should have been passed to rename_fn");
        assert!(!tmp.exists(), "temporary file must be removed on failure");
        assert!(!path.exists());
        cleanup(&path);
    }

    fn unique_path(label: &str) -> PathBuf {
        if label.ends_with(".json") {
            crate::testing::temp_config_path(label)
        } else {
            crate::testing::temp_toml_config_path(label)
        }
    }

    fn cleanup(path: &Path) {
        crate::testing::remove_temp_config(path);
    }
}
