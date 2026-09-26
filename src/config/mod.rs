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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PortForwardMode {
    #[default]
    Disabled,
    /// Lease a NAT-PMP port from the tunnel gateway without pushing it
    /// anywhere.
    Forward,
    /// Lease the port and automatically push it to qBittorrent.
    /// `lowercase` would serialize this as "forwardandsync", so the one
    /// long variant carries an explicit spelling shared by serde,
    /// `Display`, docs, and the TOML example.
    #[serde(rename = "forward-and-sync")]
    ForwardAndSync,
}

impl PortForwardMode {
    pub fn is_enabled(&self) -> bool {
        !matches!(self, PortForwardMode::Disabled)
    }

    pub fn syncs_to_qbittorrent(&self) -> bool {
        matches!(self, PortForwardMode::ForwardAndSync)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PortForwardMode::Disabled => "disabled",
            PortForwardMode::Forward => "forward",
            PortForwardMode::ForwardAndSync => "forward-and-sync",
        }
    }
}

impl std::str::FromStr for PortForwardMode {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "disabled" | "off" | "none" => Ok(PortForwardMode::Disabled),
            "forward" | "on" | "port-forward" => Ok(PortForwardMode::Forward),
            "forward-and-sync" | "auto-sync" | "qbit" => Ok(PortForwardMode::ForwardAndSync),
            other => Err(AppError::Config(format!(
                "invalid port-forward mode '{other}'; expected 'disabled', 'forward', or 'forward-and-sync'"
            ))),
        }
    }
}

impl std::fmt::Display for PortForwardMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
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
    #[serde(default, alias = "autoconnect_at_boot")]
    pub autoconnect_at_login: bool,
    /// Verify fresh tunnels with an endpoint and persistent keepalive; disconnect
    /// if no authenticated traffic arrives. Idle on-demand tunnels are exempt.
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
            autoconnect_at_login: false,
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
#[serde(from = "PortForwardConfigDe")]
pub struct PortForwardConfig {
    #[serde(default)]
    pub mode: PortForwardMode,
    /// Legacy `enabled` flag, deserialized only so configs written before
    /// the mode existed keep loading; reconciled into `mode` in [`load`]
    /// and never serialized back.
    #[serde(skip_serializing)]
    pub legacy_enabled: bool,
    /// Whether the file explicitly set `mode`. Absent `mode` and explicit
    /// `mode = "disabled"` both deserialize to `Disabled` and would be
    /// indistinguishable, so the reconcile step in [`load`] needs this to
    /// know an explicit choice always wins over legacy flags.
    #[serde(skip_serializing)]
    pub mode_explicit: bool,
}

/// Deserialization shadow of [`PortForwardConfig`]: `mode` arrives as an
/// `Option` so presence survives into [`PortForwardConfig::mode_explicit`].
#[derive(Debug, Default, Deserialize)]
struct PortForwardConfigDe {
    #[serde(default)]
    mode: Option<PortForwardMode>,
    #[serde(default, alias = "enabled")]
    legacy_enabled: bool,
}

impl From<PortForwardConfigDe> for PortForwardConfig {
    fn from(de: PortForwardConfigDe) -> Self {
        Self {
            mode: de.mode.unwrap_or_default(),
            legacy_enabled: de.legacy_enabled,
            mode_explicit: de.mode.is_some(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QBittorrentConfig {
    /// Legacy sync toggle, deserialized only so pre-mode configs keep
    /// loading; the port-forward mode decides syncing now (see
    /// [`PortForwardMode`]).
    #[serde(default, alias = "enabled", skip_serializing)]
    pub legacy_enabled: bool,
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

/// Host and port of a WebUI URL. Scheme and path stay put so editing the
/// address does not drop `http://` or a non-root path.
pub fn split_webui_url(url: &str) -> (String, String) {
    let rest = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if let Some((host, port)) = authority.rsplit_once(':')
        && !host.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
    {
        return (host.to_string(), port.to_string());
    }
    (
        authority.to_string(),
        default_qbittorrent_url()
            .rsplit_once(':')
            .map(|(_, port)| port.to_string())
            .unwrap_or_else(|| "8080".to_string()),
    )
}

pub fn join_webui_url(url: &str, host: &str, port: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let path = rest.find(['/', '?', '#']).map(|i| &rest[i..]).unwrap_or("");
    format!("{scheme}://{host}:{port}{path}")
}

impl Default for QBittorrentConfig {
    fn default() -> Self {
        Self {
            legacy_enabled: false,
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
    /// Imported notes keyed by UUID. Loaded from profile-info.json; the legacy
    /// inline field is accepted for migration but never serialized into settings.
    #[serde(default, skip_serializing)]
    pub profile_custom_info: BTreeMap<String, String>,
}

fn default_true() -> bool {
    true
}

pub fn load(path: &Path) -> AppResult<AppConfig> {
    let mut config = if path.exists() {
        let data = fs::read_to_string(path)?;
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            serde_json::from_str::<AppConfig>(&data)?
        } else {
            toml::from_str::<AppConfig>(&data)?
        }
    } else {
        AppConfig::default()
    };
    if let Some(info) = read_profile_info(path)? {
        // The sidecar is authoritative, even when empty: a failed settings
        // save must not resurrect deleted notes from the old inline field.
        config.profile_custom_info = info;
    }
    // Reconcile pre-mode configs: two independent booleans collapsed into
    // one mode. An explicit `mode` always wins (tracked separately because
    // absent `mode` and explicit `mode = "disabled"` both read as
    // `Disabled`); legacy flags only promote when no mode was given.
    if !config.port_forwarding.mode_explicit {
        if config.qbittorrent.legacy_enabled && config.port_forwarding.legacy_enabled {
            config.port_forwarding.mode = PortForwardMode::ForwardAndSync;
        } else if config.port_forwarding.legacy_enabled {
            config.port_forwarding.mode = PortForwardMode::Forward;
        }
    }
    Ok(config)
}

fn profile_info_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name("profile-info.json")
}

fn read_profile_info(config_path: &Path) -> AppResult<Option<BTreeMap<String, String>>> {
    let path = profile_info_path(config_path);
    match fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data).map(Some).map_err(|error| {
            AppError::Config(format!("could not parse {}: {error}", path.display()))
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(AppError::Config(format!(
            "could not read {}: {error}",
            path.display()
        ))),
    }
}

pub fn save(path: &Path, config: &AppConfig) -> AppResult<()> {
    let _lock = lock_config(path)?;
    save_unlocked(path, config)
}

static IN_PROCESS_POLICY_LOCKS: std::sync::Mutex<
    Option<std::collections::HashMap<PathBuf, std::sync::Arc<std::sync::Mutex<()>>>>,
> = std::sync::Mutex::new(None);

fn path_policy_mutex(path: &Path) -> std::sync::Arc<std::sync::Mutex<()>> {
    let mut lock = IN_PROCESS_POLICY_LOCKS.lock().unwrap();
    let map = lock.get_or_insert_with(std::collections::HashMap::new);
    map.entry(path.to_path_buf())
        .or_insert_with(|| std::sync::Arc::new(std::sync::Mutex::new(())))
        .clone()
}

/// Coordinate global policy sweeps and activation so concurrent workers cannot
/// interleave profile changes and overwrite settings with stale configurations.
pub fn coordinate_policy<R>(path: &Path, f: impl FnOnce() -> AppResult<R>) -> AppResult<R> {
    let mutex = path_policy_mutex(path);
    let _mem_lock = mutex
        .lock()
        .map_err(|_| AppError::Config("policy coordination mutex poisoned".to_string()))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".policy.lock");
    let lock = options.open(PathBuf::from(lock_path))?;
    lock.lock()?;
    f()
}

/// Serialize narrow read-modify-write edits across threads and Neutron processes.
/// Lock a stable sidecar, since atomic replacement changes the config's inode.
pub fn update(path: &Path, edit: impl FnOnce(&mut AppConfig)) -> AppResult<AppConfig> {
    let _lock = lock_config(path)?;
    let mut config = load(path)?;
    edit(&mut config);
    save_unlocked(path, &config)?;
    Ok(config)
}

fn lock_config(path: &Path) -> AppResult<fs::File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock = options.open(PathBuf::from(lock_path))?;
    lock.lock()?;
    Ok(lock)
}

fn save_unlocked(path: &Path, config: &AppConfig) -> AppResult<()> {
    let body = if path.extension().and_then(|e| e.to_str()) == Some("json") {
        serde_json::to_string_pretty(config)?
    } else {
        toml::to_string_pretty(config)?
    };
    let stored_info = read_profile_info(path)?;
    if stored_info.as_ref() != Some(&config.profile_custom_info)
        && (stored_info.is_some() || !config.profile_custom_info.is_empty())
    {
        // Preserve notes before removing their legacy copy from settings. Both
        // writes share the config lock; each individual file is replaced atomically.
        let info_path = profile_info_path(path);
        write_atomically(
            &info_path,
            &serde_json::to_string_pretty(&config.profile_custom_info)?,
        )
        .map_err(|error| {
            AppError::Config(format!("could not save {}: {error}", info_path.display()))
        })?;
    }
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

/// Write `body` to `path` so a concurrent reader sees either the old contents or
/// the new ones, never a partial write. Shared with
/// [`crate::service::lease`], which republishes a file a running TUI is reading.
pub(crate) fn write_atomically(path: &Path, body: &str) -> io::Result<()> {
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
    fn profile_notes_migrate_from_toml_and_json_and_follow_profile_deletion() {
        for (label, legacy) in [
            (
                "notes",
                "[profile_custom_info]\nuuid = \"Provider notes\\nSecond line\"\n",
            ),
            (
                "notes.json",
                r#"{"profile_custom_info":{"uuid":"Provider notes\nSecond line"}}"#,
            ),
        ] {
            let path = unique_path(label);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, legacy).unwrap();
            assert_eq!(
                load(&path).unwrap().profile_custom_info["uuid"],
                "Provider notes\nSecond line"
            );
            assert!(
                !profile_info_path(&path).exists(),
                "reading must not migrate files"
            );
            update(&path, |cfg| cfg.theme.preset = "gruvbox".into()).unwrap();
            assert!(
                !fs::read_to_string(&path)
                    .unwrap()
                    .contains("profile_custom_info")
            );
            assert_eq!(
                load(&path).unwrap().profile_custom_info["uuid"],
                "Provider notes\nSecond line"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(profile_info_path(&path))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
            update(&path, |cfg| {
                forget_profile(cfg, "uuid");
            })
            .unwrap();
            assert!(load(&path).unwrap().profile_custom_info.is_empty());
            // A stale inline copy after an interrupted save must not resurrect notes.
            fs::write(&path, legacy).unwrap();
            assert!(load(&path).unwrap().profile_custom_info.is_empty());
            cleanup(&path);
        }
    }

    #[test]
    fn failed_metadata_migration_preserves_inline_notes_and_reports_the_file() {
        let path = unique_path("notes-failed-migration");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let legacy = "[profile_custom_info]\nuuid = \"keep me\"\n";
        fs::write(&path, legacy).unwrap();
        fs::create_dir(profile_info_path(&path)).unwrap();
        let error = update(&path, |_| {}).unwrap_err();
        assert!(error.to_string().contains("profile-info.json"));
        assert_eq!(fs::read_to_string(&path).unwrap(), legacy);
        fs::remove_dir(profile_info_path(&path)).unwrap();
        fs::write(profile_info_path(&path), "invalid JSON").unwrap();
        assert!(load(&path).is_err());
        assert!(save(&path, &AppConfig::default()).is_err());
        assert_eq!(
            fs::read_to_string(profile_info_path(&path)).unwrap(),
            "invalid JSON"
        );
        cleanup(&path);
    }

    #[test]
    fn concurrent_narrow_updates_preserve_every_writer() {
        let path = unique_path("concurrent-updates");
        save(&path, &AppConfig::default()).unwrap();
        std::thread::scope(|scope| {
            for i in 0..16 {
                let path = &path;
                scope.spawn(move || {
                    update(path, |cfg| {
                        cfg.favorite_profile_ids.insert(format!("uuid-{i}"));
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    })
                    .unwrap();
                });
            }
        });
        assert_eq!(load(&path).unwrap().favorite_profile_ids.len(), 16);
        cleanup(&path);
    }

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
    fn port_forward_mode_parsing_and_display() {
        assert_eq!(
            "forward".parse::<PortForwardMode>().unwrap(),
            PortForwardMode::Forward
        );
        assert_eq!(
            "forward-and-sync".parse::<PortForwardMode>().unwrap(),
            PortForwardMode::ForwardAndSync
        );
        assert_eq!(
            "disabled".parse::<PortForwardMode>().unwrap(),
            PortForwardMode::Disabled
        );
        assert_eq!(
            "off".parse::<PortForwardMode>().unwrap(),
            PortForwardMode::Disabled
        );
        assert_eq!(
            "auto-sync".parse::<PortForwardMode>().unwrap(),
            PortForwardMode::ForwardAndSync
        );
        assert!("invalid".parse::<PortForwardMode>().is_err());

        assert_eq!(PortForwardMode::Forward.to_string(), "forward");
        assert_eq!(
            PortForwardMode::ForwardAndSync.to_string(),
            "forward-and-sync"
        );
        assert_eq!(PortForwardMode::Disabled.to_string(), "disabled");

        assert!(PortForwardMode::Forward.is_enabled());
        assert!(PortForwardMode::ForwardAndSync.is_enabled());
        assert!(!PortForwardMode::Disabled.is_enabled());
        assert!(PortForwardMode::ForwardAndSync.syncs_to_qbittorrent());
        assert!(!PortForwardMode::Forward.syncs_to_qbittorrent());
        assert!(!PortForwardMode::Disabled.syncs_to_qbittorrent());
    }

    #[test]
    fn legacy_enabled_flags_migrate_to_mode() {
        let write_fixture = |label: &str, body: &str| -> PathBuf {
            let path = unique_path(label);
            fs::create_dir_all(path.parent().expect("fixture path has a parent"))
                .expect("fixture dir should be created");
            fs::write(&path, body).expect("legacy fixture should write");
            path
        };

        let path = write_fixture(
            "pf-legacy-both",
            "[port_forwarding]\nenabled = true\n[qbittorrent]\nenabled = true\n",
        );
        let loaded = load(&path).expect("legacy config should load");
        assert_eq!(loaded.port_forwarding.mode, PortForwardMode::ForwardAndSync);
        cleanup(&path);

        let path = write_fixture("pf-legacy-forward", "[port_forwarding]\nenabled = true\n");
        let loaded = load(&path).expect("legacy config should load");
        assert_eq!(loaded.port_forwarding.mode, PortForwardMode::Forward);
        cleanup(&path);

        // An explicit mode always wins over legacy flags.
        let path = write_fixture(
            "pf-mode-wins",
            "[port_forwarding]\nmode = \"forward\"\nenabled = true\n[qbittorrent]\nenabled = true\n",
        );
        let loaded = load(&path).expect("config should load");
        assert_eq!(loaded.port_forwarding.mode, PortForwardMode::Forward);
        cleanup(&path);

        // Explicit `mode = "disabled"` is a real choice, not an absent mode:
        // stale legacy flags must not promote it.
        let path = write_fixture(
            "pf-explicit-disabled-wins",
            "[port_forwarding]\nmode = \"disabled\"\nenabled = true\n[qbittorrent]\nenabled = true\n",
        );
        let loaded = load(&path).expect("config should load");
        assert_eq!(loaded.port_forwarding.mode, PortForwardMode::Disabled);
        cleanup(&path);
    }

    #[test]
    fn roundtrips_qbittorrent_config() {
        let path = unique_path("qbittorrent-config");
        let config = AppConfig {
            port_forwarding: PortForwardConfig {
                mode: PortForwardMode::ForwardAndSync,
                ..Default::default()
            },
            qbittorrent: QBittorrentConfig {
                url: "http://192.168.1.50:8080".to_string(),
                username: Some("admin".to_string()),
                password: Some("secret123".to_string()),
                bind_interface: true,
                ..Default::default()
            },
            ..AppConfig::default()
        };

        save(&path, &config).expect("config should save");
        let loaded = load(&path).expect("config should load");

        assert_eq!(loaded.port_forwarding.mode, PortForwardMode::ForwardAndSync);
        assert_eq!(loaded.qbittorrent.url, "http://192.168.1.50:8080");
        assert_eq!(loaded.qbittorrent.username.as_deref(), Some("admin"));
        assert_eq!(loaded.qbittorrent.password.as_deref(), Some("secret123"));
        assert!(loaded.qbittorrent.bind_interface);
        let (host, port) = split_webui_url(&loaded.qbittorrent.url);
        assert_eq!((host.as_str(), port.as_str()), ("192.168.1.50", "8080"));
        assert_eq!(
            join_webui_url("http://127.0.0.1:8080/qbittorrent", "10.0.0.2", "9090"),
            "http://10.0.0.2:9090/qbittorrent"
        );
        cleanup(&path);
    }

    #[test]
    fn roundtrips_port_forwarding_config() {
        let path = unique_path("port-forwarding-config");
        let default_cfg = AppConfig::default();
        assert_eq!(default_cfg.port_forwarding.mode, PortForwardMode::Disabled);

        let config = AppConfig {
            port_forwarding: PortForwardConfig {
                mode: PortForwardMode::Forward,
                ..Default::default()
            },
            ..AppConfig::default()
        };

        save(&path, &config).expect("config should save");
        let loaded = load(&path).expect("config should load");
        assert_eq!(loaded.port_forwarding.mode, PortForwardMode::Forward);
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
