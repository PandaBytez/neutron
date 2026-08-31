use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

pub(crate) mod autoconnect;
pub mod health;
pub mod kill_switch;
pub mod network_info;
pub mod split_tunnel;
pub mod tunnel_routing;

/// Maximum time to wait for an `nmcli` invocation before giving up.
///
/// NetworkManager operations are normally fast, but a stuck daemon or hung
/// network operation must not block the caller (and, in the GUI, the main
/// thread) indefinitely.
const NMCLI_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProfileState {
    Active,
    Inactive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardProfile {
    pub name: String,
    pub uuid: String,
    pub state: ProfileState,
}

impl WireguardProfile {
    pub fn is_active(&self) -> bool {
        self.state == ProfileState::Active
    }
}

/// A peer endpoint (`host:port`) that a WireGuard tunnel connects out to.
///
/// Lockdown needs these so the *encrypted* handshake is still allowed to leave
/// the physical interface while every other non-tunnel packet is blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

/// The lockdown-relevant details of a WireGuard profile: the tunnel interface
/// (so *decrypted* traffic is allowed once the tunnel is up) and the peer
/// endpoints (so the handshake can reach the server while locked down).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WireguardTunnel {
    pub interface: Option<String>,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileDiagnostics {
    pub interface_name: String,
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: String,
    pub latest_handshake: String,
    pub transfer_rx: String,
    pub transfer_tx: String,
    pub keepalive: String,
}

pub trait NmClient {
    fn list_wireguard_profiles(&self) -> AppResult<Vec<WireguardProfile>>;
    fn connect(&self, profile_identifier: &str) -> AppResult<()>;
    fn disconnect_active(&self) -> AppResult<()>;
    fn switch_to(&self, profile_identifier: &str) -> AppResult<()>;
    /// Apply (or remove) the kill-switch routing policy on *every* WireGuard
    /// profile. The kill switch is a global setting, so this is enforced across
    /// all profiles rather than per profile. The change is persisted to each
    /// NetworkManager profile and takes effect the next time it is activated.
    fn set_kill_switch_all(&self, enable: bool) -> AppResult<()>;
    /// Set NetworkManager's `connection.autoconnect` property on *every*
    /// WireGuard profile. Only ever called with `false`: the app issues every
    /// activation explicitly, so NM must never bring a profile up on its own.
    /// Left alone, each profile carries NM's `autoconnect=yes` default and they
    /// all activate together at boot. See [`crate::nm::autoconnect`].
    fn set_autoconnect_all(&self, enable: bool) -> AppResult<()>;
    /// Discover the interface name and peer endpoints of every WireGuard
    /// profile. Used to build the lockdown firewall allow-list so the tunnel
    /// and its handshake keep working while all other traffic is blocked.
    fn wireguard_tunnels(&self) -> AppResult<Vec<WireguardTunnel>>;
    /// Import a WireGuard configuration file as a new NetworkManager profile,
    /// returning NetworkManager's confirmation message. Keeps NetworkManager the
    /// single source of truth (no local copy of the config is kept).
    fn import_wireguard_profile(&self, path: &std::path::Path) -> AppResult<String>;
    /// Get read-only WireGuard diagnostics for a specific profile connection.
    fn get_profile_diagnostics(&self, uuid: &str, is_active: bool)
    -> AppResult<ProfileDiagnostics>;
    /// The tunnel's local IPv4 address (e.g. `10.2.0.2/32`), used to derive the
    /// NAT-PMP gateway that hands out a forwarded port.
    fn tunnel_address(&self, uuid: &str) -> Option<String>;
    /// The tunnel's configured DNS servers (e.g. `10.2.0.1`).
    fn tunnel_dns(&self, uuid: &str) -> Option<String>;
    /// Permanently delete a NetworkManager profile. NetworkManager deactivates
    /// the connection first if it is currently active. Any Neutron-side metadata
    /// that referenced the profile (provider comments, startup eligibility) is
    /// cleaned up too so stale entries don't accumulate.
    fn delete_profile(&self, uuid: &str) -> AppResult<()>;
    /// Apply split-tunnel routing rules to *every* WireGuard profile.
    fn apply_split_tunnel_all(
        &self,
        mode: crate::config::SplitTunnelMode,
        v4_routes: &[String],
        v6_routes: &[String],
    ) -> AppResult<()>;
}

fn extract_interface_comments(path: &std::path::Path) -> String {
    use std::io::BufRead;
    let mut comments = Vec::new();
    if let Ok(file) = std::fs::File::open(path) {
        let reader = std::io::BufReader::new(file);
        let mut in_interface = false;
        for l in reader.lines().map_while(Result::ok) {
            let trimmed = l.trim();
            let lower = trimmed.to_lowercase();
            if lower.starts_with("[interface]") {
                in_interface = true;
                continue;
            }
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                in_interface = false;
                continue;
            }
            if in_interface && (trimmed.starts_with('#') || trimmed.starts_with(';')) {
                let content = trimmed[1..].trim();
                if !content.is_empty() {
                    comments.push(content.to_string());
                }
            }
        }
    }
    comments.join("\n")
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CliNmClient;

impl NmClient for CliNmClient {
    fn list_wireguard_profiles(&self) -> AppResult<Vec<WireguardProfile>> {
        let connections = run_nmcli(&["-t", "-f", "NAME,UUID,TYPE", "connection", "show"])?;
        let active = run_nmcli(&[
            "-t",
            "-f",
            "NAME,UUID,TYPE",
            "connection",
            "show",
            "--active",
        ])?;

        let mut active_uuids = std::collections::HashSet::new();
        for line in active.lines() {
            let (_name, uuid, typ) = parse_nmcli_triplet(line)?;
            if typ == "wireguard" {
                active_uuids.insert(uuid);
            }
        }

        let mut profiles = Vec::new();
        for line in connections.lines() {
            let (name, uuid, typ) = parse_nmcli_triplet(line)?;

            if typ != "wireguard" {
                continue;
            }

            let state = if active_uuids.contains(&uuid) {
                ProfileState::Active
            } else {
                ProfileState::Inactive
            };

            profiles.push(WireguardProfile { name, uuid, state });
        }

        profiles.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(profiles)
    }

    fn connect(&self, profile_identifier: &str) -> AppResult<()> {
        let profiles = self.list_wireguard_profiles()?;
        let profile = find_unique_profile_by_identifier(&profiles, profile_identifier)?;
        activate(&profile.uuid)
    }

    fn disconnect_active(&self) -> AppResult<()> {
        let profiles = self.list_wireguard_profiles()?;
        let active = profiles
            .iter()
            .find(|profile| profile.is_active())
            .ok_or(AppError::NoActiveProfile)?;

        run_nmcli(&["connection", "down", &active.uuid])?;
        Ok(())
    }

    fn switch_to(&self, profile_identifier: &str) -> AppResult<()> {
        let profiles = self.list_wireguard_profiles()?;
        let target = find_unique_profile_by_identifier(&profiles, profile_identifier)?;

        if target.is_active() {
            return Ok(());
        }

        if let Some(active) = profiles.iter().find(|profile| profile.is_active()) {
            run_nmcli(&["connection", "down", &active.uuid])?;
        }

        activate(&target.uuid)
    }

    fn set_kill_switch_all(&self, enable: bool) -> AppResult<()> {
        let profiles = self.list_wireguard_profiles()?;
        // NOTE: unlike `set_autoconnect_all` below, this still aborts on the
        // first failure, so later profiles keep their previous kill-switch
        // value while the caller sees a single error. Converting it to
        // `apply_to_every_profile` is a behavior change to a security-relevant
        // setting and is deliberately left out of the autoconnect fix.
        for args in kill_switch_arg_batches(&profiles, enable, profile_has_ipv6) {
            run_nmcli_owned(&args)?;
        }
        Ok(())
    }

    fn set_autoconnect_all(&self, enable: bool) -> AppResult<()> {
        let profiles = self.list_wireguard_profiles()?;
        let batches = autoconnect_arg_batches(&profiles, enable);
        apply_to_every_profile(&profiles, batches, |args| run_nmcli_owned(args).map(|_| ()))
    }

    fn wireguard_tunnels(&self) -> AppResult<Vec<WireguardTunnel>> {
        let profiles = self.list_wireguard_profiles()?;
        let mut tunnels = Vec::new();
        for profile in &profiles {
            // `-g` (get-values) prints only the property value, so no field
            // prefix has to be stripped.
            let interface = run_nmcli(&[
                "-g",
                "connection.interface-name",
                "connection",
                "show",
                &profile.uuid,
            ])
            .map(|value| parse_interface_name(&value))?;
            let endpoints =
                run_nmcli(&["-g", "wireguard.peers", "connection", "show", &profile.uuid])
                    .map(|value| extract_endpoints(&value))?;
            tunnels.push(WireguardTunnel {
                interface,
                endpoints,
            });
        }
        Ok(tunnels)
    }

    fn import_wireguard_profile(&self, path: &std::path::Path) -> AppResult<String> {
        let path_str = path
            .to_str()
            .ok_or_else(|| AppError::Config("import path is not valid UTF-8".to_string()))?;

        let before_profiles = match self.list_wireguard_profiles() {
            Ok(profiles) => profiles,
            Err(e) => {
                tracing::warn!("failed to list profiles before import of {path_str}: {e}");
                Vec::new()
            }
        };
        let before_uuids: std::collections::HashSet<String> =
            before_profiles.into_iter().map(|p| p.uuid).collect();

        let output = run_nmcli(&[
            "connection",
            "import",
            "type",
            "wireguard",
            "file",
            path_str,
        ])?;

        let after_profiles = match self.list_wireguard_profiles() {
            Ok(profiles) => profiles,
            Err(e) => {
                tracing::warn!("failed to list profiles after import of {path_str}: {e}");
                Vec::new()
            }
        };
        let mut new_uuid = None;
        for p in after_profiles {
            if !before_uuids.contains(&p.uuid) {
                new_uuid = Some(p.uuid);
                break;
            }
        }

        if let Some(uuid) = new_uuid {
            // `nmcli connection import` auto-activates the freshly imported
            // WireGuard connection (autoconnect defaults on). That hijacks an
            // already-active tunnel and flips the new profile's toggle on
            // without the user asking. Bring it straight back down so importing
            // only adds the profile; the user activates it explicitly.
            let _ = run_nmcli(&["connection", "down", uuid.as_str()]);

            // NetworkManager's `autoconnect=yes` default would also bring this
            // profile (and every other) up automatically at the next boot,
            // defeating the startup-random selector. Disable it so activation
            // stays user- and selector-driven. Best-effort: a failure here must
            // not fail the import (the selector re-applies this on every run).
            let _ = run_nmcli_owned(&autoconnect::set_args(uuid.as_str(), false));

            let comments = extract_interface_comments(path);
            if let Ok(config_path) = crate::config::default_config_path()
                && let Ok(mut app_cfg) = crate::config::load(&config_path)
            {
                if !comments.is_empty() {
                    app_cfg.profile_custom_info.insert(uuid.clone(), comments);
                }
                if app_cfg.global_split_tunnel.mode.is_enabled() {
                    let (v4, v6) = split_tunnel::routes_for(
                        app_cfg.global_split_tunnel.mode,
                        &app_cfg.global_split_tunnel.cidrs,
                        &app_cfg.global_split_tunnel.domains,
                    );
                    let _ = run_nmcli_owned(&split_tunnel::set_args(
                        uuid.as_str(),
                        app_cfg.global_split_tunnel.mode,
                        &v4,
                        &v6,
                    ));
                }
                if app_cfg.kill_switch_enabled {
                    let has_ipv6 = profile_has_ipv6(&uuid);
                    let _ = run_nmcli_owned(&kill_switch::set_args(uuid.as_str(), true, has_ipv6));
                }
                let _ = crate::config::save(&config_path, &app_cfg);
            }
        }

        Ok(output)
    }

    fn get_profile_diagnostics(
        &self,
        uuid: &str,
        is_active: bool,
    ) -> AppResult<ProfileDiagnostics> {
        let settings = parse_peer_settings(&run_nmcli(&["-s", "connection", "show", uuid])?);
        let interface_name = settings
            .interface_name
            .clone()
            .unwrap_or_else(|| uuid.to_string());
        let mut diagnostics = settings_to_diagnostics(&settings, interface_name.clone(), is_active);

        if !is_active {
            return Ok(diagnostics);
        }

        // `wg show` reports the live link, so it wins over the stored profile.
        match crate::process::run_with_timeout(
            "wg",
            &["show", &interface_name, "dump"],
            Duration::from_secs(2),
        ) {
            Ok(dump) => overlay_wg_dump(&mut diagnostics, &dump),
            // `wg` is optional (read-only diagnostics), so fall back to the
            // kernel's own byte counters for the interface.
            Err(_) => {
                let (rx, tx) = network_info::read_interface_bytes(Some(&interface_name));
                if rx > 0 || tx > 0 {
                    diagnostics.transfer_rx = format_bytes(rx);
                    diagnostics.transfer_tx = format_bytes(tx);
                }
            }
        }

        Ok(diagnostics)
    }

    fn tunnel_address(&self, uuid: &str) -> Option<String> {
        let output = run_nmcli(&["-g", "ipv4.addresses", "connection", "show", uuid]).ok()?;
        // A profile may carry several addresses; the first is the tunnel host.
        let first = output.split(',').next()?.trim();
        if first.is_empty() {
            return None;
        }
        Some(first.to_string())
    }

    fn tunnel_dns(&self, uuid: &str) -> Option<String> {
        let output = run_nmcli(&["-g", "ipv4.dns", "connection", "show", uuid]).ok()?;
        let trimmed = output.trim();
        if trimmed.is_empty() || trimmed == "--" {
            return None;
        }
        Some(trimmed.replace(',', ", "))
    }

    fn delete_profile(&self, uuid: &str) -> AppResult<()> {
        // NetworkManager deactivates the connection automatically before
        // removing it, so an active profile can be deleted directly.
        run_nmcli(&["connection", "delete", uuid])?;

        // Drop any Neutron-side metadata keyed by this UUID so it doesn't linger
        // after the profile is gone. Best-effort: a config failure here must not
        // mask the successful deletion.
        if let Ok(config_path) = crate::config::default_config_path()
            && let Ok(mut app_cfg) = crate::config::load(&config_path)
        {
            let changed = crate::config::forget_profile(&mut app_cfg, uuid);
            if changed {
                let _ = crate::config::save(&config_path, &app_cfg);
            }
        }

        Ok(())
    }

    fn apply_split_tunnel_all(
        &self,
        mode: crate::config::SplitTunnelMode,
        v4_routes: &[String],
        v6_routes: &[String],
    ) -> AppResult<()> {
        let profiles = self.list_wireguard_profiles()?;
        let batches = split_tunnel_arg_batches(&profiles, mode, v4_routes, v6_routes);
        apply_to_every_profile(&profiles, batches, |args| run_nmcli_owned(args).map(|_| ()))
    }
}

/// The peer fields Neutron reads out of `nmcli -s connection show <uuid>`.
///
/// Every field is optional because a profile may legitimately omit it, and
/// because NetworkManager prints `--` for unset values.
#[derive(Debug, Default, PartialEq, Eq)]
struct PeerSettings {
    interface_name: Option<String>,
    public_key: Option<String>,
    endpoint: Option<String>,
    allowed_ips: Option<String>,
    keepalive: Option<String>,
}

/// Parse the `connection.interface-name` and `wireguard.peers` lines out of
/// `nmcli -s connection show` output.
///
/// Split out of `get_profile_diagnostics` so the parsing can be tested without
/// invoking `nmcli`.
fn parse_peer_settings(output: &str) -> PeerSettings {
    let mut settings = PeerSettings::default();

    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if value == "--" || value.is_empty() {
            continue;
        }

        match key {
            "connection.interface-name" => settings.interface_name = Some(value.to_string()),
            "wireguard.peers" => {
                let mut tokens = value.split_whitespace().peekable();
                // The peer's public key is printed bare, before the `k=v`
                // pairs; a leading token containing `=` means it is absent.
                if let Some(first) = tokens.peek()
                    && !first.contains('=')
                {
                    settings.public_key = Some((*first).to_string());
                }
                for token in tokens {
                    if let Some(endpoint) = token.strip_prefix("endpoint=") {
                        settings.endpoint = Some(endpoint.to_string());
                    } else if let Some(ips) = token.strip_prefix("allowed-ips=") {
                        settings.allowed_ips = Some(ips.replace(';', ", "));
                    } else if let Some(keepalive) = token.strip_prefix("persistent-keepalive=") {
                        settings.keepalive = Some(keepalive.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    settings
}

/// Render parsed settings as diagnostics, filling unset fields with the
/// placeholders the UI expects.
fn settings_to_diagnostics(
    settings: &PeerSettings,
    interface_name: String,
    is_active: bool,
) -> ProfileDiagnostics {
    fn or_na(value: &Option<String>) -> String {
        value.clone().unwrap_or_else(|| "N/A".to_string())
    }

    ProfileDiagnostics {
        interface_name,
        public_key: or_na(&settings.public_key),
        endpoint: or_na(&settings.endpoint),
        allowed_ips: settings
            .allowed_ips
            .clone()
            .unwrap_or_else(|| "0.0.0.0/0, ::/0".to_string()),
        latest_handshake: if is_active {
            "Active"
        } else {
            "Inactive (Standby)"
        }
        .to_string(),
        transfer_rx: "0 B".to_string(),
        transfer_tx: "0 B".to_string(),
        keepalive: or_na(&settings.keepalive),
    }
}

/// Overlay live link statistics from `wg show <iface> dump` onto `diagnostics`.
///
/// The dump's first line describes the interface and the second the first peer,
/// both tab separated. Fields that are absent, empty or `(none)` leave the
/// profile-derived value in place.
fn overlay_wg_dump(diagnostics: &mut ProfileDiagnostics, dump: &str) {
    let mut lines = dump.lines();

    if let Some(interface_line) = lines.next() {
        let columns: Vec<&str> = interface_line.split('\t').collect();
        if let Some(public_key) = columns.get(1).filter(|value| !value.is_empty()) {
            diagnostics.public_key = (*public_key).to_string();
        }
    }

    let Some(peer_line) = lines.next() else {
        return;
    };
    let columns: Vec<&str> = peer_line.split('\t').collect();
    if columns.len() < 8 {
        return;
    }

    let present = |index: usize| -> Option<&str> {
        columns
            .get(index)
            .copied()
            .filter(|value| !value.is_empty() && *value != "(none)")
    };

    if let Some(endpoint) = present(2) {
        diagnostics.endpoint = endpoint.to_string();
    }
    if let Some(allowed_ips) = present(3) {
        diagnostics.allowed_ips = allowed_ips.to_string();
    }
    if let Some(timestamp) = present(4).and_then(|value| value.parse::<u64>().ok())
        && timestamp > 0
    {
        diagnostics.latest_handshake = format_handshake_time(timestamp);
    }
    if let Some(rx) = present(5).and_then(|value| value.parse::<u64>().ok()) {
        diagnostics.transfer_rx = format_bytes(rx);
    }
    if let Some(tx) = present(6).and_then(|value| value.parse::<u64>().ok()) {
        diagnostics.transfer_tx = format_bytes(tx);
    }
    if let Some(keepalive) = present(7).filter(|value| *value != "off") {
        diagnostics.keepalive = keepalive.to_string();
    }
}

pub fn format_handshake_time(timestamp: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now >= timestamp {
        let diff = now - timestamp;
        if diff < 60 {
            format!("{}s ago", diff)
        } else if diff < 3600 {
            format!("{}m {}s ago", diff / 60, diff % 60)
        } else {
            format!("{}h {}m ago", diff / 3600, (diff % 3600) / 60)
        }
    } else {
        "Just now".to_string()
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.2} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Interpret a single `nmcli -g connection.interface-name` value, returning
/// `None` when NetworkManager reports no interface name (empty or `--`).
fn parse_interface_name(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "--" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Pull every `endpoint = host:port` out of an `nmcli` `wireguard.peers` value.
///
/// The peer description format varies between NetworkManager versions (spacing
/// around `=`, trailing `,`/`;`), so this scans tolerantly: it finds each
/// `endpoint` marker, skips an optional `=` and whitespace, then reads the
/// address token up to the next delimiter.
fn extract_endpoints(text: &str) -> Vec<Endpoint> {
    let mut endpoints = Vec::new();
    for segment in text.split("endpoint").skip(1) {
        let token: String = segment
            .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
            .chars()
            .take_while(|c| !matches!(c, ' ' | '\t' | '\n' | '\r' | ',' | ';'))
            .collect();
        if let Some(endpoint) = parse_endpoint(&unescape_nmcli(&token)) {
            endpoints.push(endpoint);
        }
    }
    endpoints
}

/// Strip nmcli's backslash escaping from a terse-output field.
///
/// `nmcli -g` escapes its separator characters, so a peer endpoint arrives as
/// `1.2.3.4\:51820`. Left in place, the trailing backslash on the host makes it
/// fail to parse as an IP address, and the endpoint gets treated as a hostname
/// -- which the firewall can only allow by destination port, opening UDP/51820
/// to *every* host instead of pinning the VPN peer.
fn unescape_nmcli(token: &str) -> String {
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // A trailing lone backslash is dropped rather than preserved: it is
            // malformed input either way, and keeping it would break parsing.
            if let Some(escaped) = chars.next() {
                out.push(escaped);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Parse a single `host:port` endpoint token, handling bracketed IPv6 literals
/// (`[::1]:51820`). Returns `None` for malformed tokens or invalid ports.
fn parse_endpoint(token: &str) -> Option<Endpoint> {
    let (host, port) = if let Some(rest) = token.strip_prefix('[') {
        // Bracketed IPv6 literal: `[addr]:port`.
        let (host, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        (host, port)
    } else {
        // IPv4 or hostname: the port follows the last colon.
        token.rsplit_once(':')?
    };

    if host.is_empty() {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    Some(Endpoint {
        host: host.to_string(),
        port,
    })
}

/// Check whether a profile has IPv6 method enabled (not disabled/ignore/empty).
fn profile_has_ipv6(uuid: &str) -> bool {
    let method = run_nmcli(&["-g", "ipv6.method", "connection", "show", uuid]).unwrap_or_default();
    let trimmed = method.trim();
    !trimmed.is_empty() && trimmed != "disabled" && trimmed != "ignore" && trimmed != "--"
}

/// Build the per-profile `nmcli` argument batches that apply (`enable`) or
/// remove the kill switch across *every* profile.
///
/// Extracted from [`CliNmClient::set_kill_switch_all`] so the "global = every
/// profile" behavior is unit-testable without invoking `nmcli`.
fn kill_switch_arg_batches<F>(
    profiles: &[WireguardProfile],
    enable: bool,
    mut has_ipv6: F,
) -> Vec<Vec<String>>
where
    F: FnMut(&str) -> bool,
{
    profiles
        .iter()
        .map(|profile| kill_switch::set_args(&profile.uuid, enable, has_ipv6(&profile.uuid)))
        .collect()
}

/// Build the per-profile `nmcli` argument batches that set
/// `connection.autoconnect` across *every* profile.
///
/// Extracted from [`CliNmClient::set_autoconnect_all`] so the "global = every
/// profile" behavior is unit-testable without invoking `nmcli`.
fn autoconnect_arg_batches(profiles: &[WireguardProfile], enable: bool) -> Vec<Vec<String>> {
    profiles
        .iter()
        .map(|profile| autoconnect::set_args(&profile.uuid, enable))
        .collect()
}

/// Build the per-profile `nmcli` argument batches that set split tunneling
/// configuration across *every* profile.
fn split_tunnel_arg_batches(
    profiles: &[WireguardProfile],
    mode: crate::config::SplitTunnelMode,
    v4_routes: &[String],
    v6_routes: &[String],
) -> Vec<Vec<String>> {
    profiles
        .iter()
        .map(|profile| split_tunnel::set_args(&profile.uuid, mode, v4_routes, v6_routes))
        .collect()
}

/// Run one argument batch per profile, continuing past failures, then report
/// every failure together.
///
/// These settings are global -- "on" means "on for every profile" -- so a sweep
/// that aborts on the first error leaves the system silently inconsistent: the
/// profiles after the failure keep their old value while the caller reports a
/// single generic error. Applying to all of them and reporting the failures
/// together is strictly more useful.
///
/// `connection.autoconnect` is the motivating case: giving up early leaves every
/// later profile on NetworkManager's `autoconnect=yes` default, and each of
/// those activates at the next boot, because WireGuard profiles are separate
/// interfaces and never compete for a device.
///
/// `run` is injected so the continue-on-failure behavior is unit-testable
/// without invoking `nmcli`.
fn apply_to_every_profile<F>(
    profiles: &[WireguardProfile],
    batches: Vec<Vec<String>>,
    mut run: F,
) -> AppResult<()>
where
    F: FnMut(&[String]) -> AppResult<()>,
{
    // Callers derive `batches` from `profiles`, so the two are the same length
    // by construction. `zip` would silently skip the surplus otherwise, and the
    // "N of M" count below would understate how many profiles went untouched.
    debug_assert_eq!(
        profiles.len(),
        batches.len(),
        "one argument batch is required per profile"
    );

    let failures: Vec<String> = profiles
        .iter()
        .zip(batches)
        .filter_map(|(profile, args)| {
            run(&args)
                .err()
                .map(|error| format!("{} ({}): {error}", profile.name, profile.uuid))
        })
        .collect();

    if failures.is_empty() {
        return Ok(());
    }

    // No "failed" prefix here: `AppError::CommandFailed` already renders as
    // "command failed: ...", and each entry carries its own
    // cause.
    Err(AppError::CommandFailed(format!(
        "{} of {} profiles rejected the change: {}",
        failures.len(),
        profiles.len(),
        failures.join("; ")
    )))
}

fn find_unique_profile_by_name<'a>(
    profiles: &'a [WireguardProfile],
    profile_name: &str,
) -> AppResult<&'a WireguardProfile> {
    let mut matches = profiles
        .iter()
        .filter(|profile| profile.name == profile_name);
    let first = matches
        .next()
        .ok_or_else(|| AppError::ProfileNotFound(profile_name.to_string()))?;
    if matches.next().is_some() {
        return Err(AppError::AmbiguousProfileName(profile_name.to_string()));
    }
    Ok(first)
}

/// Resolve a profile by UUID first, then by unique name.
///
/// Returns [`AppError::ProfileNotFound`] when no profile matches, or
/// [`AppError::AmbiguousProfileName`] when a name matches more than one profile.
pub fn find_unique_profile_by_identifier<'a>(
    profiles: &'a [WireguardProfile],
    profile_identifier: &str,
) -> AppResult<&'a WireguardProfile> {
    if let Some(profile) = profiles
        .iter()
        .find(|profile| profile.uuid == profile_identifier)
    {
        return Ok(profile);
    }

    find_unique_profile_by_name(profiles, profile_identifier)
}

fn parse_nmcli_triplet(line: &str) -> AppResult<(String, String, String)> {
    let fields = parse_nmcli_fields(line);
    if fields.len() != 3 {
        return Err(AppError::NmParseFailed(line.to_string()));
    }
    Ok((fields[0].clone(), fields[1].clone(), fields[2].clone()))
}

fn parse_nmcli_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut escaped = false;

    for ch in line.chars() {
        if escaped {
            field.push(ch);
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        if ch == ':' {
            fields.push(field);
            field = String::new();
            continue;
        }

        field.push(ch);
    }

    if escaped {
        field.push('\\');
    }

    fields.push(field);
    fields
}

/// Bring connection `uuid` up, first making sure it will actually route
/// traffic.
///
/// NetworkManager's `default` for automatic default-route handling was observed
/// installing no routes at all, so a profile that has never been through a
/// kill-switch sweep -- a fresh import, one added through GNOME Settings, or one
/// left behind by an older version -- would activate and carry nothing while
/// reporting success. Pinning it here means any profile repairs itself the first
/// time it is used; see [`tunnel_routing`].
///
/// The pin is best-effort: if NetworkManager rejects the change the activation
/// still proceeds, because refusing to connect at all is worse than connecting
/// with whatever routing NetworkManager chooses. The failure is logged so the
/// cause is visible.
///
/// Once up, the tunnel is verified (see [`health`]) and taken back down if the
/// peer never completes a handshake. Now that a full tunnel owns the default
/// route, a peer that never answers would otherwise swallow every packet while
/// the UI reported a working connection.
fn activate(uuid: &str) -> AppResult<()> {
    let has_ipv6 = profile_has_ipv6(uuid);
    if let Err(error) = run_nmcli_owned(&tunnel_routing::set_args(uuid, has_ipv6)) {
        tracing::warn!("could not pin automatic default-route handling on {uuid}: {error}");
    }
    // Also apply global kill switch setting and refresh split-tunnel routes (BUG-016, BUG-017)
    if let Ok(config_path) = crate::config::default_config_path()
        && let Ok(app_cfg) = crate::config::load(&config_path)
    {
        let _ = run_nmcli_owned(&kill_switch::set_args(
            uuid,
            app_cfg.kill_switch_enabled,
            has_ipv6,
        ));
        if app_cfg.global_split_tunnel.mode.is_enabled() {
            let (v4, v6) = split_tunnel::routes_for(
                app_cfg.global_split_tunnel.mode,
                &app_cfg.global_split_tunnel.cidrs,
                &app_cfg.global_split_tunnel.domains,
            );
            let _ = run_nmcli_owned(&split_tunnel::set_args(
                uuid,
                app_cfg.global_split_tunnel.mode,
                &v4,
                &v6,
            ));
        }
    }
    // Whether the interface already exists is sampled *before* activation: a
    // fresh one starts its receive counter at zero, which is what makes that
    // counter a handshake signal. See `health`.
    let interface = tunnel_interface_name(uuid);
    let existed = interface
        .as_deref()
        .map(health::interface_exists)
        .unwrap_or(false);

    run_nmcli(&["connection", "up", uuid])?;
    verify_or_disconnect(uuid, interface.as_deref(), existed)
}

/// The interface name configured on profile `uuid`, if it has a usable one.
fn tunnel_interface_name(uuid: &str) -> Option<String> {
    run_nmcli(&[
        "-g",
        "connection.interface-name",
        "connection",
        "show",
        uuid,
    ])
    .ok()
    .and_then(|value| parse_interface_name(&value))
}

/// Whether the health check is enabled. Defaults to on, including when the
/// config cannot be read -- a missing config must not silently disable a safety
/// check.
fn health_check_enabled() -> bool {
    crate::config::default_config_path()
        .and_then(|path| crate::config::load(&path))
        .map(|config| config.general.verify_tunnel_on_connect)
        .unwrap_or(true)
}

/// Confirm the peer behind `uuid` completed a handshake, deactivating the
/// tunnel and reporting an error when it did not.
///
/// `interface` and `existed_before` must have been sampled *before* activation.
fn verify_or_disconnect(
    uuid: &str,
    interface: Option<&str>,
    existed_before: bool,
) -> AppResult<()> {
    if !health_check_enabled() {
        return Ok(());
    }

    // Without an interface name there is nothing to sample; treat that as
    // healthy rather than tearing down a connection on a technicality.
    let Some(interface) = interface else {
        return Ok(());
    };

    // The interface was already up before this call, so its receive counter
    // holds another activation's traffic and cannot be read as this one's
    // handshake. Reconnecting a profile that is already connected is not a new
    // tunnel to verify, and guessing here would disconnect a working one.
    if existed_before {
        return Ok(());
    }

    if health::probe(interface).is_healthy() {
        return Ok(());
    }

    // Roll the activation back so the dead tunnel stops owning the default
    // route. Best-effort: report the diagnosis even if the teardown fails,
    // since that is the actionable part.
    if let Err(error) = run_nmcli(&["connection", "down", uuid]) {
        tracing::warn!("could not deactivate unhealthy tunnel {uuid}: {error}");
    }

    Err(AppError::TunnelUnhealthy(format!(
        "{interface}: the peer never completed a handshake (server down, or the \
         profile's keys are no longer valid). Disconnected so it does not \
         black-hole your traffic."
    )))
}

fn run_nmcli(args: &[&str]) -> AppResult<String> {
    run_nmcli_with_timeout(args, NMCLI_TIMEOUT)
}

/// Convenience wrapper around [`run_nmcli`] for dynamically built argument
/// lists (such as the kill-switch `connection modify` commands).
fn run_nmcli_owned(args: &[String]) -> AppResult<String> {
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_nmcli(&arg_refs)
}

fn run_nmcli_with_timeout(args: &[&str], timeout: Duration) -> AppResult<String> {
    crate::process::run_with_timeout("nmcli", args, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, uuid: &str) -> WireguardProfile {
        WireguardProfile {
            name: name.to_string(),
            uuid: uuid.to_string(),
            state: ProfileState::Inactive,
        }
    }

    #[test]
    fn returns_not_found_for_missing_name() {
        let profiles = vec![profile("wg-us", "uuid-1")];

        let result = find_unique_profile_by_name(&profiles, "wg-eu");

        assert!(matches!(result, Err(AppError::ProfileNotFound(name)) if name == "wg-eu"));
    }

    #[test]
    fn returns_ambiguous_for_duplicate_name() {
        let profiles = vec![profile("wg-us", "uuid-1"), profile("wg-us", "uuid-2")];

        let result = find_unique_profile_by_name(&profiles, "wg-us");

        assert!(matches!(
            result,
            Err(AppError::AmbiguousProfileName(name)) if name == "wg-us"
        ));
    }

    #[test]
    fn returns_matching_profile_for_unique_name() {
        let profiles = vec![profile("wg-us", "uuid-1"), profile("wg-eu", "uuid-2")];

        let result =
            find_unique_profile_by_name(&profiles, "wg-eu").expect("unique profile should resolve");

        assert_eq!(result.uuid, "uuid-2");
    }

    #[test]
    fn returns_profile_by_uuid_identifier() {
        let profiles = vec![profile("wg-us", "uuid-1"), profile("wg-eu", "uuid-2")];

        let result = find_unique_profile_by_identifier(&profiles, "uuid-2")
            .expect("uuid should resolve directly");

        assert_eq!(result.name, "wg-eu");
    }

    #[test]
    fn parses_escaped_colons_in_nmcli_output() {
        let line = r"wg\:us:uuid-1:wireguard";

        let parsed = parse_nmcli_triplet(line).expect("line should parse");

        assert_eq!(parsed.0, "wg:us");
        assert_eq!(parsed.1, "uuid-1");
        assert_eq!(parsed.2, "wireguard");
    }

    #[test]
    fn fails_on_invalid_nmcli_triplet() {
        let result = parse_nmcli_triplet("only-two:fields");

        assert!(matches!(result, Err(AppError::NmParseFailed(_))));
    }

    #[test]
    fn preserves_trailing_backslash_in_nmcli_fields() {
        let fields = parse_nmcli_fields(r"value\");

        assert_eq!(fields, vec![r"value\".to_string()]);
    }

    #[test]
    fn interface_name_treats_empty_and_dash_as_absent() {
        assert_eq!(parse_interface_name("wg0"), Some("wg0".to_string()));
        // nmcli prints surrounding whitespace that must be trimmed.
        assert_eq!(parse_interface_name("  wg0  "), Some("wg0".to_string()));
        // An empty value or the `--` placeholder means "no interface set".
        assert_eq!(parse_interface_name(""), None);
        assert_eq!(parse_interface_name("--"), None);
    }

    #[test]
    fn extracts_ipv4_endpoint_from_peer_value() {
        let endpoints = extract_endpoints("endpoint = 1.2.3.4:51820, allowed-ips = 0.0.0.0/0");

        assert_eq!(
            endpoints,
            vec![Endpoint {
                host: "1.2.3.4".to_string(),
                port: 51820,
            }]
        );
    }

    #[test]
    fn extracts_multiple_peer_endpoints() {
        // NetworkManager lists each peer; every `endpoint` marker is collected.
        let endpoints = extract_endpoints("endpoint=1.2.3.4:51820; endpoint=vpn.example.com:1194;");

        assert_eq!(
            endpoints,
            vec![
                Endpoint {
                    host: "1.2.3.4".to_string(),
                    port: 51820,
                },
                Endpoint {
                    host: "vpn.example.com".to_string(),
                    port: 1194,
                },
            ]
        );
    }

    #[test]
    fn extracts_bracketed_ipv6_endpoint() {
        // Bracketed IPv6 literals must keep the address intact (the port follows
        // the closing bracket, not the last colon inside the address).
        let endpoints = extract_endpoints("endpoint = [2001:db8::1]:51820");

        assert_eq!(
            endpoints,
            vec![Endpoint {
                host: "2001:db8::1".to_string(),
                port: 51820,
            }]
        );
    }

    #[test]
    fn ignores_peers_without_endpoints() {
        assert!(extract_endpoints("allowed-ips = 0.0.0.0/0").is_empty());
    }

    #[test]
    fn extracts_nmcli_escaped_ip_endpoint_as_a_pinnable_literal() {
        // Regression: `nmcli -g` escapes the port separator, so the host kept a
        // trailing backslash, failed to parse as an IP, and was treated as a
        // hostname -- which lockdown could only allow by port, opening
        // UDP/51820 to every host instead of just the VPN peer.
        let raw = "KEY= allowed-ips=0.0.0.0/0;\\:\\:/0 endpoint=79.127.154.1\\:51820 persistent-keepalive=25";

        let endpoints = extract_endpoints(raw);

        assert_eq!(endpoints.len(), 1, "{endpoints:?}");
        assert_eq!(endpoints[0].host, "79.127.154.1");
        assert_eq!(endpoints[0].port, 51820);
        assert!(
            endpoints[0].host.parse::<std::net::IpAddr>().is_ok(),
            "host must parse as an IP so the firewall can pin it"
        );
    }

    #[test]
    fn unescape_nmcli_removes_escapes_and_keeps_plain_text() {
        assert_eq!(unescape_nmcli("1.2.3.4\\:51820"), "1.2.3.4:51820");
        assert_eq!(
            unescape_nmcli("[2001\\:db8\\:\\:1]\\:51820"),
            "[2001:db8::1]:51820"
        );
        assert_eq!(
            unescape_nmcli("vpn.example.com:1194"),
            "vpn.example.com:1194"
        );
        // A literal backslash arrives doubled.
        assert_eq!(unescape_nmcli("a\\\\b"), "a\\b");
    }

    #[test]
    fn parse_endpoint_rejects_malformed_tokens() {
        // Missing port, empty host, and non-numeric port are all rejected.
        assert_eq!(parse_endpoint("1.2.3.4"), None);
        assert_eq!(parse_endpoint(":51820"), None);
        assert_eq!(parse_endpoint("host:notaport"), None);
        assert_eq!(parse_endpoint("[2001:db8::1]"), None);
    }

    #[test]
    fn kill_switch_arg_batches_target_every_profile_to_enable() {
        let profiles = vec![
            profile("wg-us", "uuid-1"),
            profile("wg-eu", "uuid-2"),
            profile("wg-as", "uuid-3"),
        ];

        let batches = kill_switch_arg_batches(&profiles, true, |_| false);

        // One batch per profile: the kill switch is global, so every profile is
        // modified, each targeting its own UUID with the enable arguments.
        assert_eq!(batches.len(), 3);
        for (batch, uuid) in batches.iter().zip(["uuid-1", "uuid-2", "uuid-3"]) {
            assert_eq!(batch, &kill_switch::set_args(uuid, true, false));
        }
    }

    #[test]
    fn kill_switch_arg_batches_target_every_profile_to_disable() {
        let profiles = vec![profile("wg-us", "uuid-1"), profile("wg-eu", "uuid-2")];

        let batches = kill_switch_arg_batches(&profiles, false, |_| false);

        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0], kill_switch::set_args("uuid-1", false, false));
        assert_eq!(batches[1], kill_switch::set_args("uuid-2", false, false));
    }

    #[test]
    fn kill_switch_arg_batches_is_empty_without_profiles() {
        // No profiles means no `nmcli` calls at all (rather than an error).
        assert!(kill_switch_arg_batches(&[], true, |_| false).is_empty());
        assert!(kill_switch_arg_batches(&[], false, |_| false).is_empty());
    }

    #[test]
    fn autoconnect_arg_batches_target_every_profile_to_disable() {
        let profiles = vec![
            profile("wg-us", "uuid-1"),
            profile("wg-eu", "uuid-2"),
            profile("wg-as", "uuid-3"),
        ];

        let batches = autoconnect_arg_batches(&profiles, false);

        // One batch per profile: autoconnect is a global concern, so every
        // profile is modified, each targeting its own UUID.
        assert_eq!(batches.len(), 3);
        for (batch, uuid) in batches.iter().zip(["uuid-1", "uuid-2", "uuid-3"]) {
            assert_eq!(batch, &autoconnect::set_args(uuid, false));
        }
    }

    #[test]
    fn autoconnect_arg_batches_target_every_profile_to_enable() {
        let profiles = vec![profile("wg-us", "uuid-1"), profile("wg-eu", "uuid-2")];

        let batches = autoconnect_arg_batches(&profiles, true);

        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0], autoconnect::set_args("uuid-1", true));
        assert_eq!(batches[1], autoconnect::set_args("uuid-2", true));
    }

    #[test]
    fn autoconnect_arg_batches_is_empty_without_profiles() {
        // No profiles means no `nmcli` calls at all (rather than an error).
        assert!(autoconnect_arg_batches(&[], true).is_empty());
        assert!(autoconnect_arg_batches(&[], false).is_empty());
    }

    #[test]
    fn apply_to_every_profile_continues_after_a_failure() {
        // Regression: aborting on the first failure left every later profile on
        // NetworkManager's `autoconnect=yes` default, so all of them activated
        // at the next boot.
        let profiles = vec![
            profile("wg-us", "uuid-1"),
            profile("wg-eu", "uuid-2"),
            profile("wg-jp", "uuid-3"),
        ];
        let batches = autoconnect_arg_batches(&profiles, false);
        let mut attempted = Vec::new();

        let result = apply_to_every_profile(&profiles, batches, |args| {
            let uuid = args[2].clone();
            attempted.push(uuid.clone());
            if uuid == "uuid-1" {
                return Err(AppError::CommandFailed("simulated".to_string()));
            }
            Ok(())
        });

        assert_eq!(attempted, vec!["uuid-1", "uuid-2", "uuid-3"]);

        let Err(AppError::CommandFailed(message)) = result else {
            panic!("the failure must still be reported");
        };
        // Numerator and denominator differ here, so a swapped or off-by-one
        // count cannot pass.
        assert!(message.contains("1 of 3"), "got: {message}");
        assert!(message.contains("wg-us"), "got: {message}");
        assert!(
            !message.contains("wg-eu") && !message.contains("wg-jp"),
            "profiles that succeeded must not be listed: {message}"
        );
    }

    #[test]
    fn apply_to_every_profile_reports_all_failures_with_profile_identity() {
        let profiles = vec![profile("wg-us", "uuid-1"), profile("wg-eu", "uuid-2")];
        let batches = autoconnect_arg_batches(&profiles, false);

        let result = apply_to_every_profile(&profiles, batches, |_| {
            Err(AppError::CommandFailed("simulated".to_string()))
        });

        let Err(AppError::CommandFailed(message)) = result else {
            panic!("expected an aggregated CommandFailed error");
        };
        assert!(message.contains("2 of 2 profiles"), "got: {message}");
        assert!(message.contains("wg-us (uuid-1)"), "got: {message}");
        assert!(message.contains("wg-eu (uuid-2)"), "got: {message}");
    }

    #[test]
    fn apply_to_every_profile_is_ok_when_every_batch_succeeds() {
        let profiles = vec![profile("wg-us", "uuid-1"), profile("wg-eu", "uuid-2")];
        let batches = autoconnect_arg_batches(&profiles, false);
        let mut calls = 0;

        let result = apply_to_every_profile(&profiles, batches, |_| {
            calls += 1;
            Ok(())
        });

        assert_eq!(calls, 2);
        assert!(result.is_ok());
    }

    #[test]
    fn parses_peer_settings_from_nmcli_output() {
        let output = "connection.interface-name:            wg0\n\
                      wireguard.peers:                     PUBKEY= endpoint=1.2.3.4:51820 allowed-ips=0.0.0.0/0;::/0 persistent-keepalive=25\n\
                      ipv4.method:                         manual\n";

        let settings = parse_peer_settings(output);

        assert_eq!(settings.interface_name.as_deref(), Some("wg0"));
        assert_eq!(settings.endpoint.as_deref(), Some("1.2.3.4:51820"));
        assert_eq!(settings.allowed_ips.as_deref(), Some("0.0.0.0/0, ::/0"));
        assert_eq!(settings.keepalive.as_deref(), Some("25"));
        // The bare leading token is the peer key; a `k=v` token is not.
        assert_eq!(settings.public_key, None);
    }

    #[test]
    fn parses_bare_public_key_and_treats_dashes_as_unset() {
        let settings = parse_peer_settings(
            "connection.interface-name:  --\nwireguard.peers:  abc123 endpoint=host:51820\n",
        );

        assert_eq!(settings.interface_name, None, "`--` means unset");
        assert_eq!(settings.public_key.as_deref(), Some("abc123"));
        assert_eq!(settings.endpoint.as_deref(), Some("host:51820"));
    }

    #[test]
    fn diagnostics_fall_back_to_placeholders_for_unset_fields() {
        let diagnostics =
            settings_to_diagnostics(&PeerSettings::default(), "wg0".to_string(), false);

        assert_eq!(diagnostics.public_key, "N/A");
        assert_eq!(diagnostics.endpoint, "N/A");
        assert_eq!(diagnostics.keepalive, "N/A");
        // An unset allowed-ips means a full tunnel, not an unknown value.
        assert_eq!(diagnostics.allowed_ips, "0.0.0.0/0, ::/0");
        assert_eq!(diagnostics.latest_handshake, "Inactive (Standby)");
    }

    #[test]
    fn wg_dump_overlays_live_link_statistics() {
        let mut diagnostics =
            settings_to_diagnostics(&PeerSettings::default(), "wg0".to_string(), true);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should move forward")
            .as_secs();
        let dump = format!(
            "privkey\tifacekey\t51820\toff\n\
             peerkey\tpsk\t9.9.9.9:51820\t10.0.0.0/8\t{now}\t2048\t1024\t25\n"
        );

        overlay_wg_dump(&mut diagnostics, &dump);

        assert_eq!(diagnostics.public_key, "ifacekey");
        assert_eq!(diagnostics.endpoint, "9.9.9.9:51820");
        assert_eq!(diagnostics.allowed_ips, "10.0.0.0/8");
        assert_eq!(diagnostics.transfer_rx, "2.00 KiB");
        assert_eq!(diagnostics.transfer_tx, "1.00 KiB");
        assert_eq!(diagnostics.keepalive, "25");
        assert!(diagnostics.latest_handshake.ends_with("ago"));
    }

    #[test]
    fn wg_dump_placeholders_leave_profile_values_untouched() {
        let settings = PeerSettings {
            endpoint: Some("profile.example:51820".to_string()),
            keepalive: Some("15".to_string()),
            ..PeerSettings::default()
        };
        let mut diagnostics = settings_to_diagnostics(&settings, "wg0".to_string(), true);

        // `(none)`, empty columns, a zero handshake and `off` all mean "no live
        // value", so the profile-derived ones must survive.
        overlay_wg_dump(
            &mut diagnostics,
            "privkey\t\t51820\toff\npeerkey\t\t(none)\t\t0\t0\t0\toff\n",
        );

        assert_eq!(diagnostics.endpoint, "profile.example:51820");
        assert_eq!(diagnostics.keepalive, "15");
        assert_eq!(diagnostics.latest_handshake, "Active");
        assert_eq!(diagnostics.transfer_rx, "0 B");
    }

    #[test]
    fn wg_dump_ignores_truncated_output() {
        let mut diagnostics =
            settings_to_diagnostics(&PeerSettings::default(), "wg0".to_string(), true);

        overlay_wg_dump(&mut diagnostics, "privkey\tifacekey\t51820\toff\n");

        assert_eq!(diagnostics.public_key, "ifacekey");
        assert_eq!(diagnostics.transfer_rx, "0 B", "no peer line, no counters");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KiB");
        assert_eq!(format_bytes(1536), "1.50 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GiB");
    }

    #[test]
    fn test_format_handshake_time() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        assert_eq!(format_handshake_time(now), "0s ago");
        assert_eq!(format_handshake_time(now - 10), "10s ago");
        assert_eq!(format_handshake_time(now - 65), "1m 5s ago");
        assert_eq!(format_handshake_time(now - 3665), "1h 1m ago");
        assert_eq!(format_handshake_time(now + 10), "Just now");
    }

    #[test]
    fn test_extract_interface_comments() {
        use std::fs::File;
        use std::io::Write;
        let config_path = std::env::temp_dir().join(format!(
            "neutron-vpn-comments-test-{}.conf",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should move forward")
                .as_nanos()
        ));
        let mut file = File::create(&config_path).unwrap();
        writeln!(file, "[Interface]").unwrap();
        writeln!(file, "# Bouncing: Enabled").unwrap();
        writeln!(file, "; NetShield: Block malware").unwrap();
        writeln!(file, "Address = 10.2.0.2/32").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "[Peer]").unwrap();
        writeln!(file, "PublicKey = abc").unwrap();
        drop(file);

        let comments = extract_interface_comments(&config_path);
        assert_eq!(comments, "Bouncing: Enabled\nNetShield: Block malware");

        let _ = std::fs::remove_file(config_path);
    }
}
