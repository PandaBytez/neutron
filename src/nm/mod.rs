use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

mod autoconnect;
mod kill_switch;

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

impl ProfileDiagnostics {
    pub fn unavailable(interface_name: String) -> Self {
        Self {
            interface_name,
            public_key: "N/A".to_string(),
            endpoint: "N/A".to_string(),
            allowed_ips: "N/A".to_string(),
            latest_handshake: "N/A".to_string(),
            transfer_rx: "N/A".to_string(),
            transfer_tx: "N/A".to_string(),
            keepalive: "N/A".to_string(),
        }
    }
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
    /// WireGuard profile. The startup-random selector requires autoconnect to be
    /// disabled so NetworkManager does not activate profiles itself at boot --
    /// otherwise every profile comes up automatically and the selector is left
    /// nothing to do. See [`crate::nm::autoconnect`] for the rationale.
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
    /// Open the native NetworkManager connection editor for the specified connection.
    fn edit_connection(&self, uuid: &str, is_dark: bool) -> AppResult<()>;
    /// Permanently delete a NetworkManager profile. NetworkManager deactivates
    /// the connection first if it is currently active. Any Neutron-side metadata
    /// that referenced the profile (provider comments, startup eligibility) is
    /// cleaned up too so stale entries don't accumulate.
    fn delete_profile(&self, uuid: &str) -> AppResult<()>;
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
        run_nmcli(&["connection", "up", &profile.uuid])?;
        Ok(())
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

        run_nmcli(&["connection", "up", &target.uuid])?;
        Ok(())
    }

    fn set_kill_switch_all(&self, enable: bool) -> AppResult<()> {
        let profiles = self.list_wireguard_profiles()?;
        for args in kill_switch_arg_batches(&profiles, enable) {
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

        let before_profiles = self.list_wireguard_profiles().unwrap_or_default();
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

        let after_profiles = self.list_wireguard_profiles().unwrap_or_default();
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
            if !comments.is_empty()
                && let Ok(config_path) = crate::config::default_config_path()
                && let Ok(mut app_cfg) = crate::config::load(&config_path)
            {
                app_cfg.profile_custom_info.insert(uuid, comments);
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
        let nm_output = run_nmcli(&[
            "-g",
            "connection.interface-name",
            "connection",
            "show",
            uuid,
        ])?;

        let interface_name = parse_interface_name(&nm_output).ok_or_else(|| {
            AppError::NmCommandFailed("No interface name configured for this profile".to_string())
        })?;

        let mut diag = ProfileDiagnostics::unavailable(interface_name.clone());

        if !is_active {
            return Ok(diag);
        }

        let wg_output = run_command_with_timeout(
            "wg",
            &["show", &interface_name, "dump"],
            Duration::from_secs(5),
        );

        let wg_stdout = match wg_output {
            Ok(out) => out,
            Err(_) => return Ok(diag),
        };

        let mut lines = wg_stdout.lines();
        if let Some(first_line) = lines.next() {
            let cols: Vec<&str> = first_line.split('\t').collect();
            if cols.len() >= 2 {
                diag.public_key = cols[1].to_string();
            }
        }
        if let Some(second_line) = lines.next() {
            let cols: Vec<&str> = second_line.split('\t').collect();
            if cols.len() >= 8 {
                diag.endpoint = cols[2].to_string();
                diag.allowed_ips = cols[3].to_string();
                if let Ok(ts) = cols[4].parse::<u64>() {
                    if ts > 0 {
                        diag.latest_handshake = format_handshake_time(ts);
                    } else {
                        diag.latest_handshake = "Never".to_string();
                    }
                }
                if let Ok(rx) = cols[5].parse::<u64>() {
                    diag.transfer_rx = format_bytes(rx);
                }
                if let Ok(tx) = cols[6].parse::<u64>() {
                    diag.transfer_tx = format_bytes(tx);
                }
                diag.keepalive = cols[7].to_string();
            }
        }

        Ok(diag)
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

    fn edit_connection(&self, uuid: &str, is_dark: bool) -> AppResult<()> {
        let (theme, scheme) = if is_dark {
            ("Adwaita:dark", "prefer-dark")
        } else {
            ("Adwaita:light", "prefer-light")
        };
        host_command_with_env(
            "nm-connection-editor",
            &[("GTK_THEME", theme), ("ADW_DEBUG_COLOR_SCHEME", scheme)],
        )
        .arg("-e")
        .arg(uuid)
        .spawn()?;
        Ok(())
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
        if let Some(endpoint) = parse_endpoint(&token) {
            endpoints.push(endpoint);
        }
    }
    endpoints
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

/// Build the per-profile `nmcli` argument batches that apply (`enable`) or
/// remove the kill switch across *every* profile.
///
/// Extracted from [`CliNmClient::set_kill_switch_all`] so the "global = every
/// profile" behavior is unit-testable without invoking `nmcli`.
fn kill_switch_arg_batches(profiles: &[WireguardProfile], enable: bool) -> Vec<Vec<String>> {
    profiles
        .iter()
        .map(|profile| kill_switch::set_args(&profile.uuid, enable))
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

/// Run one argument batch per profile, continuing past failures, then report
/// every failure together.
///
/// Aborting on the first error would leave all *later* profiles unmodified. For
/// `connection.autoconnect` that is the difference between one profile still
/// autoconnecting and every profile after the failure still autoconnecting --
/// and each of those activates at the next boot, because WireGuard profiles are
/// separate interfaces and never compete for a device. Partial success is
/// strictly better than stopping halfway.
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

    Err(AppError::NmCommandFailed(format!(
        "failed on {} of {} profiles: {}",
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
    run_command_with_timeout("nmcli", args, timeout)
}

/// Build a [`Command`] for `program` to execute on the system.
pub(crate) fn host_command(program: &str) -> Command {
    Command::new(program)
}

/// Like [`host_command`], but also sets environment variables on the process.
pub(crate) fn host_command_with_env(program: &str, envs: &[(&str, &str)]) -> Command {
    let mut command = Command::new(program);
    command.envs(envs.iter().copied());
    command
}

pub(crate) fn format_command_error(
    prefix: &str,
    status: std::process::ExitStatus,
    stderr: &str,
) -> String {
    let stderr = stderr.trim();
    let code = status
        .code()
        .map(|code| code.to_string())
        .unwrap_or_else(|| "terminated by signal".to_string());
    if stderr.is_empty() {
        format!("{prefix} (exit {code})")
    } else {
        format!("{stderr} (exit {code})")
    }
}

fn run_command_with_timeout(program: &str, args: &[&str], timeout: Duration) -> AppResult<String> {
    let mut command = host_command(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;

    // Drain stdout/stderr on separate threads so a large amount of output
    // cannot fill the pipe buffers and deadlock the child while we wait.
    let mut stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| AppError::NmCommandFailed(format!("{program} stdout unavailable")))?;
    let mut stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| AppError::NmCommandFailed(format!("{program} stderr unavailable")))?;

    let stdout_reader = thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buffer);
        buffer
    });
    let stderr_reader = thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buffer);
        buffer
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(AppError::NmCommandFailed(format!(
                "{program} {args:?} timed out after {}s",
                timeout.as_secs()
            )));
        }
        thread::sleep(Duration::from_millis(20));
    };

    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();

    if !status.success() {
        let stderr_str = String::from_utf8_lossy(&stderr);
        let prefix = format!("{program} {args:?} failed");
        return Err(AppError::NmCommandFailed(format_command_error(
            &prefix,
            status,
            &stderr_str,
        )));
    }

    Ok(String::from_utf8_lossy(&stdout).trim().to_string())
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

        let batches = kill_switch_arg_batches(&profiles, true);

        // One batch per profile: the kill switch is global, so every profile is
        // modified, each targeting its own UUID with the enable arguments.
        assert_eq!(batches.len(), 3);
        for (batch, uuid) in batches.iter().zip(["uuid-1", "uuid-2", "uuid-3"]) {
            assert_eq!(batch, &kill_switch::set_args(uuid, true));
        }
    }

    #[test]
    fn kill_switch_arg_batches_target_every_profile_to_disable() {
        let profiles = vec![profile("wg-us", "uuid-1"), profile("wg-eu", "uuid-2")];

        let batches = kill_switch_arg_batches(&profiles, false);

        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0], kill_switch::set_args("uuid-1", false));
        assert_eq!(batches[1], kill_switch::set_args("uuid-2", false));
    }

    #[test]
    fn kill_switch_arg_batches_is_empty_without_profiles() {
        // No profiles means no `nmcli` calls at all (rather than an error).
        assert!(kill_switch_arg_batches(&[], true).is_empty());
        assert!(kill_switch_arg_batches(&[], false).is_empty());
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
                return Err(AppError::NmCommandFailed("simulated".to_string()));
            }
            Ok(())
        });

        assert_eq!(attempted, vec!["uuid-1", "uuid-2", "uuid-3"]);
        assert!(result.is_err(), "the failure must still be reported");
    }

    #[test]
    fn apply_to_every_profile_reports_all_failures_with_profile_identity() {
        let profiles = vec![profile("wg-us", "uuid-1"), profile("wg-eu", "uuid-2")];
        let batches = autoconnect_arg_batches(&profiles, false);

        let result = apply_to_every_profile(&profiles, batches, |_| {
            Err(AppError::NmCommandFailed("simulated".to_string()))
        });

        let Err(AppError::NmCommandFailed(message)) = result else {
            panic!("expected an aggregated NmCommandFailed error");
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

    #[cfg(unix)]
    #[test]
    fn command_timeout_kills_long_running_process() {
        let start = Instant::now();
        let result = run_command_with_timeout("sleep", &["10"], Duration::from_millis(150));

        assert!(
            matches!(result, Err(AppError::NmCommandFailed(message)) if message.contains("timed out"))
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "timeout should return promptly instead of waiting for the process"
        );
    }

    #[cfg(unix)]
    #[test]
    fn command_success_returns_trimmed_stdout() {
        let result = run_command_with_timeout("printf", &["hello"], Duration::from_secs(5))
            .expect("printf should succeed");

        assert_eq!(result, "hello");
    }

    #[cfg(unix)]
    #[test]
    fn command_failure_includes_exit_code() {
        let result = run_command_with_timeout("false", &[], Duration::from_secs(5));

        assert!(matches!(
            result,
            Err(AppError::NmCommandFailed(message)) if message.contains("exit 1")
        ));
    }

    #[test]
    fn host_command_creates_command_for_program() {
        let command = host_command("nmcli");

        assert_eq!(command.get_program(), "nmcli");
        assert_eq!(command.get_args().count(), 0);
    }

    #[test]
    fn host_command_with_env_sets_env_on_command() {
        let command = host_command_with_env("pkexec", &[("SHELL", "/bin/sh")]);

        assert_eq!(command.get_program(), "pkexec");
        assert_eq!(command.get_args().count(), 0);
        let envs: Vec<_> = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_str().expect("env key should be valid UTF-8"),
                    value.map(|value| value.to_str().expect("env value should be valid UTF-8")),
                )
            })
            .collect();
        assert_eq!(envs, [("SHELL", Some("/bin/sh"))]);
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
