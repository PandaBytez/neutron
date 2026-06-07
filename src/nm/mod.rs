use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

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
        run_nmcli(&[
            "connection",
            "import",
            "type",
            "wireguard",
            "file",
            path_str,
        ])
    }

    fn get_profile_diagnostics(
        &self,
        uuid: &str,
        is_active: bool,
    ) -> AppResult<ProfileDiagnostics> {
        let nm_output = run_command_with_timeout(
            "nmcli",
            &[
                "-g",
                "connection.interface-name",
                "connection",
                "show",
                uuid,
            ],
            NMCLI_TIMEOUT,
        )?;

        let interface_name = parse_interface_name(&nm_output).ok_or_else(|| {
            AppError::NmCommandFailed("No interface name configured for this profile".to_string())
        })?;

        let mut diag = ProfileDiagnostics {
            interface_name: interface_name.clone(),
            public_key: "N/A".to_string(),
            endpoint: "N/A".to_string(),
            allowed_ips: "N/A".to_string(),
            latest_handshake: "N/A".to_string(),
            transfer_rx: "N/A".to_string(),
            transfer_tx: "N/A".to_string(),
            keepalive: "N/A".to_string(),
        };

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
        .map(|profile| {
            if enable {
                kill_switch::enable_args(&profile.uuid)
            } else {
                kill_switch::disable_args(&profile.uuid)
            }
        })
        .collect()
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

/// Returns `true` when the process is running inside a Flatpak sandbox.
///
/// Flatpak always mounts `/.flatpak-info` inside the sandbox, so its presence
/// is the canonical way to detect that host tools must be reached through the
/// session helper rather than executed directly.
fn running_in_flatpak_sandbox() -> bool {
    std::path::Path::new("/.flatpak-info").exists()
}

/// Build a [`Command`] for `program`, transparently routing through
/// `flatpak-spawn --host` when running inside a Flatpak sandbox.
///
/// Host tools such as `nmcli` are not shipped inside the GNOME runtime, so when
/// sandboxed we ask the Flatpak session helper to run them on the host instead.
/// Outside a sandbox the program is executed directly.
pub(crate) fn host_command(program: &str) -> Command {
    host_command_for(running_in_flatpak_sandbox(), program)
}

fn host_command_for(in_sandbox: bool, program: &str) -> Command {
    if in_sandbox {
        let mut command = Command::new("flatpak-spawn");
        command.arg("--host").arg(program);
        command
    } else {
        Command::new(program)
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
        let stderr = String::from_utf8_lossy(&stderr).trim().to_string();
        let code = status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "terminated by signal".to_string());
        return Err(AppError::NmCommandFailed(if stderr.is_empty() {
            format!("{program} {args:?} failed (exit {code})")
        } else {
            format!("{stderr} (exit {code})")
        }));
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
            assert_eq!(batch, &kill_switch::enable_args(uuid));
        }
    }

    #[test]
    fn kill_switch_arg_batches_target_every_profile_to_disable() {
        let profiles = vec![profile("wg-us", "uuid-1"), profile("wg-eu", "uuid-2")];

        let batches = kill_switch_arg_batches(&profiles, false);

        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0], kill_switch::disable_args("uuid-1"));
        assert_eq!(batches[1], kill_switch::disable_args("uuid-2"));
    }

    #[test]
    fn kill_switch_arg_batches_is_empty_without_profiles() {
        // No profiles means no `nmcli` calls at all (rather than an error).
        assert!(kill_switch_arg_batches(&[], true).is_empty());
        assert!(kill_switch_arg_batches(&[], false).is_empty());
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
    fn sandbox_routes_through_flatpak_spawn() {
        let command = host_command_for(true, "nmcli");

        assert_eq!(command.get_program(), "flatpak-spawn");
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_str().expect("args should be valid UTF-8"))
            .collect();
        assert_eq!(args, ["--host", "nmcli"]);
    }

    #[test]
    fn non_sandbox_runs_program_directly() {
        let command = host_command_for(false, "nmcli");

        assert_eq!(command.get_program(), "nmcli");
        assert_eq!(command.get_args().count(), 0);
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
}
