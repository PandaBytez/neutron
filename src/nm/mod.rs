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
}
