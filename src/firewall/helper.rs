//! Root-owned, refresh-only copy installed during an authenticated lockdown toggle.
//! It derives allowances from NetworkManager, never accepts rules from the caller,
//! and cannot enable or disable lockdown. Permanent rules authorize refreshes.

use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use super::*;
use crate::nm::{NmIntrospect, NmLifecycle};

pub const NAME: &str = "neutron-lockdown-helper";
pub(super) const PATH: &str = "/usr/local/libexec/neutron-lockdown-helper";
pub(super) const LOCK_PATH: &str = "/run/neutron-lockdown.lock";
const ACTION_ID: &str = "io.github.pandabytez.neutron.lockdown-refresh";
const LEGACY_POLICY_PATH: &str = "/etc/polkit-1/rules.d/49-neutron-lockdown-refresh.rules";
/// Action directory polkit only reads at startup (see [`action_directory`]).
const LOCAL_ACTION_DIR: &str = "/usr/local/share/polkit-1/actions";
/// The directory older polkit releases read. Never written by a current install,
/// but swept by [`uninstall_script`] so a downgrade cannot leave a live grant.
const SHARED_ACTION_DIR: &str = "/usr/share/polkit-1/actions";

pub(super) fn install_script() -> AppResult<String> {
    let executable = std::env::current_exe()?;
    let executable = executable
        .to_str()
        .ok_or_else(|| AppError::Firewall("Neutron executable path is not valid UTF-8".into()))?;
    let version = crate::process::run_with_timeout(
        "pkaction",
        &["--version"],
        std::time::Duration::from_secs(5),
    )?;
    let action_dir = action_directory(&version)?;
    let action_path = format!("{action_dir}/{ACTION_ID}.policy");
    let policy_start = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="{ACTION_ID}">
    <description>Refresh existing Neutron lockdown rules</description>
    <message>Refresh existing Neutron lockdown rules</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>yes</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">"#
    );
    let policy_end = "</annotate>\n  </action>\n</policyconfig>\n";
    // A newly created local actions directory may not invalidate polkit's
    // cache. Reload the authority by its D-Bus owner's PID, not by process name.
    let reload = if action_dir == LOCAL_ACTION_DIR {
        polkit_reload()
    } else {
        ""
    };
    // Replace atomically: another process may still be executing the old copy.
    // pkexec resolves symlinks before matching exec.path (e.g. /usr/local on
    // Fedora Atomic), so record the installed helper's canonical path.
    Ok(format!(
        "install -d -m 755 /usr/local/libexec\n\
         install -m 755 -- {} {PATH}.new\n\
         mv -f -- {PATH}.new {PATH}\n\
         helper_path=$(readlink -f -- {PATH})\n\
         helper_path_xml=$(printf %s \"$helper_path\" | sed 's/&/\\&amp;/g; s/</\\&lt;/g; s/>/\\&gt;/g')\n\
         install -d -m 755 {action_dir}\n\
         printf %s {} \"$helper_path_xml\" {} > {action_path}.new\n\
         chmod 644 {action_path}.new\n\
         mv -f -- {action_path}.new {action_path}\n\
         rm -f -- {LEGACY_POLICY_PATH}\n\
         {reload}\
         attempt=0\n\
         until pkaction --action-id {ACTION_ID} >/dev/null 2>&1; do\n\
           attempt=$((attempt + 1))\n\
           if [ \"$attempt\" -ge 5 ]; then pkaction --action-id {ACTION_ID} >&2; exit 1; fi\n\
           sleep 1\n\
         done\n\
         if [ -d /run/systemd/system ]; then systemctl enable firewalld.service; fi\n",
        shell_quote(executable),
        shell_quote(&policy_start),
        shell_quote(policy_end),
    ))
}

/// Ask the running polkit authority to drop its cached action files, by the
/// D-Bus owner's PID rather than by process name.
fn polkit_reload() -> &'static str {
    "polkit_reply=$(dbus-send --system --print-reply --dest=org.freedesktop.DBus \
     /org/freedesktop/DBus org.freedesktop.DBus.GetConnectionUnixProcessID \
     string:org.freedesktop.PolicyKit1)\n\
     polkit_pid=${polkit_reply##*uint32 }\n\
     case \"$polkit_pid\" in ''|*[!0-9]*) echo 'Invalid polkit daemon PID' >&2; exit 1;; esac\n\
     kill -HUP \"$polkit_pid\"\n"
}

/// Every root-owned file an install leaves behind, none of which any package
/// manager owns -- so they outlive the app unless teardown revokes them.
///
/// Order is revoke-then-delete: the polkit authorization goes first, so the
/// binary is never briefly reachable through a policy that outlives it.
fn installed_files() -> [String; 3] {
    [
        format!("{LOCAL_ACTION_DIR}/{ACTION_ID}.policy"),
        format!("{SHARED_ACTION_DIR}/{ACTION_ID}.policy"),
        PATH.to_string(),
    ]
}

/// Whether any installed helper or polkit action is still on disk. Unprivileged
/// `stat`, so callers can gate a teardown on it without prompting.
pub(super) fn is_installed() -> bool {
    installed_files()
        .iter()
        .any(|path| Path::new(path).exists())
}

/// The teardown's top-level shell statements, one per entry.
///
/// Best effort by design, and only at the top level: a failure must not abort
/// teardown under `set -e` on a read-only or immutable `/usr/local`, because a
/// hard error would leave the user reading a scary message after their firewall
/// is already open. [`is_installed`] reports real leftovers to the caller
/// instead. Acquiring the lock *does* still abort on failure, deliberately --
/// without it a concurrent refresh could re-add rules after the teardown.
///
/// The reload is guarded as one subshell for the same reason, and it is not
/// dead work: the action's `exec.path` is a fixed path, so a cached action that
/// outlives the file would authorize whatever executable lands there next.
fn uninstall_statements() -> Vec<String> {
    let mut statements: Vec<String> = installed_files()
        .iter()
        .map(|file| format!("rm -f -- {file} || true"))
        .collect();
    statements.push(format!("({}) || true", polkit_reload()));
    statements
}

/// Render [`uninstall_statements`] into a script for the disable/uninstall batch.
///
/// Both action directories are swept without probing the installed polkit
/// version: `rm -f` on a missing path succeeds, so a wrong guess costs nothing.
pub(super) fn uninstall_script() -> String {
    let mut script = String::new();
    for statement in uninstall_statements() {
        script.push_str(&statement);
        script.push('\n');
    }
    script
}

fn action_directory(version: &str) -> AppResult<&'static str> {
    let release = version
        .split_whitespace()
        .last()
        .and_then(|value| {
            value
                .strip_prefix("0.")
                .unwrap_or(value)
                .parse::<u32>()
                .ok()
        })
        .ok_or_else(|| AppError::Firewall(format!("Unrecognized polkit version: {version}")))?;
    // Local action directories were added in polkit 126. Older releases only
    // read /usr/share; newer ones can also install on immutable /usr systems.
    Ok(if release >= 126 {
        LOCAL_ACTION_DIR
    } else {
        SHARED_ACTION_DIR
    })
}

fn authorization_command() -> std::process::Command {
    let mut command = crate::process::host_command("pkcheck");
    // Unprivileged callers cannot supply --detail, even for their own process.
    // The dedicated action binds pkexec to the helper without caller details.
    command
        .args([
            "--action-id",
            ACTION_ID,
            "--process",
            &std::process::id().to_string(),
        ])
        .stdin(Stdio::null());
    command
}

/// Invoke only the narrowly authorized helper; never fall back to a password prompt.
pub(super) fn refresh(activating: Option<&str>) -> AppResult<()> {
    // Older installations already have permanent protection. They can keep using
    // matching rules until the next explicit enable installs the helper.
    if !std::path::Path::new(PATH).exists() {
        let tunnels = tunnels(activating)?;
        if refresh_batches(&tunnels)?.is_empty() {
            return Ok(());
        }
        return Err(AppError::Firewall(
            "Lockdown rules need refreshing. Run `neutron lockdown enable` once to install \
             the password-free refresh helper; existing protection remains in place."
                .into(),
        ));
    }
    // pkexec's flag only disables its *terminal* agent. Check authorization
    // without AllowUserInteraction first, so a missing action cannot open a GUI prompt.
    let authorization = authorization_command().output()?;
    if !authorization.status.success() {
        let detail = crate::process::format_command_error(
            "pkcheck denied authorization",
            authorization.status,
            &String::from_utf8_lossy(&authorization.stderr),
        );
        return Err(AppError::Firewall(format!(
            "Password-free lockdown refresh is unavailable: {detail}. \
             Run `neutron lockdown enable` once from an active local session to install \
             or repair authorization; existing protection remains in place."
        )));
    }
    let mut child = crate::process::host_command_with_env("pkexec", &[("SHELL", "/bin/sh")])
        .arg("--disable-internal-agent")
        .arg(std::fs::canonicalize(PATH)?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(activating.unwrap_or("").as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(AppError::Firewall(crate::process::format_command_error(
            "Lockdown refresh failed; run `neutron lockdown enable` to repair the helper",
            output.status,
            &String::from_utf8_lossy(&output.stderr),
        )))
    }
}

/// Entry point for the installed executable. Arguments cannot select other app actions.
pub fn run() -> AppResult<()> {
    // No caller-controlled command lookup in this privileged process.
    // SAFETY: main invokes the helper before starting any threads.
    unsafe { std::env::set_var("PATH", "/usr/sbin:/usr/bin:/sbin:/bin") };
    let mut requested = String::new();
    std::io::stdin().take(37).read_to_string(&mut requested)?;
    if !requested.is_empty()
        && (requested.len() != 36
            || !requested.bytes().enumerate().all(|(i, byte)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            }))
    {
        return Err(AppError::Firewall("Invalid activation UUID".into()));
    }
    let lock = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(LOCK_PATH)?;
    lock.lock()?;
    // Check while holding the same lock as authenticated toggles. A delayed
    // refresh can never undo a disable, even when user config still says ON.
    if marked_removal_batches()?.is_empty() {
        return Ok(());
    }
    let tunnels = tunnels((!requested.is_empty()).then_some(requested.as_str()))?;
    let batches = refresh_batches(&tunnels)?;
    if batches.is_empty() {
        return Ok(());
    }
    run_script(&build_firewall_script(&batches), false)
}

fn tunnels(activating: Option<&str>) -> AppResult<Vec<WireguardTunnel>> {
    let client = crate::nm::CliNmClient;
    let mut tunnels = client.wireguard_tunnels()?;
    if let Some(uuid) = activating {
        if !client
            .list_wireguard_profiles()?
            .iter()
            .any(|p| p.uuid == uuid)
        {
            return Err(AppError::Firewall(
                "Unknown WireGuard activation UUID".into(),
            ));
        }
        let interface = client.tunnel_interface(uuid).ok_or_else(|| {
            AppError::Firewall("WireGuard activation has no configured interface".into())
        })?;
        for tunnel in &mut tunnels {
            if tunnel.interface.as_ref() == Some(&interface) {
                tunnel.is_active = true;
            }
        }
    }
    Ok(tunnels)
}

fn refresh_batches(tunnels: &[WireguardTunnel]) -> AppResult<Vec<Vec<String>>> {
    let desired = lockdown_enable_batches(tunnels);
    let permanent = marked_removal_batches()?;
    let runtime: Vec<_> = runtime_removal_batches()?
        .into_iter()
        .map(|mut batch| {
            batch.insert(0, "--permanent".into());
            batch
        })
        .collect();
    let mut batches = Vec::new();
    for (current, is_permanent) in [(permanent, true), (runtime, false)] {
        if rules_match(&current, &desired) {
            continue;
        }
        let rebuild = lockdown_rebuild_batches(current, tunnels);
        batches.extend(rebuild.into_iter().map(|mut batch| {
            if !is_permanent {
                batch.remove(0);
            }
            batch
        }));
    }
    Ok(batches)
}

fn rules_match(removals: &[Vec<String>], desired: &[Vec<String>]) -> bool {
    let installed: std::collections::BTreeSet<_> = removals.iter().map(|b| &b[3..]).collect();
    let desired: std::collections::BTreeSet<_> = desired.iter().map(|b| &b[3..]).collect();
    installed == desired
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_check_is_unprivileged_and_noninteractive() {
        let command = authorization_command();
        assert_eq!(command.get_program(), "pkcheck");
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(
            args,
            [
                "--action-id",
                ACTION_ID,
                "--process",
                &std::process::id().to_string(),
            ]
        );
    }

    #[test]
    fn action_directory_supports_old_polkit_and_immutable_usr() {
        for version in ["pkaction version 0.105", "pkaction version 125"] {
            assert_eq!(
                action_directory(version).unwrap(),
                "/usr/share/polkit-1/actions"
            );
        }
        for version in ["pkaction version 126", "pkaction version 127\n"] {
            assert_eq!(
                action_directory(version).unwrap(),
                "/usr/local/share/polkit-1/actions"
            );
        }
        assert!(action_directory("unexpected output").is_err());
        assert!(action_directory("").is_err());
    }

    #[test]
    fn teardown_revokes_every_installed_file_and_never_aborts() {
        let statements = uninstall_statements();

        // Every path an install writes must be swept, whatever polkit version
        // wrote it, and the authorization must go before the binary it allows.
        let revoked: Vec<_> = statements
            .iter()
            .filter_map(|statement| statement.strip_prefix("rm -f -- "))
            .map(|statement| statement.trim_end_matches(" || true"))
            .collect();
        assert_eq!(revoked, installed_files());
        assert!(
            revoked[0].ends_with(".policy") && revoked[1].ends_with(".policy"),
            "authorization is revoked first: {revoked:?}"
        );
        assert_eq!(*revoked.last().unwrap(), PATH);

        // Every top-level statement is best effort, so `set -e` cannot abort
        // teardown before `is_installed` reports a real leftover.
        for statement in &statements {
            assert!(
                statement.ends_with("|| true"),
                "unguarded teardown statement: {statement}"
            );
        }
        // And the script is exactly those statements, nothing smuggled between.
        assert_eq!(
            uninstall_script(),
            format!("{}\n", statements.join("\n")),
            "the script must not add unguarded commands"
        );
    }

    #[test]
    fn restored_rules_are_a_noop_but_dns_changes_and_missing_rules_are_not() {
        let disconnected = lockdown_enable_batches(&[]);
        let mut restored: Vec<_> = disconnected
            .iter()
            .map(|b| {
                let mut b = b.clone();
                b[2] = "--remove-rule".into();
                b
            })
            .collect();
        restored.reverse();
        assert!(rules_match(&restored, &disconnected));
        let connected = lockdown_enable_batches(&[WireguardTunnel {
            interface: Some("wg0".into()),
            is_active: true,
            ..Default::default()
        }]);
        assert!(!rules_match(&restored, &connected));
        restored.pop();
        assert!(!rules_match(&restored, &disconnected));
        assert!(!rules_match(&[], &disconnected));
    }
}
