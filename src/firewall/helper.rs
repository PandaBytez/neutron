//! Root-owned, refresh-only copy installed during an authenticated lockdown toggle.
//! It derives allowances from NetworkManager, never accepts rules from the caller,
//! and cannot enable or disable lockdown. Every refresh requires admin authentication.

use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use super::*;
use crate::nm::{NmIntrospect, NmLifecycle};

pub const NAME: &str = "neutron-lockdown-helper";
pub(super) const PATH: &str = "/usr/local/libexec/neutron-lockdown-helper";
pub(super) const LOCK_PATH: &str = "/run/neutron-lockdown.lock";
pub(super) const LOCK_DIR: &str = "/run/neutron-lockdown";
pub(super) const PRIVATE_LOCK_PATH: &str = "/run/neutron-lockdown/lock";
pub(super) const LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const ACTION_ID: &str = "io.github.pandabytez.neutron.lockdown-refresh";
const LEGACY_POLICY_PATH: &str = "/etc/polkit-1/rules.d/49-neutron-lockdown-refresh.rules";
/// Action directory polkit only reads at startup (see [`action_directory`]).
const LOCAL_ACTION_DIR: &str = "/usr/local/share/polkit-1/actions";
/// The directory older polkit releases read. Never written by a current install,
/// but swept by [`uninstall_script`] so a downgrade cannot leave a live grant.
const SHARED_ACTION_DIR: &str = "/usr/share/polkit-1/actions";

pub(super) fn install_script() -> AppResult<String> {
    let version = crate::process::run_with_timeout(
        "pkaction",
        &["--version"],
        std::time::Duration::from_secs(5),
    )?;
    install_script_for(&version, std::process::id())
}

fn install_script_for(version: &str, installer_pid: u32) -> AppResult<String> {
    // The caller blocks in run_script until installation finishes. Linux pins
    // its executable inode even if an attacker replaces the original pathname.
    let executable = format!("/proc/{installer_pid}/exe");
    let source = std::fs::metadata("/proc/self/exe")?;
    let source_identity = format!("{}:{}", source.dev(), source.ino());
    let action_dir = action_directory(version)?;
    let action_path = format!("{action_dir}/{ACTION_ID}.policy");
    let obsolete_dir = if action_dir == LOCAL_ACTION_DIR {
        SHARED_ACTION_DIR
    } else {
        LOCAL_ACTION_DIR
    };
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
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">"#
    );
    let policy_end = "</annotate>\n  </action>\n</policyconfig>\n";
    // A newly created local actions directory may not invalidate polkit's
    // cache. Reload the authority by its D-Bus owner's PID, not by process name.
    let reload = polkit_reload();
    // Replace atomically: another process may still be executing the old copy.
    // pkexec resolves symlinks before matching exec.path (e.g. /usr/local on
    // Fedora Atomic), so record the installed helper's canonical path.
    Ok(format!(
        "exec 8<{}\n\
         [ \"$(stat -Lc '%d:%i' /proc/self/fd/8)\" = {} ] || {{ echo 'Installer executable changed' >&2; exit 1; }}\n\
         install -d -m 755 /usr/local/libexec\n\
         install -m 755 -- /proc/self/fd/8 {PATH}.new\n\
         mv -f -- {PATH}.new {PATH}\n\
         helper_path=$(readlink -f -- {PATH})\n\
         helper_path_xml=$(printf %s \"$helper_path\" | sed 's/&/\\&amp;/g; s/</\\&lt;/g; s/>/\\&gt;/g')\n\
         install -d -m 755 {action_dir}\n\
         printf %s {} \"$helper_path_xml\" {} > {action_path}.new\n\
         chmod 644 {action_path}.new\n\
         mv -f -- {action_path}.new {action_path}\n\
         rm -f -- {obsolete_dir}/{ACTION_ID}.policy\n\
         rm -f -- {LEGACY_POLICY_PATH}\n\
         {reload}\
         attempt=0\n\
         until pkaction --action-id {ACTION_ID} >/dev/null 2>&1; do\n\
           attempt=$((attempt + 1))\n\
           if [ \"$attempt\" -ge 5 ]; then pkaction --action-id {ACTION_ID} >&2; exit 1; fi\n\
           sleep 1\n\
         done\n\
         if [ -d /run/systemd/system ]; then systemctl enable firewalld.service; fi\n",
        shell_quote(&executable),
        shell_quote(&source_identity),
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
fn installed_files() -> [String; 4] {
    [
        format!("{LOCAL_ACTION_DIR}/{ACTION_ID}.policy"),
        format!("{SHARED_ACTION_DIR}/{ACTION_ID}.policy"),
        LEGACY_POLICY_PATH.to_string(),
        PATH.to_string(),
    ]
}

/// Whether any installed helper or polkit action is still on disk. Unprivileged
/// `stat`, so callers can gate a teardown on it without prompting.
pub(super) fn is_installed() -> bool {
    installed_files()
        .iter()
        .any(|path| std::fs::symlink_metadata(path).is_ok())
}

const HARDENED_DEFAULTS: &str = "<defaults><allow_any>no</allow_any><allow_inactive>auth_admin</allow_inactive><allow_active>auth_admin</allow_active></defaults>";

pub(super) fn has_hardened_authorization() -> bool {
    let files = installed_files();
    hardened_authorization_at(
        Path::new(&files[2]),
        &[Path::new(&files[0]), Path::new(&files[1])],
    )
}

fn hardened_authorization_at(legacy: &Path, policies: &[&Path]) -> bool {
    if std::fs::symlink_metadata(legacy).is_ok() {
        return false;
    }
    let mut found = false;
    for path in policies {
        match std::fs::read_to_string(path) {
            Ok(policy) => {
                found = true;
                let compact: String = policy.chars().filter(|c| !c.is_whitespace()).collect();
                if !compact.contains(HARDENED_DEFAULTS)
                    || compact.matches("<defaults>").count() != 1
                {
                    return false;
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && std::fs::symlink_metadata(path).is_err() => {}
            Err(_) => return false,
        }
    }
    found
}

/// Evaluate under the root lock after authentication, so disable never retains
/// a legacy grant introduced while the password prompt was open.
pub(super) fn revoke_unsafe_authorization_script() -> String {
    let files = installed_files();
    revoke_unsafe_authorization_script_for(LEGACY_POLICY_PATH, &files[..2], &uninstall_script())
}

fn revoke_unsafe_authorization_script_for(
    legacy: &str,
    policies: &[String],
    revoke: &str,
) -> String {
    let mut script = format!(
        "hardened=true\nfound=false\n[ ! -e {legacy} ] && [ ! -L {legacy} ] || hardened=false\n",
        legacy = shell_quote(legacy),
    );
    for path in policies {
        script.push_str(&format!(
            "if [ -e {path} ] || [ -L {path} ]; then\n\
               found=true\n\
               policy=$(tr -d '[:space:]' < {path}) || hardened=false\n\
               case \"$policy\" in *'{HARDENED_DEFAULTS}'*) ;; *) hardened=false;; esac\n\
               rest=${{policy#*<defaults>}}\n\
               case \"$rest\" in *'<defaults>'*) hardened=false;; esac\n\
             fi\n",
            path = shell_quote(path),
        ));
    }
    script.push_str("if [ \"$hardened:$found\" != true:true ]; then\n");
    script.push_str(revoke);
    script.push_str("fi\n");
    script
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

/// Invoke the refresh-only helper with fresh administrator authorization.
pub(super) fn refresh(activating: Option<&str>) -> AppResult<()> {
    if is_installed() && !has_hardened_authorization() {
        return Err(AppError::Firewall(
            "Administrator-authenticated lockdown refresh is unavailable. Run `neutron lockdown enable` to upgrade the helper; existing protection remains in place.".into(),
        ));
    }
    // Older installations already have permanent protection. They can keep using
    // matching rules until the next explicit enable installs the helper.
    if !std::path::Path::new(PATH).exists() {
        let tunnels = tunnels(activating)?;
        let desired = lockdown_enable_batches(&tunnels);
        if refresh_batches(&desired)?.is_empty() {
            verify_protection(&desired)?;
            return Ok(());
        }
        return Err(AppError::Firewall(
            "Lockdown rules need refreshing. Run `neutron lockdown enable` once to install \
              the administrator-authenticated refresh helper; existing protection remains in place."
                .into(),
        ));
    }
    let mut child = std::process::Command::new("pkexec")
        .env("SHELL", "/bin/sh")
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
    let identity = crate::process::run_with_timeout("id", &["-u"], LOCK_TIMEOUT)?;
    if identity != "0" {
        return Err(AppError::Firewall(
            "Lockdown refresh requires administrator authorization".into(),
        ));
    }
    if !has_hardened_authorization() {
        return Err(AppError::Firewall("Unsafe lockdown refresh authorization; run `neutron lockdown enable` to migrate legacy grants".into()));
    }
    let mut requested = String::new();
    std::io::stdin().take(37).read_to_string(&mut requested)?;
    if !is_valid_activation_uuid(&requested) {
        return Err(AppError::Firewall("Invalid activation UUID".into()));
    }
    let _lock = acquire_lock(Path::new(LOCK_PATH), 0, LOCK_TIMEOUT)?;
    secure_lock_directory(Path::new(LOCK_DIR), 0)?;
    let _private_lock = acquire_lock(Path::new(PRIVATE_LOCK_PATH), 0, LOCK_TIMEOUT)?;
    // Check while holding the same lock as authenticated toggles. A delayed
    // refresh can never undo a disable, even when user config still says ON.
    if marked_removal_batches()?.is_empty() {
        return absent_protection_result(!requested.is_empty());
    }
    let tunnels = tunnels((!requested.is_empty()).then_some(requested.as_str()))?;
    let desired = lockdown_enable_batches(&tunnels);
    let batches = refresh_batches(&desired)?;
    if !batches.is_empty() {
        run_script(&build_firewall_script(&batches), false)?;
    }
    verify_protection(&desired)
}

fn absent_protection_result(activating: bool) -> AppResult<()> {
    if activating {
        Err(AppError::Firewall(
            "Lockdown protection is absent; activation refused. Run `neutron lockdown enable` to restore protection.".into(),
        ))
    } else {
        Ok(())
    }
}

fn verify_protection(desired: &[Vec<String>]) -> AppResult<()> {
    verify_protection_with(
        desired,
        &marked_removal_batches()?,
        &normalized_runtime_removals()?,
    )
}

fn verify_protection_with(
    desired: &[Vec<String>],
    permanent: &[Vec<String>],
    runtime: &[Vec<String>],
) -> AppResult<()> {
    if rules_match(permanent, desired) && rules_match(runtime, desired) {
        Ok(())
    } else {
        Err(AppError::Firewall(
            "Incomplete IPv4/IPv6 runtime or permanent lockdown protection; activation refused. Run `neutron lockdown enable` to repair protection.".into(),
        ))
    }
}

/// Whether piped stdin is an acceptable activation UUID for the privileged
/// entry point: empty (refresh everything) or a 36-byte lowercase/uppercase
/// hex UUID with dashes at 8/13/18/23. Anything else is rejected before any
/// privileged work happens. Extracted pure so the trust boundary is unit
/// testable without invoking the helper itself.
fn is_valid_activation_uuid(requested: &str) -> bool {
    requested.is_empty()
        || (requested.len() == 36
            && requested.bytes().enumerate().all(|(i, byte)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            }))
}

fn tunnels(activating: Option<&str>) -> AppResult<Vec<WireguardTunnel>> {
    let client = crate::nm::CliNmClient;
    let mut tunnels = client.wireguard_tunnels()?;
    validate_tunnel_interfaces(&tunnels)?;
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
        validate_tunnel_interfaces(&[WireguardTunnel {
            interface: Some(interface.clone()),
            ..Default::default()
        }])?;
        for tunnel in &mut tunnels {
            if tunnel.interface.as_ref() == Some(&interface) {
                tunnel.is_active = true;
            }
        }
    }
    Ok(tunnels)
}

fn acquire_lock(path: &Path, owner: u32, timeout: std::time::Duration) -> AppResult<std::fs::File> {
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && (!metadata.is_file() || metadata.uid() != owner || metadata.nlink() != 1)
    {
        return Err(AppError::Firewall("Unsafe lockdown lock file".into()));
    }
    let lock = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    let metadata = lock.metadata()?;
    if !metadata.is_file() || metadata.uid() != owner || metadata.nlink() != 1 {
        return Err(AppError::Firewall("Unsafe lockdown lock file".into()));
    }
    // Repair the existing inode, never unlink it: old helpers/toggles may hold it.
    lock.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match lock.try_lock() {
            Ok(()) => return Ok(lock),
            Err(std::fs::TryLockError::WouldBlock) => {
                if std::time::Instant::now() >= deadline {
                    return Err(AppError::Firewall(
                        "Timed out waiting for lockdown lock".into(),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
        }
    }
}

fn secure_lock_directory(path: &Path, owner: u32) -> AppResult<()> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != owner {
        return Err(AppError::Firewall("Unsafe lockdown lock directory".into()));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn normalized_runtime_removals() -> AppResult<Vec<Vec<String>>> {
    Ok(runtime_removal_batches()?
        .into_iter()
        .map(|mut batch| {
            batch.insert(0, "--permanent".into());
            batch
        })
        .collect())
}

fn refresh_batches(desired: &[Vec<String>]) -> AppResult<Vec<Vec<String>>> {
    let permanent = marked_removal_batches()?;
    let runtime = normalized_runtime_removals()?;
    let mut batches = Vec::new();
    for (current, is_permanent) in [(permanent, true), (runtime, false)] {
        if rules_match(&current, desired) {
            continue;
        }
        let rebuild = lockdown_rebuild_batches_for(current, desired);
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
    fn preactivation_requires_complete_both_family_both_scope_policy_without_guards() {
        assert!(absent_protection_result(false).is_ok());
        assert!(absent_protection_result(true).is_err());
        let desired = lockdown_enable_batches(&[]);
        let complete: Vec<_> = desired
            .iter()
            .map(|batch| {
                let mut batch = batch.clone();
                batch[2] = "--remove-rule".into();
                batch
            })
            .collect();
        assert!(verify_protection_with(&desired, &complete, &complete).is_ok());
        assert!(verify_protection_with(&desired, &[], &[]).is_err());
        for family in FAMILIES {
            let incomplete: Vec<_> = complete
                .iter()
                .filter(|batch| batch[3] != family)
                .cloned()
                .collect();
            assert!(verify_protection_with(&desired, &incomplete, &complete).is_err());
            assert!(verify_protection_with(&desired, &complete, &incomplete).is_err());
        }
        let mut guarded = complete.clone();
        let mut guard = add_rule("ipv6", -1, &["-j", "DROP"]);
        guard[2] = "--remove-rule".into();
        guarded.push(guard);
        assert!(verify_protection_with(&desired, &complete, &guarded).is_err());
        let mut missing = complete.clone();
        missing.pop();
        assert!(verify_protection_with(&desired, &complete, &missing).is_err());
    }

    #[test]
    fn authorization_rejects_legacy_and_mixed_installed_policies() {
        let dir = crate::testing::scratch_dir("legacy-authorization");
        let legacy = dir.join("legacy.rules");
        let local = dir.join("local.policy");
        let shared = dir.join("shared.policy");
        let policies = [local.as_path(), shared.as_path()];
        let script = revoke_unsafe_authorization_script_for(
            legacy.to_str().unwrap(),
            &[
                local.to_str().unwrap().into(),
                shared.to_str().unwrap().into(),
            ],
            "printf revoked\n",
        );
        let revoked = || {
            let output = std::process::Command::new("/bin/sh")
                .args(["-c", &format!("set -e\n{script}")])
                .output()
                .unwrap();
            assert!(output.status.success());
            output.stdout == b"revoked"
        };
        assert!(!hardened_authorization_at(&legacy, &policies));
        assert!(revoked());
        std::fs::write(&local, HARDENED_DEFAULTS).unwrap();
        assert!(hardened_authorization_at(&legacy, &policies));
        assert!(!revoked());
        std::fs::write(&legacy, "polkit.Result.YES").unwrap();
        assert!(!hardened_authorization_at(&legacy, &policies));
        assert!(revoked());
        std::fs::remove_file(&legacy).unwrap();
        std::fs::write(&shared, HARDENED_DEFAULTS.replace("auth_admin", "yes")).unwrap();
        assert!(!hardened_authorization_at(&legacy, &policies));
        assert!(revoked());
        std::fs::write(&shared, HARDENED_DEFAULTS).unwrap();
        assert!(hardened_authorization_at(&legacy, &policies));
        assert!(!revoked());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn lock_repairs_same_inode_and_bounds_contention() {
        let dir = crate::testing::scratch_dir("firewall-lock");
        let path = dir.join("lock");
        let first = std::fs::File::create(&path).unwrap();
        first
            .set_permissions(std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let metadata = first.metadata().unwrap();
        let private_dir = dir.join("private");
        secure_lock_directory(&private_dir, metadata.uid()).unwrap();
        assert_eq!(
            std::fs::metadata(&private_dir).unwrap().mode() & 0o777,
            0o700
        );
        let private_path = private_dir.join("lock");
        let private_lock = acquire_lock(&private_path, metadata.uid(), LOCK_TIMEOUT).unwrap();
        assert_eq!(private_lock.metadata().unwrap().mode() & 0o777, 0o600);
        drop(private_lock);
        let symlink = dir.join("symlink");
        std::os::unix::fs::symlink(&path, &symlink).unwrap();
        assert!(acquire_lock(&symlink, metadata.uid(), LOCK_TIMEOUT).is_err());
        first.lock().unwrap();
        let start = std::time::Instant::now();
        assert!(acquire_lock(&path, metadata.uid(), std::time::Duration::from_millis(60)).is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), metadata.ino());
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        drop(first);
        drop(acquire_lock(&path, metadata.uid(), LOCK_TIMEOUT).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn activation_uuid_gate_accepts_empty_and_valid_uuids_only() {
        assert!(is_valid_activation_uuid(""));
        assert!(is_valid_activation_uuid(
            "123e4567-e89b-12d3-a456-426614174000"
        ));
        assert!(is_valid_activation_uuid(
            "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        ));
        // Wrong lengths: stdin is truncated at 37 bytes, so anything but
        // empty-or-36 is malformed input, not a UUID.
        assert!(!is_valid_activation_uuid(
            "123e4567-e89b-12d3-a456-42661417400"
        ));
        assert!(!is_valid_activation_uuid(
            "123e4567-e89b-12d3-a456-4266141740000"
        ));
        // Non-hex content and misplaced dashes.
        assert!(!is_valid_activation_uuid(
            "123e4567-e89b-12d3-a456-42661417400g"
        ));
        assert!(!is_valid_activation_uuid(
            "123e4567_e89b-12d3-a456-426614174000"
        ));
        assert!(!is_valid_activation_uuid(
            "-23e4567-e89b-12d3-a456-426614174000"
        ));
        assert!(!is_valid_activation_uuid(
            "123e4567-e89b-12d3-a456-42661417400\n"
        ));
    }

    #[test]
    fn install_script_quotes_paths_and_targets_the_polkit_action() {
        let script = install_script_for("pkaction version 126", std::process::id()).unwrap();
        let raw_exe = format!("/proc/{}/exe", std::process::id());
        let quoted_exe = format!("'{raw_exe}'");
        // The executable path must only ever appear single-quoted: the
        // whole script runs as root via pkexec, so an unquoted path with
        // spaces or metacharacters would be a command injection.
        assert!(
            script.contains(&format!("exec 8<{quoted_exe}\n")),
            "executable must be quoted in the install step: {script}"
        );
        assert_eq!(
            script.matches(raw_exe.as_str()).count(),
            script.matches(quoted_exe.as_str()).count(),
            "every occurrence of the executable path must be quoted: {script}"
        );
        assert!(
            script.contains(&format!("{ACTION_ID}.policy")),
            "script must target the dedicated policy file: {script}"
        );
        assert!(
            script.contains(&format!("rm -f -- {LEGACY_POLICY_PATH}")),
            "script must remove the legacy rules file: {script}"
        );
        assert!(
            script.contains(&format!("pkaction --action-id {ACTION_ID}")),
            "script must verify the action is registered: {script}"
        );
        assert!(script.contains("<allow_active>auth_admin</allow_active>"));
        assert!(script.contains("<allow_inactive>auth_admin</allow_inactive>"));
        assert!(!script.contains("<allow_active>yes</allow_active>"));
        assert!(!script.contains("auth_admin_keep"));
        assert!(script.contains("stat -Lc '%d:%i' /proc/self/fd/8"));
        assert!(script.contains("install -m 755 -- /proc/self/fd/8"));
        assert!(script.contains(&format!("rm -f -- {SHARED_ACTION_DIR}/{ACTION_ID}.policy")));
    }

    #[test]
    fn proc_executable_copy_survives_source_path_replacement() {
        let dir = crate::testing::scratch_dir("installer-executable");
        let source = dir.join("installer");
        let destination = dir.join("helper");
        std::fs::copy("/bin/sleep", &source).unwrap();
        let mut installer = std::process::Command::new(&source)
            .arg("30")
            .spawn()
            .unwrap();
        let original = std::fs::metadata(&source).unwrap();
        let replacement = dir.join("replacement");
        std::fs::copy("/bin/true", &replacement).unwrap();
        std::fs::rename(&replacement, &source).unwrap();
        let script = format!(
            "set -e\nexec 8</proc/{}/exe\n\
             [ \"$(stat -Lc '%d:%i' /proc/self/fd/8)\" = '{}:{}' ]\n\
             install -m 755 -- /proc/self/fd/8 {}\n",
            installer.id(),
            original.dev(),
            original.ino(),
            shell_quote(destination.to_str().unwrap()),
        );
        let copied = std::process::Command::new("/bin/sh")
            .args(["-c", &script])
            .status()
            .unwrap();
        installer.kill().unwrap();
        installer.wait().unwrap();
        assert!(copied.success());
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            std::fs::read("/bin/sleep").unwrap()
        );
        std::fs::remove_dir_all(dir).unwrap();
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
        assert!(revoked.contains(&LEGACY_POLICY_PATH));
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
