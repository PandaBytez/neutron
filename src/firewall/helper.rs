//! Root-owned, refresh-only copy installed during an authenticated lockdown toggle.
//! It derives allowances from NetworkManager, never accepts rules from the caller,
//! and cannot enable or disable lockdown. Permanent rules authorize refreshes.

use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;

use super::*;
use crate::nm::NmClient;

pub const NAME: &str = "neutron-lockdown-helper";
const PATH: &str = "/usr/local/libexec/neutron-lockdown-helper";
pub(super) const LOCK_PATH: &str = "/run/neutron-lockdown.lock";
const POLICY_PATH: &str = "/etc/polkit-1/rules.d/49-neutron-lockdown-refresh.rules";
const POLICY: &str = r#"polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.policykit.exec" &&
        action.lookup("program") == "/usr/local/libexec/neutron-lockdown-helper") {
        return subject.local && subject.active ? polkit.Result.YES : polkit.Result.NO;
    }
});
"#;

pub(super) fn install_script() -> AppResult<String> {
    let executable = std::env::current_exe()?;
    let executable = executable
        .to_str()
        .ok_or_else(|| AppError::Firewall("Neutron executable path is not valid UTF-8".into()))?;
    // Replace atomically: another process may still be executing the old copy.
    Ok(format!(
        "install -d -m 755 /usr/local/libexec\n\
         install -m 755 -- {} {PATH}.new\n\
         mv -f -- {PATH}.new {PATH}\n\
         install -d -m 755 /etc/polkit-1/rules.d\n\
         printf %s {} > {POLICY_PATH}\n\
         chmod 644 {POLICY_PATH}\n\
         if [ -d /run/systemd/system ]; then systemctl enable firewalld.service; fi\n",
        shell_quote(executable),
        shell_quote(POLICY),
    ))
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
    // without AllowUserInteraction first, so a missing rule cannot open a GUI prompt.
    let authorization = crate::process::host_command("pkcheck")
        .args([
            "--action-id",
            "org.freedesktop.policykit.exec",
            "--process",
            &std::process::id().to_string(),
            "--detail",
            "program",
            PATH,
        ])
        .output()?;
    if !authorization.status.success() {
        return Err(AppError::Firewall(
            "Password-free lockdown refresh is unavailable. Run `neutron lockdown enable` \
             once from an active local session to install or repair authorization."
                .into(),
        ));
    }
    let mut child = crate::process::host_command_with_env("pkexec", &[("SHELL", "/bin/sh")])
        .args(["--disable-internal-agent", PATH])
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
