//! Uninstalling and resetting: the two commands that take Neutron back out.
//!
//! They live together because they are the same operation with different
//! endings. Both hand back state the app applied -- the permanent firewalld
//! ruleset, the root-owned refresh helper and its polkit action, the kill switch
//! and split-tunnel routes written into NetworkManager profiles, the autostart
//! entry, and in reset's case every setting. Uninstall then removes the package;
//! reset stops at defaults. Revoke-then-purge is the load-bearing order in both:
//! if the privileged teardown fails, this returns early with the settings still
//! on disk, so a failed teardown never leaves the user with neither protection
//! nor configuration.

use crate::app::set_global_kill_switch;
use crate::app::split_tunnel;
use crate::config;
use crate::error::{AppError, AppResult};
use crate::firewall::FirewallClient;
use crate::nm::{NmClient, NmIntrospect};
use crate::service;

/// `neutron reset`: factory reset, back to a first-run state.
///
/// Everything the app *applied* is undone -- the lockdown ruleset, the refresh
/// grant, the kill switch, the split-tunnel routes -- and every setting returns
/// to its default. What it will not touch is anything the user owns: the profile
/// drop directory is reported and left alone, and the WireGuard profiles
/// themselves are only edited to withdraw policies Neutron wrote.
/// `proc_root` is passed in for the same reason `autostart_dir` is: the process
/// scan ends in `kill(2)`, so a test has to be able to aim it at a scratch
/// directory rather than at the real `/proc`.
pub fn handle_reset_command<C: NmClient + FirewallClient>(
    client: &C,
    path: &std::path::Path,
    autostart_dir: Option<&std::path::Path>,
    proc_root: &std::path::Path,
    assume_yes: bool,
) -> AppResult<()> {
    let before = load_for_teardown(path);
    if !assume_yes && !confirm_reset(&before)? {
        println!("Reset cancelled; nothing was changed.");
        return Ok(());
    }

    // A running daemon keeps applying policies from the old settings, so a reset
    // underneath it would be undone before it finished. A window is somebody's
    // session, so it is left open and named at the end.
    let still_running = crate::app::stop_daemons(proc_root, std::time::Duration::from_secs(2));

    // Firewall first, and stop on failure. The one state a half-finished reset
    // must never leave behind is a machine firewalled with no configuration
    // explaining why -- so the privileged, hard-to-reverse step gets the
    // opportunity to abort while the settings are still intact.
    let revoked_lockdown = revoke_installed_state(client, autostart_dir)?;

    // Withdraw the policies Neutron wrote into the NetworkManager profiles. Gated
    // on saved intent so a reset on a clean install does not sweep every profile
    // for nothing; the config is the only record of what was applied, and these
    // are recoverable by hand, unlike a locked-down box.
    if before.kill_switch_enabled {
        crate::spinner::with_spinner("Disabling Kill Switch", || {
            set_global_kill_switch(client, path, false)
        })?;
    }
    if before.global_split_tunnel.mode.is_enabled() || !before.global_split_tunnel.is_empty() {
        crate::spinner::with_spinner("Clearing Split Tunnel", || {
            split_tunnel::clear_global(client, path)
        })?;
    }

    // Defaults in place, which also empties `profile-info.json` (the notes) since
    // the fresh config carries none.
    config::save(path, &config::AppConfig::default())?;

    println!("Reset to factory defaults.");
    println!(
        "  lockdown rules, refresh helper, and polkit action: {}",
        if revoked_lockdown {
            "removed"
        } else {
            "were not installed"
        }
    );
    println!("  settings: {}", path.display());
    report_drop_dir(path, &before);
    if still_running > 0 {
        println!("  {still_running} daemon(s) did not exit; close them before logging in again.");
    }
    Ok(())
}

/// The saved settings, or defaults when they cannot be read.
///
/// Teardown is gated on evidence, never on this, precisely because the settings
/// may be the thing that is broken: a config that no longer parses must not be
/// able to stop the command that would leave the machine firewalled. Reading it
/// still decides what else to withdraw, so the failure is reported rather than
/// swallowed.
fn load_for_teardown(path: &std::path::Path) -> config::AppConfig {
    match config::load(path) {
        Ok(cfg) => cfg,
        Err(error) => {
            println!(
                "Settings at {} could not be read ({error}); continuing from evidence on disk.",
                path.display()
            );
            config::AppConfig::default()
        }
    }
}

/// Withdraw what the installation applied outside the package: the permanent
/// ruleset, the root-owned refresh helper and its polkit action, and the
/// autostart entry. Returns whether the privileged teardown ran.
///
/// Evidence, not intent. The rules outlive the setting that installed them, so
/// gating on saved config left a machine whose config was lost, corrupt or
/// already purged stuck firewalled with no binary to lift it -- and gating on
/// intent instead prompts for a password to delete files that were never
/// created. Both checks are unprivileged.
fn revoke_installed_state<C: FirewallClient>(
    client: &C,
    autostart_dir: Option<&std::path::Path>,
) -> AppResult<bool> {
    let installed = client.has_installed_lockdown_state()?;
    if installed {
        // One batch: rules and grant together, so this is a single prompt.
        client.teardown_lockdown(true)?;
    }
    if let Some(dir) = autostart_dir {
        service::autostart::uninstall_in(dir)?;
    }
    Ok(installed)
}

/// Name a drop directory that was left behind because it lives outside the
/// configuration directory.
///
/// `profiles_dir` is user-configurable and may be any path, holding `.conf`
/// files that may never have been imported. Reported by both commands, and never
/// deleted: these are the user's files, not the app's.
fn report_drop_dir(config_path: &std::path::Path, cfg: &config::AppConfig) {
    let drop_dir = config::resolve_profiles_dir(cfg);
    let inside = config_path
        .parent()
        .is_some_and(|root| drop_dir.starts_with(root));
    if !inside {
        println!(
            "  profile drop directory left in place: {}",
            drop_dir.display()
        );
    }
}

/// Ask before wiping everything. Deliberately needs the word `reset`, not a `y`.
///
/// Non-interactive stdin refuses rather than proceeding: something scripting
/// this should say so out loud with `--yes`, not wipe a machine because a pipe
/// happened to be attached.
fn confirm_reset(before: &config::AppConfig) -> AppResult<bool> {
    use std::io::{IsTerminal, Write};

    if !std::io::stdin().is_terminal() {
        return Err(AppError::Config(
            "neutron reset needs a terminal to confirm; pass --yes to proceed unattended".into(),
        ));
    }
    let mut notes = before.excluded_profile_ids.len() + before.favorite_profile_ids.len();
    notes += before.profile_custom_info.len();
    eprintln!(
        "This removes every Neutron setting -- eligibility pool, favorites, notes, \
         qBittorrent credentials{} -- and withdraws the applied policies.",
        if notes > 0 {
            format!(
                " ({notes} entr{} kept nowhere)",
                if notes == 1 { "y" } else { "ies" }
            )
        } else {
            String::new()
        }
    );
    if before.lockdown_enabled {
        eprintln!("Lockdown is on: its firewall rules and root-owned helper will be removed.");
    }
    eprint!("Type 'reset' to continue: ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(answer.trim() == "reset")
}

/// `neutron uninstall`: revoke the app's out-of-package state, then remove the
/// package itself.
///
/// Order is the whole point. The permanent firewalld rules, the root-owned
/// refresh helper, and its polkit action live outside every package manager's
/// file list, and no packaging hook can clean them up: Homebrew's
/// `post_uninstall` runs *after* the files are gone, with no way to
/// authenticate. So the teardown has to happen while this binary still exists,
/// which is why it is a subcommand rather than a package script.
///
/// The install source is resolved *first*, and the package removed *last*:
/// refusing an unrecognized source is only safe if nothing has been deleted
/// yet, and removing the binary we are running from is only safe once there is
/// nothing left to do afterwards.
pub fn handle_uninstall_command<C: NmClient + FirewallClient>(
    client: &C,
    path: &std::path::Path,
    purge: bool,
) -> AppResult<()> {
    let removal = crate::install::current()?;
    // A live tray daemon can re-apply policies after teardown, and would keep
    // renewing a port forward with the binary about to be gone. A window is a
    // session somebody is in, so it is left open and reported below.
    let still_running = crate::app::stop_daemons(
        std::path::Path::new("/proc"),
        std::time::Duration::from_secs(2),
    );
    // A missing autostart directory is not a failure: nothing was installed.
    let autostart_dir = service::autostart::dir().ok();
    revoke_and_purge(client, path, autostart_dir.as_deref(), purge)?;
    if still_running > 0 {
        println!(
            "{still_running} Neutron daemon(s) did not exit; they can re-apply policies until closed."
        );
    }
    remove_the_package(&removal)
}

/// Revoke every Neutron-owned file outside the package: the lockdown ruleset,
/// the root-owned refresh helper, its polkit action, the autostart entry, and
/// (under `purge`) the configuration directory.
///
/// Revoke-then-purge is deliberate and load-bearing. If the privileged teardown
/// fails -- a declined password prompt, a firewalld that rejects the batch --
/// this returns early with the settings still on disk, so a failed teardown can
/// never leave the user with neither protection nor configuration. Callers must
/// resolve the install source before calling this.
pub fn revoke_and_purge<C: NmIntrospect + FirewallClient>(
    client: &C,
    path: &std::path::Path,
    autostart_dir: Option<&std::path::Path>,
    purge: bool,
) -> AppResult<()> {
    revoke_installed_state(client, autostart_dir)?;
    // Saved intent is deliberately left as the user set it. Uninstall removes the
    // mechanism, it does not rewrite preferences: with `--purge` the file goes
    // anyway, and without it a reinstall restores the lockdown they chose. The
    // lock is gone either way, so a stale `true` cannot leave them unprotected.
    if let Some(drop_dir) = remove_app_settings(path, purge)? {
        println!(
            "Profile drop directory left in place: {}",
            drop_dir.display()
        );
    }
    report_manual_unit(path.parent());
    Ok(())
}

/// Hand the binary to the package manager that installed it.
fn remove_the_package(removal: &crate::install::Removal) -> AppResult<()> {
    // Unprivileged, no shell, inheriting the terminal so brew or cargo can
    // report or prompt itself.
    let status = crate::process::host_command(removal.program)
        .args(&removal.args)
        .status()
        .map_err(|error| AppError::CommandFailed(format!("{}: {error}", removal.program)))?;
    if !status.success() {
        return Err(AppError::CommandFailed(format!(
            "{} exited with {status}; Neutron's own state is already revoked",
            removal.program
        )));
    }
    println!("Removed the {} install of Neutron.", removal.program);
    Ok(())
}

/// Delete the app's configuration directory when `purge` asks for it.
///
/// Settings are kept by default -- see [`handle_uninstall_command`] -- so this
/// normally just reports where they are.
///
/// Returns a drop directory that was left behind because it lives *outside* the
/// configuration directory: `profiles_dir` is user-configurable and may be any
/// path (even `~`), holding `.conf` files that may never have been imported.
/// Settings are read before the directory goes away -- that file is the only
/// copy of the setting.
fn remove_app_settings(
    config_path: &std::path::Path,
    purge: bool,
) -> AppResult<Option<std::path::PathBuf>> {
    let Some(parent) = config_path.parent() else {
        return Ok(None);
    };
    if !purge {
        println!("Settings kept at {}", parent.display());
        return Ok(None);
    }
    // An absent or unreadable config records no drop directory, so there is
    // nothing to report: the default path would be a guess, and a guess must
    // never be announced as a directory of the user's we deliberately kept.
    let profiles = if config_path.exists() {
        config::load(config_path)
            .map(|cfg| config::resolve_profiles_dir(&cfg))
            .unwrap_or_default()
    } else {
        std::path::PathBuf::new()
    };
    match std::fs::remove_dir_all(parent) {
        Ok(()) => {}
        // Nothing to purge: an install that never wrote settings has no
        // directory, and that must not abort an uninstall this late.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    println!("Removed {}", parent.display());
    Ok((!profiles.as_os_str().is_empty() && !profiles.starts_with(parent)).then_some(profiles))
}

/// Point out the systemd user unit, which `systemd/README.md` has the user
/// install by hand. It is not ours to remove -- it may have been edited, and
/// `systemctl` needs its own reload -- but an enabled unit outliving the binary
/// fails at every login, so name it while the user is still here.
fn report_manual_unit(config_root: Option<&std::path::Path>) {
    const UNIT: &str = "neutron-startup-random.service";
    let Some(unit) = config_root.map(|root| root.join("systemd/user").join(UNIT)) else {
        return;
    };
    if unit.exists() {
        println!(
            "systemd user unit left in place: {}\n  \
             systemctl --user disable --now {UNIT} && rm {}",
            unit.display(),
            unit.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The config path and the proc root are the two things the reset tests must
    /// not take from the environment; `crate::testing` is their one home.
    fn unique_test_config_path() -> std::path::PathBuf {
        crate::testing::temp_config_path("app")
    }

    fn cleanup_test_config(path: &std::path::Path) {
        crate::testing::remove_temp_config(path);
    }

    fn scratch_proc_root() -> std::path::PathBuf {
        crate::testing::scratch_dir("proc-root")
    }

    #[test]
    fn revoke_removes_only_neutrons_own_autostart_entry() {
        let client = crate::testing::MockNmClient::new(vec![]);
        let home = decoy_config_home("autostart");
        let path = home.join("neutron/config.toml");
        let autostart_dir = home.join("autostart");
        config::save(&path, &config::AppConfig::default()).expect("config should save");
        service::autostart::install_in(&autostart_dir).expect("autostart entry should install");

        revoke_and_purge(&client, &path, Some(&autostart_dir), false)
            .expect("revoke should succeed");

        let before = relative_paths(&home);
        assert!(
            !before.contains("autostart/io.github.pandabytez.neutron-autostart.desktop"),
            "{before:?}"
        );
        assert!(
            before.contains("autostart/some-other-app.desktop"),
            "another app's autostart entry must survive: {before:?}"
        );
        remove_temp_root(&home);
    }

    #[test]
    fn a_failed_teardown_keeps_the_settings() {
        // The ordering guarantee: a declined prompt or a rejected firewall batch
        // must not leave the user with neither protection nor configuration.
        // Evidence, not the saved setting: the setting is what a corrupt or
        // purged config cannot be relied on to report.
        let client = crate::testing::MockNmClient::new(vec![])
            .fail_lockdown()
            .with_installed_lockdown_state();
        let home = decoy_config_home("failed-teardown");
        let path = home.join("neutron/config.toml");
        config::save(
            &path,
            &config::AppConfig {
                lockdown_enabled: true,
                ..config::AppConfig::default()
            },
        )
        .expect("config should save");
        let before = relative_paths(&home);

        let error = revoke_and_purge(&client, &path, None, true)
            .expect_err("a failed teardown must abort the uninstall");

        // Not a `PolicyUpdate`: there is no policy left to reconcile here, and
        // the user needs to know the uninstall stopped before it deleted
        // anything, not that a saved preference may be stale.
        assert!(matches!(error, AppError::Firewall(_)), "{error}");
        assert_eq!(relative_paths(&home), before, "nothing may be deleted");
        remove_temp_root(&home);
    }

    #[test]
    fn an_absent_configuration_still_tears_down_installed_lockdown_state() {
        // The rules outlive the setting that installed them, so a lost or
        // already-purged config must not be what decides whether the machine
        // gets unblocked. Evidence, not intent.
        let client = crate::testing::MockNmClient::new(vec![]).with_installed_lockdown_state();
        let path = unique_test_config_path();

        revoke_and_purge(&client, &path, None, false).expect("revoke should succeed");

        assert_eq!(
            client.lockdown_calls(),
            vec!["lockdown:teardown:rules+grant"]
        );
        cleanup_test_config(&path);
    }

    #[test]
    fn an_install_that_never_enabled_lockdown_tears_nothing_down() {
        // The gate is what keeps a fresh install from prompting for a password to
        // delete three files that were never created.
        let client = crate::testing::MockNmClient::new(vec![]);
        let path = unique_test_config_path();

        revoke_and_purge(&client, &path, None, true).expect("revoke should succeed");

        assert!(client.lockdown_calls().is_empty());
        cleanup_test_config(&path);
    }

    #[test]
    fn a_stale_lockdown_setting_with_nothing_installed_tears_nothing_down() {
        // The setting can outlive what it installed -- a ruleset removed by hand,
        // a config restored from an old backup. Trusting it would ask for a
        // password to delete files that are not there and, on a machine where
        // something *is* still installed, would not be the thing that decides.
        let client = crate::testing::MockNmClient::new(vec![]);
        let path = unique_test_config_path();
        config::save(
            &path,
            &config::AppConfig {
                lockdown_enabled: true,
                ..config::AppConfig::default()
            },
        )
        .expect("config should save");

        revoke_and_purge(&client, &path, None, true).expect("revoke should succeed");

        assert!(
            client.lockdown_calls().is_empty(),
            "intent is not evidence: {:?}",
            client.lockdown_calls()
        );
        cleanup_test_config(&path);
    }

    #[test]
    fn a_corrupt_config_does_not_stop_the_teardown() {
        // The failure this command exists for is a machine that cannot be reached
        // any other way, so a config that no longer parses must not be able to
        // block it. The setting is unreadable *and* the state is installed: the
        // evidence check is the only way to that teardown.
        let client = crate::testing::MockNmClient::new(vec![]).with_installed_lockdown_state();
        let path = unique_test_config_path();
        std::fs::create_dir_all(path.parent().expect("config path has a parent"))
            .expect("config directory should be created");
        std::fs::write(&path, "this is not valid toml = = =").expect("corrupt config should write");

        revoke_and_purge(&client, &path, None, true).expect("revoke should succeed");

        assert_eq!(
            client.lockdown_calls(),
            vec!["lockdown:teardown:rules+grant"]
        );
        assert!(
            !path.exists(),
            "purge still runs once the teardown has been revoked"
        );
    }

    #[test]
    fn uninstall_without_purge_deletes_nothing() {
        let home = decoy_config_home("no-purge");
        let path = home.join("neutron/config.toml");
        config::save(&path, &config::AppConfig::default()).expect("config should save");
        let before = relative_paths(&home);

        assert_eq!(
            remove_app_settings(&path, false).expect("settings should be kept"),
            None
        );

        assert_eq!(relative_paths(&home), before, "the default must be a no-op");
        remove_temp_root(&home);
    }

    #[test]
    fn purge_deletes_only_the_application_directory() {
        let home = decoy_config_home("purge");
        let path = home.join("neutron/config.toml");
        config::save(&path, &config::AppConfig::default()).expect("config should save");

        remove_app_settings(&path, true).expect("purge should succeed");

        assert_eq!(
            relative_paths(&home),
            BTreeSet::from([
                "autostart/".to_string(),
                "autostart/some-other-app.desktop".to_string(),
                "neutron-vpn/".to_string(),
                "neutron-vpn/config.json".to_string(),
                "other-app/".to_string(),
                "other-app/config.json".to_string(),
                "systemd/".to_string(),
                "systemd/user/".to_string(),
                "systemd/user/neutron-startup-random.service".to_string(),
            ]),
            "purge must remove the app directory and nothing else"
        );
        remove_temp_root(&home);
    }

    #[test]
    fn purge_reports_but_never_deletes_a_drop_directory_outside_the_app_dir() {
        let home = decoy_config_home("drop-outside");
        let path = home.join("neutron/config.toml");
        // A sibling of the app directory: the common `~/wg-configs` shape.
        let sibling = unique_temp_root("drop-sibling").join("drop");
        std::fs::create_dir_all(&sibling).expect("drop dir should be created");
        config::save(&path, &config_with_drop_dir(&sibling)).expect("config should save");

        let reported = remove_app_settings(&path, true).expect("purge should succeed");

        assert_eq!(reported, Some(sibling.clone()));
        assert!(
            sibling.exists(),
            "a user-chosen drop directory holds their own files"
        );
        remove_temp_root(sibling.parent().unwrap());
        remove_temp_root(&home);
    }

    #[test]
    fn purge_never_deletes_a_drop_directory_that_contains_the_config_directory() {
        // `profiles_dir: "~"` is legal, and once expanded the drop directory is the
        // app directory's own parent -- so a purge that recursed past the
        // configured path would take out everything above it, decoys included.
        let home = decoy_config_home("drop-parent");
        let path = home.join("neutron/config.toml");
        let decoys = relative_paths(&home);
        config::save(&path, &config_with_drop_dir(&home)).expect("config should save");

        let reported = remove_app_settings(&path, true).expect("purge should succeed");

        assert_eq!(reported, Some(home.clone()), "the parent is reported");
        assert!(
            !home.join("neutron").exists(),
            "the app directory itself still goes"
        );
        let survivors = relative_paths(&home);
        assert!(
            decoys
                .iter()
                .filter(|entry| !entry.starts_with("neutron/"))
                .all(|entry| survivors.contains(entry)),
            "every decoy above the app directory must survive: {survivors:?}"
        );
        remove_temp_root(&home);
    }

    #[test]
    fn purge_does_not_follow_a_symlink_out_of_the_app_dir() {
        // `remove_dir_all` unlinks a symlink instead of recursing into it. A
        // future rewrite that shells out to `rm -rf` would empty the target, so
        // pin the behaviour rather than trusting it.
        let home = decoy_config_home("symlink");
        let path = home.join("neutron/config.toml");
        let target = unique_temp_root("symlink-target").join("precious");
        std::fs::create_dir_all(&target).expect("target should be created");
        std::fs::write(target.join("keep.txt"), "keep").expect("file should be written");
        config::save(&path, &config::AppConfig::default()).expect("config should save");
        std::os::unix::fs::symlink(&target, home.join("neutron/escape"))
            .expect("symlink should be created");

        remove_app_settings(&path, true).expect("purge should succeed");

        assert!(
            !home.join("neutron").exists(),
            "the symlink must be unlinked"
        );
        assert!(
            target.join("keep.txt").exists(),
            "purge must not recurse through a symlink"
        );
        remove_temp_root(target.parent().unwrap());
        remove_temp_root(&home);
    }

    #[test]
    fn purge_of_a_legacy_configuration_directory_spares_the_current_one() {
        // `default_config_path` still resolves pre-rename directories, so the
        // resolved one is the only one that is ours to delete.
        let home = decoy_config_home("legacy");
        let path = home.join("neutron-vpn/config.json");
        config::save(&path, &config::AppConfig::default()).expect("config should save");
        let current = home.join("neutron/config.toml");
        config::save(&current, &config::AppConfig::default()).expect("config should save");

        remove_app_settings(&path, true).expect("purge should succeed");

        assert!(!path.parent().unwrap().exists());
        assert!(
            current.exists(),
            "the current directory is not ours to delete"
        );
        remove_temp_root(&home);
    }

    #[test]
    fn purge_with_a_missing_or_unreadable_configuration_still_only_purges_the_app_dir() {
        for (label, body) in [("absent", None), ("garbage", Some("not = = toml"))] {
            let home = decoy_config_home(label);
            let path = home.join("neutron/config.toml");
            if let Some(body) = body {
                std::fs::write(&path, body).expect("config should be written");
            }

            let reported = remove_app_settings(&path, true).expect("purge should succeed");

            assert_eq!(reported, None, "{label}: nothing outside was recorded");
            assert!(!home.join("neutron").exists(), "{label}");
            assert!(home.join("other-app/config.json").exists(), "{label}");
            remove_temp_root(&home);
        }
    }

    #[test]
    fn purge_is_idempotent() {
        // `--purge` on an install that never wrote settings must not abort the
        // uninstall this late, and a second run must change nothing.
        let home = decoy_config_home("idempotent");
        let path = home.join("neutron/config.toml");
        config::save(&path, &config::AppConfig::default()).expect("config should save");

        remove_app_settings(&path, true).expect("first purge should succeed");
        let after = relative_paths(&home);
        remove_app_settings(&path, true).expect("second purge should succeed");

        assert_eq!(relative_paths(&home), after);
        remove_temp_root(&home);
    }

    fn config_with_drop_dir(drop_dir: &std::path::Path) -> config::AppConfig {
        config::AppConfig {
            general: config::GeneralConfig {
                profiles_dir: drop_dir.to_string_lossy().into_owned(),
                ..Default::default()
            },
            ..config::AppConfig::default()
        }
    }

    /// A fake `~/.config` holding the application directory alongside decoys
    /// that an over-eager delete would take with it: another app, the legacy
    /// pre-rename directory, a foreign autostart entry, and the hand-installed
    /// systemd unit.
    fn decoy_config_home(label: &str) -> std::path::PathBuf {
        let home = unique_temp_root(label);
        for relative in [
            "neutron/config.toml.policy.lock",
            "neutron/profile-info.json",
            "neutron/profiles/home.conf",
            "neutron-vpn/config.json",
            "other-app/config.json",
            "autostart/some-other-app.desktop",
            "systemd/user/neutron-startup-random.service",
        ] {
            let path = home.join(relative);
            std::fs::create_dir_all(path.parent().expect("fixture parent"))
                .expect("fixture directory should be created");
            // The JSON sidecars are parsed by config::save, so they need a body
            // it can read back rather than arbitrary text.
            let body = if relative.ends_with(".json") {
                "{}"
            } else {
                ""
            };
            std::fs::write(&path, body).expect("fixture file should be written");
        }
        home
    }

    /// Every path still present under `root`, relative and slash-terminated for
    /// directories. Comparing whole sets is what makes "nothing unintended was
    /// deleted" an assertion instead of a hope.
    fn relative_paths(root: &std::path::Path) -> BTreeSet<String> {
        fn walk(root: &std::path::Path, dir: &std::path::Path, found: &mut BTreeSet<String>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                if path.is_dir() {
                    found.insert(format!("{relative}/"));
                    walk(root, &path, found);
                } else {
                    found.insert(relative);
                }
            }
        }
        let mut found = BTreeSet::new();
        walk(root, root, &mut found);
        found
    }

    fn unique_temp_root(label: &str) -> std::path::PathBuf {
        crate::testing::temp_config_path(label)
            .parent()
            .expect("temp config path has a parent")
            .to_path_buf()
    }

    fn remove_temp_root(root: &std::path::Path) {
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reset_withdraws_every_applied_policy_and_returns_settings_to_defaults() {
        let client = crate::testing::MockNmClient::new(vec![]).with_installed_lockdown_state();
        let home = decoy_config_home("reset");
        let path = home.join("neutron/config.toml");
        let autostart_dir = home.join("autostart");
        service::autostart::install_in(&autostart_dir).expect("autostart entry should install");
        config::save(
            &path,
            &config::AppConfig {
                kill_switch_enabled: true,
                lockdown_enabled: true,
                excluded_profile_ids: BTreeSet::from(["uuid-1".to_string()]),
                favorite_profile_ids: BTreeSet::from(["uuid-2".to_string()]),
                global_split_tunnel: config::SplitTunnelConfig {
                    mode: config::SplitTunnelMode::Include,
                    cidrs: vec!["10.0.0.0/8".to_string()],
                    domains: vec!["example.com".to_string()],
                },
                qbittorrent: config::QBittorrentConfig {
                    password: Some("secret".to_string()),
                    ..config::QBittorrentConfig::default()
                },
                general: config::GeneralConfig {
                    autoconnect_at_login: true,
                    ..config::GeneralConfig::default()
                },
                ..config::AppConfig::default()
            },
        )
        .expect("config should save");
        let decoys_before = relative_paths(&home);

        handle_reset_command(
            &client,
            &path,
            Some(&autostart_dir),
            &scratch_proc_root(),
            true,
        )
        .expect("reset should succeed");

        // Every applied policy withdrawn, in one pass each.
        assert_eq!(
            client.lockdown_calls(),
            vec!["lockdown:teardown:rules+grant"]
        );
        assert_eq!(client.kill_switch_calls(), vec!["kill-switch-all:off"]);
        assert_eq!(
            client.split_tunnel_calls(),
            vec!["split-tunnel-all:disabled:0:0"]
        );
        // Settings back to a first-run state, credentials included.
        let after = config::load(&path).expect("config should load");
        assert!(!after.kill_switch_enabled);
        assert!(!after.lockdown_enabled);
        assert!(after.excluded_profile_ids.is_empty());
        assert!(after.favorite_profile_ids.is_empty());
        assert!(after.global_split_tunnel.is_empty());
        assert!(!after.global_split_tunnel.mode.is_enabled());
        assert!(after.qbittorrent.password.is_none());
        assert!(!after.general.autoconnect_at_login);
        // The autostart entry mirrors that flag, so it goes with it.
        assert!(!service::autostart::is_installed_in(&autostart_dir));
        // Anything the user owns is untouched.
        let survivors = relative_paths(&home);
        assert!(
            decoys_before
                .iter()
                .filter(|entry| !entry.starts_with("neutron/") && !entry.starts_with("autostart/"))
                .all(|entry| survivors.contains(entry)),
            "a reset must not reach outside its own state: {survivors:?}"
        );
        remove_temp_root(&home);
    }

    #[test]
    fn reset_on_a_clean_install_touches_nothing_privileged() {
        // No saved intent and no installed state, so no password prompt and no
        // sweep of every NetworkManager profile for nothing.
        let client = crate::testing::MockNmClient::new(vec![]);
        let home = decoy_config_home("reset-clean");
        let path = home.join("neutron/config.toml");
        let autostart_dir = home.join("autostart");
        config::save(&path, &config::AppConfig::default()).expect("config should save");

        handle_reset_command(
            &client,
            &path,
            Some(&autostart_dir),
            &scratch_proc_root(),
            true,
        )
        .expect("reset should succeed");

        assert!(client.lockdown_calls().is_empty());
        assert!(client.kill_switch_calls().is_empty());
        assert!(client.split_tunnel_calls().is_empty());
        remove_temp_root(&home);
    }

    #[test]
    fn reset_asks_for_the_word_reset_and_changes_nothing_when_refused() {
        // Non-interactive stdin must refuse rather than wipe on a piped input.
        let client = crate::testing::MockNmClient::new(vec![]);
        let home = decoy_config_home("reset-refused");
        let path = home.join("neutron/config.toml");
        config::save(
            &path,
            &config::AppConfig {
                lockdown_enabled: true,
                ..config::AppConfig::default()
            },
        )
        .expect("config should save");
        let before = relative_paths(&home);

        let error = handle_reset_command(&client, &path, None, &scratch_proc_root(), false)
            .expect_err("without a terminal, reset must not proceed");

        assert!(error.to_string().contains("--yes"), "{error}");
        assert!(client.lockdown_calls().is_empty());
        assert_eq!(relative_paths(&home), before, "nothing may be deleted");
        remove_temp_root(&home);
    }
}
