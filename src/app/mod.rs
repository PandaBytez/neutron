pub(crate) mod eligibility;
pub mod profile_list;
pub mod qbittorrent;
pub mod refresh_sync;
pub mod split_tunnel;
pub mod sync;

use clap::{Parser, Subcommand};

use crate::config;
use crate::error::AppError;
use crate::error::AppResult;
use crate::firewall::FirewallClient;
use crate::nm::{self, NmClient, NmIntrospect, NmPolicy, WireguardProfile};
use crate::service;

#[derive(Debug, Parser)]
#[command(name = "neutron")]
#[command(about = "Neutron - Fast WireGuard profile manager via NetworkManager")]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Launch the interactive Terminal User Interface (TUI)
    Tui,
    /// Sync profile drop directory (~/.config/neutron/profiles) with NetworkManager
    Sync,
    /// List all WireGuard profiles with active and eligibility status
    List,
    /// Connect to a WireGuard profile by name or UUID
    Connect { profile: String },
    /// Disconnect the currently active WireGuard profile
    Disconnect,
    /// Switch active connection to target profile
    Switch { profile: String },
    /// Manage startup-random selection eligibility pool
    Eligible {
        #[command(subcommand)]
        command: EligibleCommands,
    },
    /// Manage favorite profiles pinned to tray quick actions
    Favorite {
        #[command(subcommand)]
        command: FavoriteCommands,
    },
    /// Run one-shot random startup profile connection
    StartupRandom,
    /// Inspect or toggle global kill switch (NetworkManager policy routing)
    KillSwitch {
        #[command(subcommand)]
        command: KillSwitchCommands,
    },
    /// Inspect or toggle always-on lockdown firewall (Netfilter direct rules)
    Lockdown {
        #[command(subcommand)]
        command: LockdownCommands,
    },
    /// Inspect or configure global split tunneling (Include / Exclude CIDRs & domains)
    SplitTunnel {
        #[command(subcommand)]
        command: SplitTunnelCommands,
    },
    /// Configure or synchronize dynamic port forwarding with qBittorrent WebUI
    #[command(alias = "qbittorrent")]
    Qbit {
        #[command(subcommand)]
        command: QbitCommands,
    },
    /// Run the persistent system tray AppIndicator daemon in the background
    #[command(alias = "daemon")]
    Indicator,
    /// Revoke everything Neutron installed outside its package, then remove the package
    Uninstall {
        /// Also delete ~/.config/neutron (settings, eligibility, qBittorrent password)
        #[arg(long)]
        purge: bool,
    },
    /// Terminate any running background daemon/processes and launch fresh instance
    Restart,
}

#[derive(Debug, Subcommand)]
enum EligibleCommands {
    List,
    Add { profile: String },
    Remove { profile: String },
}

#[derive(Debug, Subcommand)]
enum FavoriteCommands {
    List,
    Add { profile: String },
    Remove { profile: String },
}

#[derive(Debug, Subcommand)]
enum KillSwitchCommands {
    Status,
    Enable,
    Disable,
}

#[derive(Debug, Subcommand)]
enum LockdownCommands {
    Status,
    Enable,
    Disable,
}

#[derive(Debug, Subcommand)]
enum SplitTunnelCommands {
    Status,
    SetMode { mode: String },
    AddCidr { cidr: String },
    RemoveCidr { cidr: String },
    AddDomain { domain: String },
    RemoveDomain { domain: String },
    Clear,
}

#[derive(Debug, Subcommand)]
enum QbitCommands {
    /// Show qBittorrent integration status, WebUI connectivity, and current ports
    Status,
    /// Test connection to the qBittorrent WebUI
    Test,
    /// Sync active forwarded port to qBittorrent immediately
    Sync,
    /// Enable port forwarding with automatic sync to qBittorrent
    Enable,
    /// Disable automatic sync to qBittorrent, keeping port forwarding on
    Disable,
    /// Update qBittorrent WebUI connection settings
    Config {
        #[arg(long, help = "WebUI URL (e.g. http://127.0.0.1:8080)")]
        url: Option<String>,
        #[arg(long, help = "WebUI username")]
        username: Option<String>,
        #[arg(long, help = "WebUI password")]
        password: Option<String>,
        #[arg(long, help = "Bind qBittorrent to the active WireGuard interface")]
        bind: Option<bool>,
    },
}

pub fn run<C: NmClient + FirewallClient + Clone + Send + Sync + 'static>(
    client: &C,
) -> AppResult<()> {
    if let Ok(config_path) = config::default_config_path()
        && let Ok(app_cfg) = config::load(&config_path)
    {
        let _ = sync::ensure_app_dirs(&app_cfg);
    }

    let cli = Cli::parse();
    execute(client, cli)
}

fn execute<C: NmClient + FirewallClient + Clone + Send + Sync + 'static>(
    client: &C,
    cli: Cli,
) -> AppResult<()> {
    let path = config::default_config_path()?;
    match cli.command {
        None | Some(Commands::Tui) => crate::tui::run(client.clone()),
        Some(Commands::Indicator) => {
            crate::service::indicator::run_standalone_indicator(client.clone())
        }
        Some(Commands::Sync) => {
            let app_cfg = config::load(&path)?;
            let report = sync::sync_profiles_dir(client, &app_cfg)?;
            // Imported profiles have no lockdown allow-rule yet, so the ruleset
            // has to be rebuilt before they can connect.
            rebuild_lockdown_if_enabled(client, &path)?;
            if !report.imported.is_empty() {
                println!(
                    "Imported {} new profiles: {}",
                    report.imported.len(),
                    report.imported.join(", ")
                );
            }
            if report.skipped > 0 {
                println!("Skipped {} already existing profiles.", report.skipped);
            }
            if !report.errors.is_empty() {
                eprintln!("Errors during sync:\n{}", report.errors.join("\n"));
            }
            if report.imported.is_empty() && report.errors.is_empty() {
                println!("All profiles are up to date.");
            }
            Ok(())
        }
        Some(Commands::List) => {
            let app_cfg = config::load(&path)?;
            let profiles = client.list_wireguard_profiles()?;
            let rows = profile_list::build_rows(
                &profiles,
                &app_cfg.excluded_profile_ids,
                &app_cfg.favorite_profile_ids,
                &app_cfg.profile_custom_info,
            );
            for row in rows {
                println!("{}", profile_list::format_cli_row(&row));
            }
            Ok(())
        }
        Some(Commands::Connect { profile }) => {
            client.connect(&profile)?;
            rebuild_lockdown_if_enabled(client, &path)
        }
        Some(Commands::Disconnect) => {
            client.disconnect_active()?;
            rebuild_lockdown_if_enabled(client, &path)
        }
        Some(Commands::Switch { profile }) => {
            client.switch_to(&profile)?;
            rebuild_lockdown_if_enabled(client, &path)
        }
        Some(Commands::StartupRandom) => {
            let app_cfg = config::load(&path)?;
            if !app_cfg.general.autoconnect_at_login {
                let _ = service::set_autoconnect_at_login(client, &path, false);
                println!("Startup random skipped: auto-connect at login is disabled in config");
                return Ok(());
            }
            let res = service::run_startup_random(client);
            let _ = rebuild_lockdown_if_enabled(client, &path);
            service::indicator::ensure_indicator_daemon_running();
            match res? {
                service::StartupRandomResult::Connected(selected) => {
                    println!("Startup random connected: {selected}");
                }
                service::StartupRandomResult::SkippedAlreadyActive => {
                    println!("Startup random skipped: a WireGuard profile is already active");
                }
            }
            Ok(())
        }
        Some(Commands::Restart) => {
            kill_other_neutron_processes();
            std::thread::sleep(std::time::Duration::from_millis(100));
            crate::tui::run(client.clone())
        }
        Some(Commands::Eligible { command }) => handle_eligible_command(client, command),
        Some(Commands::Favorite { command }) => handle_favorite_command(client, command),
        Some(Commands::KillSwitch { command }) => handle_kill_switch_command(client, command),
        Some(Commands::Lockdown { command }) => handle_lockdown_command(client, command),
        Some(Commands::SplitTunnel { command }) => handle_split_tunnel_command(client, command),
        Some(Commands::Qbit { command }) => handle_qbit_command(client, command),
        Some(Commands::Uninstall { purge }) => handle_uninstall_command(client, &path, purge),
    }
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
fn handle_uninstall_command<C: NmClient + FirewallClient>(
    client: &C,
    path: &std::path::Path,
    purge: bool,
) -> AppResult<()> {
    let removal = crate::install::current()?;
    // A live tray daemon can re-apply policies after teardown, and would keep
    // renewing a port forward with the binary about to be gone.
    kill_other_neutron_processes();
    // A missing autostart directory is not a failure: nothing was installed.
    let autostart_dir = service::autostart::dir().ok();
    revoke_and_purge(client, path, autostart_dir.as_deref(), purge)?;
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
fn revoke_and_purge<C: NmIntrospect + FirewallClient>(
    client: &C,
    path: &std::path::Path,
    autostart_dir: Option<&std::path::Path>,
    purge: bool,
) -> AppResult<()> {
    // Evidence, not intent: the rules outlive the setting that installed them, so
    // a machine whose config was lost, corrupted, or already purged can still be
    // firewalled with no way to lift it. Both checks are unprivileged, so an
    // install that never enabled lockdown uninstalls with no password prompt.
    if config::load(path)?.lockdown_enabled || client.has_installed_lockdown_state()? {
        // One batch: rules and grant together, so this is a single prompt.
        client.teardown_lockdown(true)?;
    }
    // Saved intent is deliberately left as the user set it. Uninstall removes the
    // mechanism, it does not rewrite preferences: with `--purge` the file goes
    // anyway, and without it a reinstall restores the lockdown they chose. The
    // lock is gone either way, so a stale `true` cannot leave them unprotected.
    if let Some(dir) = autostart_dir {
        service::autostart::uninstall_in(dir)?;
    }
    remove_app_settings(path, purge)?;
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

fn handle_eligible_command<C: NmClient>(client: &C, command: EligibleCommands) -> AppResult<()> {
    let path = config::default_config_path()?;
    let app_cfg = config::load(&path)?;
    let profiles = client.list_wireguard_profiles()?;

    match command {
        EligibleCommands::List => {
            // Opt-out model: every profile is eligible unless it is in the
            // exclusion set, so listing the (smaller) excluded set is clearest.
            if app_cfg.excluded_profile_ids.is_empty() {
                println!("All profiles are eligible for startup-random (none excluded).");
            } else {
                println!("Profiles excluded from startup-random:");
                for id in &app_cfg.excluded_profile_ids {
                    if let Some(profile) = profiles.iter().find(|profile| &profile.uuid == id) {
                        println!("  {} ({})", profile.name, profile.uuid);
                    } else {
                        println!("  <unknown> ({id})");
                    }
                }
            }
        }
        EligibleCommands::Add { profile } => {
            // "Add to eligible" clears any exclusion for the profile.
            let profile_id = resolve_profile_id(&profiles, &profile)?;
            let mut changed = false;
            config::update(&path, |cfg| {
                changed = eligibility::set_profile_eligible(
                    &mut cfg.excluded_profile_ids,
                    &profile_id,
                    true,
                )
            })?;
            if changed {
                println!("Profile is now eligible for startup-random: {profile} ({profile_id})");
            } else {
                println!("Profile already eligible: {profile} ({profile_id})");
            }
        }
        EligibleCommands::Remove { profile } => {
            // "Remove from eligible" excludes the profile from startup-random.
            let profile_id = resolve_profile_id(&profiles, &profile)?;
            let mut changed = false;
            config::update(&path, |cfg| {
                changed = eligibility::set_profile_eligible(
                    &mut cfg.excluded_profile_ids,
                    &profile_id,
                    false,
                )
            })?;
            if changed {
                println!("Profile excluded from startup-random: {profile} ({profile_id})");
            } else {
                println!("Profile already excluded: {profile} ({profile_id})");
            }
        }
    }

    Ok(())
}

fn handle_favorite_command<C: NmClient>(client: &C, command: FavoriteCommands) -> AppResult<()> {
    let path = config::default_config_path()?;
    let app_cfg = config::load(&path)?;
    let profiles = client.list_wireguard_profiles()?;

    match command {
        FavoriteCommands::List => {
            for profile in &profiles {
                let is_fav = app_cfg.favorite_profile_ids.contains(&profile.uuid);
                let mark = if is_fav { "★" } else { " " };
                println!("{mark} {} ({})", profile.name, profile.uuid);
            }
        }
        FavoriteCommands::Add { profile } => {
            let profile_id = resolve_profile_id(&profiles, &profile)?;
            let mut changed = false;
            config::update(&path, |cfg| {
                changed = cfg.favorite_profile_ids.insert(profile_id.clone())
            })?;
            if changed {
                println!("Starred profile as favorite: {profile} ({profile_id})");
            } else {
                println!("Profile already in favorites: {profile} ({profile_id})");
            }
        }
        FavoriteCommands::Remove { profile } => {
            let profile_id = resolve_profile_id(&profiles, &profile)?;
            let mut changed = false;
            config::update(&path, |cfg| {
                changed = cfg.favorite_profile_ids.remove(&profile_id)
            })?;
            if changed {
                println!("Removed profile from favorites: {profile} ({profile_id})");
            } else {
                println!("Profile not in favorites: {profile} ({profile_id})");
            }
        }
    }

    Ok(())
}

fn handle_kill_switch_command<C: NmClient>(
    client: &C,
    command: KillSwitchCommands,
) -> AppResult<()> {
    let path = config::default_config_path()?;
    handle_kill_switch_command_with_path(client, command, &path)
}

fn handle_kill_switch_command_with_path<C: NmClient>(
    client: &C,
    command: KillSwitchCommands,
    path: &std::path::Path,
) -> AppResult<()> {
    match command {
        KillSwitchCommands::Status => {
            let app_cfg = config::load(path)?;
            let label = if app_cfg.kill_switch_enabled {
                "on"
            } else {
                "off"
            };
            println!("Kill switch (all profiles): {label}");
        }
        KillSwitchCommands::Enable => {
            set_global_kill_switch(client, path, true)?;
            println!(
                "Kill switch enabled for all profiles (applies on next connect; full-tunnel profiles only)."
            );
        }
        KillSwitchCommands::Disable => {
            set_global_kill_switch(client, path, false)?;
            println!("Kill switch disabled for all profiles (applies on next connect).");
        }
    }

    Ok(())
}

/// Apply the global kill-switch routing policy to every WireGuard profile and
/// persist the new intent.
///
/// Backend changes precede persistence; failures report possible partial state.
pub fn set_global_kill_switch<C: NmPolicy>(
    client: &C,
    path: &std::path::Path,
    enable: bool,
) -> AppResult<()> {
    apply_and_save_policy(
        path,
        crate::error::Policy::KillSwitch,
        || client.set_kill_switch_all(enable),
        |cfg| cfg.kill_switch_enabled = enable,
    )
}

/// Single seam for apply-before-persist policy changes.
///
/// Backend changes precede persistence; failures report possible partial state.
/// The lockdown emergency-disable in [`set_global_lockdown`] is the only
/// sanctioned bypass, and it reuses the mappers below.
pub(crate) fn apply_and_save_policy(
    path: &std::path::Path,
    policy: crate::error::Policy,
    apply: impl FnOnce() -> AppResult<()>,
    edit: impl FnOnce(&mut config::AppConfig),
) -> AppResult<()> {
    config::coordinate_policy(path, || {
        apply().map_err(|source| {
            policy_apply_error(
                policy,
                source,
                "application failed and may be partial; effective state is unknown",
            )
        })?;
        config::update(path, edit)
            .map(|_| ())
            .map_err(|source| policy_save_error(policy, source))
    })
}

fn policy_apply_error(
    policy: crate::error::Policy,
    source: AppError,
    outcome: &'static str,
) -> AppError {
    AppError::PolicyUpdate {
        policy,
        outcome,
        source: Box::new(source),
    }
}

fn policy_save_error(policy: crate::error::Policy, source: AppError) -> AppError {
    AppError::PolicyUpdate {
        policy,
        outcome: "application completed but saving failed",
        source: Box::new(source),
    }
}

fn handle_lockdown_command<C: NmClient + FirewallClient>(
    client: &C,
    command: LockdownCommands,
) -> AppResult<()> {
    let path = config::default_config_path()?;
    handle_lockdown_command_with_path(client, command, &path)
}

fn handle_lockdown_command_with_path<C: NmClient + FirewallClient>(
    client: &C,
    command: LockdownCommands,
    path: &std::path::Path,
) -> AppResult<()> {
    match command {
        LockdownCommands::Status => {
            let app_cfg = config::load(path)?;
            let label = if app_cfg.lockdown_enabled {
                "on"
            } else {
                "off"
            };
            println!("Lockdown saved intent: {label} (effective firewall state is not verified)");
        }
        LockdownCommands::Enable => {
            // Escalates and rewrites the ruleset, so it blocks for as long as
            // the user takes to authenticate. Show that something is happening.
            crate::wait::with_spinner("Enabling Lockdown", || {
                set_global_lockdown(client, path, true)
            })?;
            println!(
                "Lockdown enabled: all traffic is blocked except the WireGuard tunnel, its handshake, and DNS."
            );
        }
        LockdownCommands::Disable => {
            // The emergency path: a user reaching for this may be locked out, so
            // it must look alive even while the prompt is up.
            crate::wait::with_spinner("Disabling Lockdown", || {
                set_global_lockdown(client, path, false)
            })?;
            println!("Lockdown disabled: normal connectivity restored.");
        }
    }

    Ok(())
}

/// Apply (or remove) the always-on lockdown firewall and persist the new intent.
///
/// Like [`set_global_kill_switch`], the firewall is updated *before* the config
/// is saved, so a failed `firewall-cmd` call (the `?` returns early) leaves the
/// persisted `lockdown_enabled` flag untouched. Enabling first reads the current
/// tunnels so their interfaces and endpoints are allowed through; disabling
/// needs no tunnel data and always tears the ruleset down (the safeguard that
/// the user can never be permanently locked out).
pub fn set_global_lockdown<C: NmIntrospect + FirewallClient>(
    client: &C,
    path: &std::path::Path,
    enable: bool,
) -> AppResult<()> {
    if !enable {
        let disable = || -> AppResult<()> {
            client.disable_lockdown().map_err(|source| {
                policy_apply_error(
                    crate::error::Policy::Lockdown,
                    source,
                    "disable failed; effective state is unknown",
                )
            })?;
            config::update(path, |cfg| cfg.lockdown_enabled = false)
                .map(|_| ())
                .map_err(|source| policy_save_error(crate::error::Policy::Lockdown, source))
        };
        let mut entered = false;
        let result = config::coordinate_policy(path, || {
            entered = true;
            disable()
        });
        // If coordination storage is unavailable, still permit emergency removal.
        return if entered { result } else { disable() };
    }
    apply_and_save_policy(
        path,
        crate::error::Policy::Lockdown,
        || {
            if enable {
                let tunnels = client.wireguard_tunnels()?;
                client.enable_lockdown(&tunnels)?;
            } else {
                client.disable_lockdown()?;
            }
            Ok(())
        },
        |cfg| cfg.lockdown_enabled = enable,
    )
}

fn handle_split_tunnel_command<C: NmClient>(
    client: &C,
    command: SplitTunnelCommands,
) -> AppResult<()> {
    let path = config::default_config_path()?;
    handle_split_tunnel_command_with_path(client, command, &path)
}

fn handle_split_tunnel_command_with_path<C: NmClient>(
    client: &C,
    command: SplitTunnelCommands,
    path: &std::path::Path,
) -> AppResult<()> {
    match command {
        SplitTunnelCommands::Status => {
            let app_cfg = config::load(path)?;
            let st_cfg = split_tunnel::get_global_split_tunnel(&app_cfg);
            println!("{}", split_tunnel::format_global_status(&st_cfg));
        }
        SplitTunnelCommands::SetMode { mode } => {
            let mode = mode.parse::<config::SplitTunnelMode>()?;
            let st_cfg = split_tunnel::set_global_mode(client, path, mode)?;
            println!("Global split-tunnel mode set to: {}", st_cfg.mode);
        }
        SplitTunnelCommands::AddCidr { cidr } => {
            let (st_cfg, changed) = split_tunnel::add_global_cidr(client, path, &cidr)?;
            if changed {
                println!(
                    "Added CIDR '{}' to global split tunneling (mode: {}).",
                    cidr, st_cfg.mode
                );
            } else {
                println!(
                    "CIDR '{}' is already present in global split tunneling.",
                    cidr
                );
            }
        }
        SplitTunnelCommands::RemoveCidr { cidr } => {
            let (_, changed) = split_tunnel::remove_global_cidr(client, path, &cidr)?;
            if changed {
                println!("Removed CIDR '{}' from global split tunneling.", cidr);
            } else {
                println!("CIDR '{}' was not found in global split tunneling.", cidr);
            }
        }
        SplitTunnelCommands::AddDomain { domain } => {
            let (st_cfg, changed) = split_tunnel::add_global_domain(client, path, &domain)?;
            if changed {
                println!(
                    "Added domain '{}' to global split tunneling (mode: {}).",
                    domain, st_cfg.mode
                );
            } else {
                println!(
                    "Domain '{}' is already present in global split tunneling.",
                    domain
                );
            }
        }
        SplitTunnelCommands::RemoveDomain { domain } => {
            let (_, changed) = split_tunnel::remove_global_domain(client, path, &domain)?;
            if changed {
                println!("Removed domain '{}' from global split tunneling.", domain);
            } else {
                println!(
                    "Domain '{}' was not found in global split tunneling.",
                    domain
                );
            }
        }
        SplitTunnelCommands::Clear => {
            split_tunnel::clear_global(client, path)?;
            println!("Cleared global split-tunnel configuration.");
        }
    }

    Ok(())
}

fn handle_qbit_command<C: NmClient>(client: &C, command: QbitCommands) -> AppResult<()> {
    let path = config::default_config_path()?;
    handle_qbit_command_with_path(client, command, &path)
}

fn handle_qbit_command_with_path<C: NmClient>(
    client: &C,
    command: QbitCommands,
    path: &std::path::Path,
) -> AppResult<()> {
    match command {
        QbitCommands::Status => {
            let app_cfg = config::load(path)?;
            let qcfg = &app_cfg.qbittorrent;
            println!("=== qBittorrent Port Forwarding Integration ===");
            println!("Port Forward Mode: {}", app_cfg.port_forwarding.mode);
            println!(
                "Auto-Sync:         {}",
                if app_cfg.port_forwarding.mode.syncs_to_qbittorrent() {
                    "Enabled"
                } else {
                    "Disabled"
                }
            );
            println!("WebUI URL:         {}", qcfg.url);
            println!(
                "Authentication:    {}",
                if qcfg.username.is_some() {
                    "Configured"
                } else {
                    "None / Localhost bypass"
                }
            );
            println!(
                "Interface Binding: {}",
                if qcfg.bind_interface {
                    "Enabled"
                } else {
                    "Disabled"
                }
            );
            println!();

            let profiles = client.list_wireguard_profiles()?;
            let active = profiles.iter().find(|p| p.is_active());
            if let Some(profile) = active {
                println!("Active WireGuard Tunnel: {}", profile.name);
                if let Some(addr) = client.tunnel_address(&profile.uuid) {
                    // Asked of the gateway rather than read from
                    // `service::lease`, unlike the TUI. A one-shot command owns
                    // no lease and cannot renew one, so there is no timer here
                    // to race; asking directly keeps `qbit status` working as a
                    // diagnostic on a machine where the daemon is not running,
                    // which is exactly when it gets reached for. NAT-PMP returns
                    // the mapping already in place, so this reports the daemon's
                    // port rather than displacing it.
                    if let Some(port) = crate::portforward::port_for_tunnel_address(&addr) {
                        println!("Forwarded Port:    {port} (NAT-PMP Leased)");
                    } else {
                        println!(
                            "Forwarded Port:    Unavailable (NAT-PMP mapping pending or unsupported)"
                        );
                    }
                }
            } else {
                println!("Active WireGuard Tunnel: None (Disconnected)");
            }

            println!();
            print!("Testing WebUI connection... ");
            let mut qbit_client = crate::portforward::qbittorrent::QBittorrentClient::new(qcfg);
            match qbit_client.app_version() {
                Ok(ver) => {
                    println!("Online (qBittorrent {ver})");
                    if let Ok(prefs) = qbit_client.get_preferences() {
                        println!("qBittorrent Listening Port:  {}", prefs.listen_port);
                        if let Some(iface) = prefs.current_network_interface {
                            println!("qBittorrent Bound Interface: {iface}");
                        }
                    }
                }
                Err(err) => {
                    println!("Offline / Error ({err})");
                    println!(
                        "Note: Ensure qBittorrent is running with Web UI enabled in Options -> Web UI."
                    );
                }
            }
        }
        QbitCommands::Test => {
            let app_cfg = config::load(path)?;
            let mut qbit_client =
                crate::portforward::qbittorrent::QBittorrentClient::new(&app_cfg.qbittorrent);
            println!(
                "Connecting to qBittorrent WebUI at {}...",
                app_cfg.qbittorrent.url
            );
            let version = qbit_client.app_version()?;
            let prefs = qbit_client.get_preferences()?;
            println!("Success! Connected to qBittorrent {version}.");
            println!("Current listening port: {}", prefs.listen_port);
            if let Some(iface) = prefs.current_network_interface {
                println!("Current network interface: {iface}");
            }
        }
        QbitCommands::Sync => {
            let app_cfg = config::load(path)?;
            let profiles = client.list_wireguard_profiles()?;
            let active = profiles
                .iter()
                .find(|p| p.is_active())
                .ok_or(AppError::NoActiveProfile)?;

            let addr = client.tunnel_address(&active.uuid).ok_or_else(|| {
                AppError::PortForward("no IPv4 address found on active tunnel".to_string())
            })?;

            // As in `qbit status`: a one-shot command holds no lease, so it asks
            // the gateway instead of reading the daemon's publication and keeps
            // working with no daemon running. The request renews the existing
            // mapping rather than replacing it, so the port pushed here is the
            // one the daemon is already holding.
            let port = crate::portforward::port_for_tunnel_address(&addr).ok_or_else(|| {
                AppError::PortForward(
                    "gateway did not return a forwarded port via NAT-PMP".to_string(),
                )
            })?;

            let report = qbittorrent::sync_port(client, &app_cfg.qbittorrent, &active.uuid, port)?;

            println!("qBittorrent port synchronized successfully!");
            if let Some(prev) = report.previous_port {
                println!("Port: {} -> {}", prev, report.new_port);
            } else {
                println!("Port: {}", report.new_port);
            }
            if let Some(bound) = report.bound_interface {
                println!("Bound to interface: {}", bound);
            }
        }
        QbitCommands::Enable => {
            config::update(path, |cfg| {
                cfg.port_forwarding.mode = crate::config::PortForwardMode::ForwardAndSync
            })?;
            println!("qBittorrent automatic port forwarding sync enabled.");
        }
        QbitCommands::Disable => {
            config::update(path, |cfg| {
                cfg.port_forwarding.mode = crate::config::PortForwardMode::Forward
            })?;
            println!(
                "qBittorrent automatic port forwarding sync disabled (port forwarding stays on)."
            );
        }
        QbitCommands::Config {
            url,
            username,
            password,
            bind,
        } => {
            let app_cfg = config::update(path, |app_cfg| {
                if let Some(u) = url {
                    app_cfg.qbittorrent.url = u;
                }
                if let Some(user) = username {
                    app_cfg.qbittorrent.username = if user.trim().is_empty() {
                        None
                    } else {
                        Some(user)
                    };
                }
                if let Some(pass) = password {
                    app_cfg.qbittorrent.password = if pass.is_empty() { None } else { Some(pass) };
                }
                if let Some(b) = bind {
                    app_cfg.qbittorrent.bind_interface = b;
                }
            })?;
            println!("qBittorrent configuration updated.");
            println!("URL:            {}", app_cfg.qbittorrent.url);
            println!(
                "Username:       {}",
                app_cfg.qbittorrent.username.as_deref().unwrap_or("<none>")
            );
            println!(
                "Bind Interface: {}",
                if app_cfg.qbittorrent.bind_interface {
                    "true"
                } else {
                    "false"
                }
            );
        }
    }

    Ok(())
}

/// Rebuild the lockdown ruleset from the current profile set, if lockdown is on.
///
/// The allow-list pins each profile's interface and peer endpoint, so it is only
/// correct for the profiles that existed when it was built. A profile added
/// afterwards gets an interface with no matching rule and is blocked by the
/// terminal DROP -- it simply fails to connect, and because new profiles are
/// eligible by default the startup selector can pick it and silently fall
/// through to another. Removing a profile leaves a stale rule behind.
///
/// Does nothing when lockdown is off, so callers can invoke it unconditionally
/// after the profile set changes.
pub fn rebuild_lockdown_if_enabled<C: FirewallClient>(
    client: &C,
    path: &std::path::Path,
) -> AppResult<()> {
    config::coordinate_policy(path, || {
        if !config::load(path)?.lockdown_enabled {
            return Ok(());
        }
        client.refresh_lockdown(None)
    })
}

/// Terminate all running neutron processes on the system except the current process.
pub fn kill_other_neutron_processes() {
    let current_pid = std::process::id();
    #[cfg(unix)]
    {
        unsafe extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }

        let my_exe = std::env::current_exe().ok();

        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(pid_str) = name.to_str() else {
                    continue;
                };
                let Ok(pid) = pid_str.parse::<u32>() else {
                    continue;
                };
                let exe_path = entry.path().join("exe");
                let is_same_binary = match (&my_exe, std::fs::read_link(&exe_path)) {
                    (Some(my), Ok(target)) => target == *my,
                    _ => false,
                };

                let is_neutron_comm = std::fs::read_to_string(entry.path().join("comm"))
                    .map(|comm| comm.trim() == "neutron")
                    .unwrap_or(false);

                if should_terminate_process(pid, current_pid, is_same_binary, is_neutron_comm) {
                    unsafe {
                        let _ = kill(pid as i32, 15); // SIGTERM
                    }
                }
            }
        }
    }
}

fn should_terminate_process(
    pid: u32,
    current_pid: u32,
    is_same_binary: bool,
    is_neutron_comm: bool,
) -> bool {
    pid > 1 && pid != current_pid && (is_same_binary || is_neutron_comm)
}

fn resolve_profile_id(
    profiles: &[WireguardProfile],
    profile_identifier: &str,
) -> AppResult<String> {
    let profile = nm::find_unique_profile_by_identifier(profiles, profile_identifier)?;
    Ok(profile.uuid.clone())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn automatic_rebuild_rechecks_disabled_intent_after_coordination() {
        let path = crate::testing::temp_config_path("rebuild-coordination");
        config::save(
            &path,
            &config::AppConfig {
                lockdown_enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
        let client = crate::testing::MockNmClient::default();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let worker = config::coordinate_policy(&path, || {
                let worker = scope.spawn(|| {
                    started_tx.send(()).unwrap();
                    done_tx
                        .send(rebuild_lockdown_if_enabled(&client, &path))
                        .unwrap();
                });
                started_rx.recv().unwrap();
                assert!(
                    done_rx
                        .recv_timeout(std::time::Duration::from_millis(30))
                        .is_err()
                );
                config::update(&path, |cfg| cfg.lockdown_enabled = false)?;
                Ok(worker)
            })
            .unwrap();
            worker.join().unwrap();
        });
        done_rx.recv().unwrap().unwrap();
        assert!(client.lockdown_calls().is_empty());
        crate::testing::remove_temp_config(&path);
    }

    #[test]
    fn policy_success_then_save_failure_reports_uncertain_state() {
        use crate::error::Policy;
        let path = crate::testing::temp_config_path("policy-save-failure");
        config::save(
            &path,
            &config::AppConfig {
                lockdown_enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
        // A directory at the stable lock path deterministically prevents saving,
        // including when tests run as root. Reading the config still succeeds.
        std::fs::create_dir(format!("{}.blocked", path.display())).unwrap();
        let lock = format!("{}.lock", path.display());
        std::fs::remove_file(&lock).unwrap();
        std::fs::rename(format!("{}.blocked", path.display()), &lock).unwrap();
        std::fs::create_dir(format!("{}.policy.lock", path.display())).unwrap();
        let client = crate::testing::MockNmClient::default();
        let error = set_global_lockdown(&client, &path, false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("application completed but saving failed")
        );
        assert_eq!(client.lockdown_calls(), vec!["lockdown:teardown:rules"]);
        let saved = config::load(&path).unwrap();
        assert!(saved.lockdown_enabled);
        let mut state = crate::tui::state::TuiState::new(path.clone(), saved);
        state.set_error(&error);
        state.set_status("unrelated action");
        assert!(state.uncertain_policies.contains(&Policy::Lockdown));
        std::fs::remove_dir(format!("{}.policy.lock", path.display())).unwrap();
        let backend_error = apply_and_save_policy(
            &path,
            Policy::KillSwitch,
            || Err(AppError::CommandFailed("second profile rejected".into())),
            |_| {},
        )
        .unwrap_err();
        assert!(backend_error.to_string().contains("may be partial"));
        crate::testing::remove_temp_config(&path);
    }
    use crate::error::AppError;

    fn profile(name: &str, uuid: &str) -> WireguardProfile {
        WireguardProfile {
            name: name.to_string(),
            uuid: uuid.to_string(),
            state: crate::nm::ProfileState::Inactive,
        }
    }

    #[test]
    fn resolves_uuid_identifier_directly() {
        let profiles = vec![profile("wg-us", "uuid-1")];

        let resolved = resolve_profile_id(&profiles, "uuid-1").expect("uuid should resolve");

        assert_eq!(resolved, "uuid-1");
    }

    #[test]
    fn resolves_unique_name_to_uuid() {
        let profiles = vec![profile("wg-us", "uuid-1"), profile("wg-eu", "uuid-2")];

        let resolved = resolve_profile_id(&profiles, "wg-eu").expect("name should resolve");

        assert_eq!(resolved, "uuid-2");
    }

    #[test]
    fn returns_ambiguous_error_for_duplicate_names() {
        let profiles = vec![profile("wg-us", "uuid-1"), profile("wg-us", "uuid-2")];

        let result = resolve_profile_id(&profiles, "wg-us");

        assert!(matches!(
            result,
            Err(AppError::AmbiguousProfileName(name)) if name == "wg-us"
        ));
    }

    #[test]
    fn returns_not_found_for_missing_identifier() {
        let profiles = vec![profile("wg-us", "uuid-1")];

        let result = resolve_profile_id(&profiles, "wg-eu");

        assert!(matches!(result, Err(AppError::ProfileNotFound(name)) if name == "wg-eu"));
    }

    #[test]
    fn cli_subcommand_routing() {
        let cli = Cli {
            command: Some(Commands::List),
        };
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let result = execute(&client, cli);
        assert!(result.is_ok());
    }

    #[test]
    fn termination_selection_excludes_self_system_and_unrelated_processes() {
        for (pid, same_binary, neutron_comm, expected) in [
            (0, true, true, false),
            (1, true, true, false),
            (42, true, true, false),
            (43, false, false, false),
            (43, true, false, true),
            (43, false, true, true),
        ] {
            assert_eq!(
                should_terminate_process(pid, 42, same_binary, neutron_comm),
                expected
            );
        }
    }

    #[test]
    fn kill_switch_enable_applies_globally_and_persists() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();

        handle_kill_switch_command_with_path(&client, KillSwitchCommands::Enable, &path)
            .expect("enable should succeed");

        assert_eq!(client.kill_switch_calls(), vec!["kill-switch-all:on"]);
        let persisted = config::load(&path).expect("config should load");
        assert!(persisted.kill_switch_enabled);
        cleanup_test_config(&path);
    }

    #[test]
    fn kill_switch_disable_applies_globally_and_persists() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();
        config::save(
            &path,
            &config::AppConfig {
                kill_switch_enabled: true,
                ..config::AppConfig::default()
            },
        )
        .expect("config should save");

        handle_kill_switch_command_with_path(&client, KillSwitchCommands::Disable, &path)
            .expect("disable should succeed");

        assert_eq!(client.kill_switch_calls(), vec!["kill-switch-all:off"]);
        let persisted = config::load(&path).expect("config should load");
        assert!(!persisted.kill_switch_enabled);
        cleanup_test_config(&path);
    }

    #[test]
    fn kill_switch_status_does_not_change_nm_or_config() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();
        config::save(
            &path,
            &config::AppConfig {
                kill_switch_enabled: true,
                ..config::AppConfig::default()
            },
        )
        .expect("config should save");

        handle_kill_switch_command_with_path(&client, KillSwitchCommands::Status, &path)
            .expect("status should succeed");

        // Status only reports; it must not touch NetworkManager or the config.
        assert!(client.kill_switch_calls().is_empty());
        let persisted = config::load(&path).expect("config should load");
        assert!(persisted.kill_switch_enabled);
        cleanup_test_config(&path);
    }

    #[test]
    fn kill_switch_status_defaults_to_off_without_config() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();

        // No config file: status reads the default (off) instead of erroring,
        // and still does not invoke NetworkManager.
        handle_kill_switch_command_with_path(&client, KillSwitchCommands::Status, &path)
            .expect("status should succeed with default config");

        assert!(client.kill_switch_calls().is_empty());
        cleanup_test_config(&path);
    }

    #[test]
    fn kill_switch_enable_does_not_persist_when_nm_fails() {
        let client =
            crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]).fail_kill_switch();
        let path = unique_test_config_path();

        let result =
            handle_kill_switch_command_with_path(&client, KillSwitchCommands::Enable, &path);

        assert!(matches!(
            result,
            Err(AppError::PolicyUpdate {
                policy: crate::error::Policy::KillSwitch,
                ..
            })
        ));
        // The change was attempted, but because NetworkManager rejected it the
        // enabled intent must not be persisted.
        assert_eq!(client.kill_switch_calls(), vec!["kill-switch-all:on"]);
        let persisted = config::load(&path).expect("config should load");
        assert!(!persisted.kill_switch_enabled);
        cleanup_test_config(&path);
    }

    #[test]
    fn kill_switch_disable_keeps_previous_state_when_nm_fails() {
        let client =
            crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]).fail_kill_switch();
        let path = unique_test_config_path();
        config::save(
            &path,
            &config::AppConfig {
                kill_switch_enabled: true,
                ..config::AppConfig::default()
            },
        )
        .expect("config should save");

        let result =
            handle_kill_switch_command_with_path(&client, KillSwitchCommands::Disable, &path);

        assert!(matches!(
            result,
            Err(AppError::PolicyUpdate {
                policy: crate::error::Policy::KillSwitch,
                ..
            })
        ));
        // A failed disable must leave the previously-enabled state intact.
        let persisted = config::load(&path).expect("config should load");
        assert!(persisted.kill_switch_enabled);
        cleanup_test_config(&path);
    }

    #[test]
    fn kill_switch_enable_then_disable_round_trips_state() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();

        handle_kill_switch_command_with_path(&client, KillSwitchCommands::Enable, &path)
            .expect("enable should succeed");
        assert!(
            config::load(&path)
                .expect("config should load")
                .kill_switch_enabled
        );

        handle_kill_switch_command_with_path(&client, KillSwitchCommands::Disable, &path)
            .expect("disable should succeed");
        assert!(
            !config::load(&path)
                .expect("config should load")
                .kill_switch_enabled
        );

        assert_eq!(
            client.kill_switch_calls(),
            vec!["kill-switch-all:on", "kill-switch-all:off"]
        );
        cleanup_test_config(&path);
    }

    #[test]
    fn lockdown_enable_applies_and_persists() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();

        handle_lockdown_command_with_path(&client, LockdownCommands::Enable, &path)
            .expect("enable should succeed");

        assert_eq!(client.lockdown_calls(), vec!["lockdown:on"]);
        let persisted = config::load(&path).expect("config should load");
        assert!(persisted.lockdown_enabled);
        cleanup_test_config(&path);
    }

    #[test]
    fn rebuild_lockdown_reapplies_rules_when_lockdown_is_on() {
        // A profile imported after lockdown was enabled has no allow-rule and
        // is blocked by the terminal DROP, so the ruleset has to be rebuilt
        // whenever the profile set changes.
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();
        config::save(
            &path,
            &config::AppConfig {
                lockdown_enabled: true,
                ..config::AppConfig::default()
            },
        )
        .expect("config should save");

        rebuild_lockdown_if_enabled(&client, &path).expect("rebuild should succeed");

        assert_eq!(client.lockdown_calls(), vec!["lockdown:refresh"]);
        cleanup_test_config(&path);
    }

    #[test]
    fn rebuild_lockdown_does_nothing_when_lockdown_is_off() {
        // Callers invoke this unconditionally after any profile change, so it
        // must not install a ruleset the user never asked for.
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();
        config::save(&path, &config::AppConfig::default()).expect("config should save");

        rebuild_lockdown_if_enabled(&client, &path).expect("rebuild should succeed");

        assert!(client.lockdown_calls().is_empty());
        cleanup_test_config(&path);
    }

    #[test]
    fn uninstall_revokes_lockdown_and_the_autostart_entry_only_when_enabled() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let home = decoy_config_home("revoke");
        let path = home.join("neutron/config.toml");
        let autostart_dir = home.join("autostart");
        service::autostart::install_in(&autostart_dir).expect("autostart entry should install");

        // Nothing installed and intent off: no teardown, so no password prompt.
        config::save(&path, &config::AppConfig::default()).expect("config should save");
        revoke_and_purge(&client, &path, Some(&autostart_dir), false)
            .expect("revoke should succeed");
        assert!(client.lockdown_calls().is_empty());
        assert!(!service::autostart::is_installed_in(&autostart_dir));

        // Saved intent on: one batch for the rules and the grant together.
        config::save(
            &path,
            &config::AppConfig {
                lockdown_enabled: true,
                ..config::AppConfig::default()
            },
        )
        .expect("config should save");
        service::autostart::install_in(&autostart_dir).expect("autostart entry should install");

        revoke_and_purge(&client, &path, Some(&autostart_dir), false)
            .expect("revoke should succeed");

        assert_eq!(
            client.lockdown_calls(),
            vec!["lockdown:teardown:rules+grant"]
        );
        // Uninstall removes the mechanism, it does not rewrite preferences: a
        // reinstall should restore the lockdown the user had chosen.
        assert!(
            config::load(&path)
                .expect("config should load")
                .lockdown_enabled
        );
        assert!(!service::autostart::is_installed_in(&autostart_dir));
        // Purge was not asked for, so the settings must have survived it.
        assert!(path.exists());
        remove_temp_root(&home);
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
        let client = crate::testing::MockNmClient::new(vec![]).fail_lockdown();
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
    fn lockdown_disable_applies_and_persists() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();
        config::save(
            &path,
            &config::AppConfig {
                lockdown_enabled: true,
                ..config::AppConfig::default()
            },
        )
        .expect("config should save");

        handle_lockdown_command_with_path(&client, LockdownCommands::Disable, &path)
            .expect("disable should succeed");

        assert_eq!(client.lockdown_calls(), vec!["lockdown:teardown:rules"]);
        let persisted = config::load(&path).expect("config should load");
        assert!(!persisted.lockdown_enabled);
        cleanup_test_config(&path);
    }

    #[test]
    fn lockdown_status_does_not_change_firewall_or_config() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();
        config::save(
            &path,
            &config::AppConfig {
                lockdown_enabled: true,
                ..config::AppConfig::default()
            },
        )
        .expect("config should save");

        handle_lockdown_command_with_path(&client, LockdownCommands::Status, &path)
            .expect("status should succeed");

        // Status only reports; it must not touch the firewall or the config.
        assert!(client.lockdown_calls().is_empty());
        let persisted = config::load(&path).expect("config should load");
        assert!(persisted.lockdown_enabled);
        cleanup_test_config(&path);
    }

    #[test]
    fn lockdown_status_defaults_to_off_without_config() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();

        // No config file: status reads the default (off) instead of erroring,
        // and still does not invoke the firewall.
        handle_lockdown_command_with_path(&client, LockdownCommands::Status, &path)
            .expect("status should succeed with default config");

        assert!(client.lockdown_calls().is_empty());
        cleanup_test_config(&path);
    }

    #[test]
    fn lockdown_enable_does_not_persist_when_firewall_fails() {
        let client =
            crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]).fail_lockdown();
        let path = unique_test_config_path();

        let result = handle_lockdown_command_with_path(&client, LockdownCommands::Enable, &path);

        assert!(matches!(
            result,
            Err(AppError::PolicyUpdate {
                policy: crate::error::Policy::Lockdown,
                ..
            })
        ));
        // The change was attempted, but because the firewall rejected it the
        // enabled intent must not be persisted.
        assert_eq!(client.lockdown_calls(), vec!["lockdown:on"]);
        let persisted = config::load(&path).expect("config should load");
        assert!(!persisted.lockdown_enabled);
        cleanup_test_config(&path);
    }

    #[test]
    fn lockdown_disable_keeps_previous_state_when_firewall_fails() {
        let client =
            crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]).fail_lockdown();
        let path = unique_test_config_path();
        config::save(
            &path,
            &config::AppConfig {
                lockdown_enabled: true,
                ..config::AppConfig::default()
            },
        )
        .expect("config should save");

        let result = handle_lockdown_command_with_path(&client, LockdownCommands::Disable, &path);

        assert!(matches!(
            result,
            Err(AppError::PolicyUpdate {
                policy: crate::error::Policy::Lockdown,
                ..
            })
        ));
        // A failed disable must leave the previously-enabled state intact.
        let persisted = config::load(&path).expect("config should load");
        assert!(persisted.lockdown_enabled);
        cleanup_test_config(&path);
    }

    #[test]
    fn lockdown_enable_then_disable_round_trips_state() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();

        handle_lockdown_command_with_path(&client, LockdownCommands::Enable, &path)
            .expect("enable should succeed");
        assert!(
            config::load(&path)
                .expect("config should load")
                .lockdown_enabled
        );

        handle_lockdown_command_with_path(&client, LockdownCommands::Disable, &path)
            .expect("disable should succeed");
        assert!(
            !config::load(&path)
                .expect("config should load")
                .lockdown_enabled
        );

        assert_eq!(
            client.lockdown_calls(),
            vec!["lockdown:on", "lockdown:teardown:rules"]
        );
        cleanup_test_config(&path);
    }

    #[test]
    fn split_tunnel_commands_flow() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();

        // 1. Set mode to include
        handle_split_tunnel_command_with_path(
            &client,
            SplitTunnelCommands::SetMode {
                mode: "include".to_string(),
            },
            &path,
        )
        .expect("set mode should succeed");

        assert_eq!(
            client.split_tunnel_calls(),
            vec!["split-tunnel-all:include:0:0"]
        );

        // 2. Add CIDR
        handle_split_tunnel_command_with_path(
            &client,
            SplitTunnelCommands::AddCidr {
                cidr: "10.0.0.0/8".to_string(),
            },
            &path,
        )
        .expect("add cidr should succeed");

        let persisted = config::load(&path).expect("config should load");
        assert_eq!(
            persisted.global_split_tunnel.mode,
            config::SplitTunnelMode::Include
        );
        assert_eq!(
            persisted.global_split_tunnel.cidrs,
            vec!["10.0.0.0/8".to_string()]
        );

        // 3. Status check
        handle_split_tunnel_command_with_path(&client, SplitTunnelCommands::Status, &path)
            .expect("status check should succeed");

        // 4. Clear
        handle_split_tunnel_command_with_path(&client, SplitTunnelCommands::Clear, &path)
            .expect("clear should succeed");

        let persisted = config::load(&path).expect("config should load");
        assert_eq!(
            persisted.global_split_tunnel.mode,
            config::SplitTunnelMode::Disabled
        );

        cleanup_test_config(&path);
    }

    #[test]
    fn qbit_enable_and_disable_persists() {
        use crate::config::PortForwardMode;

        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();

        handle_qbit_command_with_path(&client, QbitCommands::Enable, &path)
            .expect("enable should succeed");
        let loaded = config::load(&path).expect("config should load");
        assert_eq!(loaded.port_forwarding.mode, PortForwardMode::ForwardAndSync);

        handle_qbit_command_with_path(&client, QbitCommands::Disable, &path)
            .expect("disable should succeed");
        let loaded = config::load(&path).expect("config should load");
        assert_eq!(loaded.port_forwarding.mode, PortForwardMode::Forward);

        cleanup_test_config(&path);
    }

    #[test]
    fn qbit_config_updates_settings() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();

        handle_qbit_command_with_path(
            &client,
            QbitCommands::Config {
                url: Some("http://192.168.1.100:8080".to_string()),
                username: Some("myuser".to_string()),
                password: Some("mypass".to_string()),
                bind: Some(true),
            },
            &path,
        )
        .expect("config should succeed");

        let loaded = config::load(&path).expect("config should load");
        assert_eq!(loaded.qbittorrent.url, "http://192.168.1.100:8080");
        assert_eq!(loaded.qbittorrent.username.as_deref(), Some("myuser"));
        assert_eq!(loaded.qbittorrent.password.as_deref(), Some("mypass"));
        assert!(loaded.qbittorrent.bind_interface);

        cleanup_test_config(&path);
    }

    fn unique_test_config_path() -> std::path::PathBuf {
        crate::testing::temp_config_path("app")
    }

    fn cleanup_test_config(path: &std::path::Path) {
        crate::testing::remove_temp_config(path);
    }
}
