pub(crate) mod eligibility;
pub mod profile_list;
pub mod refresh_sync;
pub mod split_tunnel;
pub mod sync;

use clap::{Parser, Subcommand};

use crate::config;
#[cfg(feature = "qbittorrent")]
use crate::error::AppError;
use crate::error::AppResult;
use crate::firewall::FirewallClient;
use crate::nm::{self, NmClient, WireguardProfile};
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
    #[cfg(feature = "qbittorrent")]
    #[command(alias = "qbittorrent")]
    Qbit {
        #[command(subcommand)]
        command: QbitCommands,
    },
    /// Run the persistent system tray AppIndicator daemon in the background
    #[command(alias = "daemon")]
    Indicator,
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
#[cfg(feature = "qbittorrent")]
enum QbitCommands {
    /// Show qBittorrent integration status, WebUI connectivity, and current ports
    Status,
    /// Test connection to the qBittorrent WebUI
    Test,
    /// Sync active VPN forwarded port to qBittorrent immediately
    Sync,
    /// Enable automatic port forwarding sync with qBittorrent
    Enable,
    /// Disable automatic port forwarding sync with qBittorrent
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
    let cli = Cli::parse();
    execute(client, cli)
}

fn execute<C: NmClient + FirewallClient + Clone + Send + Sync + 'static>(
    client: &C,
    cli: Cli,
) -> AppResult<()> {
    match cli.command {
        None | Some(Commands::Tui) => crate::tui::run(client.clone()),
        Some(Commands::Indicator) => {
            crate::service::indicator::run_standalone_indicator(client.clone())
        }
        Some(Commands::Sync) => {
            let path = config::default_config_path()?;
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
            let path = config::default_config_path()?;
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
        Some(Commands::Connect { profile }) => client.connect(&profile),
        Some(Commands::Disconnect) => client.disconnect_active(),
        Some(Commands::Switch { profile }) => client.switch_to(&profile),
        Some(Commands::StartupRandom) => {
            let res = service::run_startup_random(client);
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
        #[cfg(feature = "qbittorrent")]
        Some(Commands::Qbit { command }) => handle_qbit_command(client, command),
    }
}

fn handle_eligible_command<C: NmClient>(client: &C, command: EligibleCommands) -> AppResult<()> {
    let path = config::default_config_path()?;
    let mut app_cfg = config::load(&path)?;
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
            if eligibility::set_profile_eligible(
                &mut app_cfg.excluded_profile_ids,
                &profile_id,
                true,
            ) {
                config::save(&path, &app_cfg)?;
                println!("Profile is now eligible for startup-random: {profile} ({profile_id})");
            } else {
                println!("Profile already eligible: {profile} ({profile_id})");
            }
        }
        EligibleCommands::Remove { profile } => {
            // "Remove from eligible" excludes the profile from startup-random.
            let profile_id = resolve_profile_id(&profiles, &profile)?;
            if eligibility::set_profile_eligible(
                &mut app_cfg.excluded_profile_ids,
                &profile_id,
                false,
            ) {
                config::save(&path, &app_cfg)?;
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
    let mut app_cfg = config::load(&path)?;
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
            if app_cfg.favorite_profile_ids.insert(profile_id.clone()) {
                config::save(&path, &app_cfg)?;
                println!("Starred profile as favorite: {profile} ({profile_id})");
            } else {
                println!("Profile already in favorites: {profile} ({profile_id})");
            }
        }
        FavoriteCommands::Remove { profile } => {
            let profile_id = resolve_profile_id(&profiles, &profile)?;
            if app_cfg.favorite_profile_ids.remove(&profile_id) {
                config::save(&path, &app_cfg)?;
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
/// NetworkManager is updated *before* the config is saved, so a failed `nmcli`
/// call (the `?` returns early) leaves the persisted `kill_switch_enabled` flag
/// untouched. This apply-then-persist ordering is a correctness invariant — see
/// the `kill_switch_*_when_nm_fails` tests — and is shared by both the CLI
/// handler and the GUI toggle so it lives in exactly one place.
pub fn set_global_kill_switch<C: NmClient>(
    client: &C,
    path: &std::path::Path,
    enable: bool,
) -> AppResult<()> {
    client.set_kill_switch_all(enable)?;
    let mut app_cfg = config::load(path)?;
    app_cfg.kill_switch_enabled = enable;
    config::save(path, &app_cfg)
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
            println!("Lockdown (always-on firewall): {label}");
        }
        LockdownCommands::Enable => {
            set_global_lockdown(client, path, true)?;
            println!(
                "Lockdown enabled: all traffic is blocked except the WireGuard tunnel, its handshake, and DNS."
            );
        }
        LockdownCommands::Disable => {
            set_global_lockdown(client, path, false)?;
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
pub fn set_global_lockdown<C: NmClient + FirewallClient>(
    client: &C,
    path: &std::path::Path,
    enable: bool,
) -> AppResult<()> {
    if enable {
        let tunnels = client.wireguard_tunnels()?;
        client.enable_lockdown(&tunnels)?;
    } else {
        client.disable_lockdown()?;
    }
    let mut app_cfg = config::load(path)?;
    app_cfg.lockdown_enabled = enable;
    config::save(path, &app_cfg)
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

#[cfg(feature = "qbittorrent")]
fn handle_qbit_command<C: NmClient>(client: &C, command: QbitCommands) -> AppResult<()> {
    let path = config::default_config_path()?;
    handle_qbit_command_with_path(client, command, &path)
}

#[cfg(feature = "qbittorrent")]
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
            println!(
                "Auto-Sync:         {}",
                if qcfg.enabled { "Enabled" } else { "Disabled" }
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
                println!("Active VPN Tunnel: {}", profile.name);
                if let Some(addr) = client.tunnel_address(&profile.uuid) {
                    if let Some(port) = crate::portforward::port_for_tunnel_address(&addr) {
                        println!("Forwarded Port:    {port} (NAT-PMP Leased)");
                    } else {
                        println!(
                            "Forwarded Port:    Unavailable (NAT-PMP mapping pending or unsupported)"
                        );
                    }
                }
            } else {
                println!("Active VPN Tunnel: None (Disconnected)");
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

            let port = crate::portforward::port_for_tunnel_address(&addr).ok_or_else(|| {
                AppError::PortForward(
                    "gateway did not return a forwarded port via NAT-PMP".to_string(),
                )
            })?;

            let diag = client.get_profile_diagnostics(&active.uuid, true).ok();
            let iface = diag.as_ref().map(|d| d.interface_name.as_str());

            let mut qbit_client =
                crate::portforward::qbittorrent::QBittorrentClient::new(&app_cfg.qbittorrent);
            let report = qbit_client.sync_port(port, iface)?;

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
            let mut app_cfg = config::load(path)?;
            app_cfg.qbittorrent.enabled = true;
            config::save(path, &app_cfg)?;
            println!("qBittorrent automatic port forwarding sync enabled.");
        }
        QbitCommands::Disable => {
            let mut app_cfg = config::load(path)?;
            app_cfg.qbittorrent.enabled = false;
            config::save(path, &app_cfg)?;
            println!("qBittorrent automatic port forwarding sync disabled.");
        }
        QbitCommands::Config {
            url,
            username,
            password,
            bind,
        } => {
            let mut app_cfg = config::load(path)?;
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
            config::save(path, &app_cfg)?;
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
/// terminal REJECT -- it simply fails to connect, and because new profiles are
/// eligible by default the startup selector can pick it and silently fall
/// through to another. Removing a profile leaves a stale rule behind.
///
/// Does nothing when lockdown is off, so callers can invoke it unconditionally
/// after the profile set changes.
pub fn rebuild_lockdown_if_enabled<C: NmClient + FirewallClient>(
    client: &C,
    path: &std::path::Path,
) -> AppResult<()> {
    if !config::load(path)?.lockdown_enabled {
        return Ok(());
    }
    let tunnels = client.wireguard_tunnels()?;
    client.enable_lockdown(&tunnels)
}

/// Terminate all running neutron processes on the system except the current process.
pub fn kill_other_neutron_processes() {
    let current_pid = std::process::id();
    #[cfg(unix)]
    {
        unsafe extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }

        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(pid_str) = name.to_str() else {
                    continue;
                };
                let Ok(pid) = pid_str.parse::<u32>() else {
                    continue;
                };
                if pid == current_pid || pid <= 1 {
                    continue;
                }
                let cmdline_path = entry.path().join("cmdline");
                if let Ok(cmdline) = std::fs::read_to_string(cmdline_path) {
                    let is_neutron =
                        cmdline.contains("neutron") || cmdline.contains("io.gitlab.neutron");
                    if is_neutron {
                        unsafe {
                            let _ = kill(pid as i32, 15); // SIGTERM
                        }
                    }
                }
            }
        }
    }
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
    use super::*;
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
    fn kill_other_neutron_processes_does_not_panic() {
        // Safe to call when no other processes exist or in test environments
        kill_other_neutron_processes();
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

        assert!(matches!(result, Err(AppError::CommandFailed(_))));
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

        assert!(matches!(result, Err(AppError::CommandFailed(_))));
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
        // is blocked by the terminal REJECT, so the ruleset has to be rebuilt
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

        assert_eq!(client.lockdown_calls(), vec!["lockdown:on"]);
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

        assert_eq!(client.lockdown_calls(), vec!["lockdown:off"]);
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

        assert!(matches!(result, Err(AppError::Firewall(_))));
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

        assert!(matches!(result, Err(AppError::Firewall(_))));
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

        assert_eq!(client.lockdown_calls(), vec!["lockdown:on", "lockdown:off"]);
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

    #[cfg(feature = "qbittorrent")]
    #[test]
    fn qbit_enable_and_disable_persists() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let path = unique_test_config_path();

        handle_qbit_command_with_path(&client, QbitCommands::Enable, &path)
            .expect("enable should succeed");
        let loaded = config::load(&path).expect("config should load");
        assert!(loaded.qbittorrent.enabled);

        handle_qbit_command_with_path(&client, QbitCommands::Disable, &path)
            .expect("disable should succeed");
        let loaded = config::load(&path).expect("config should load");
        assert!(!loaded.qbittorrent.enabled);

        cleanup_test_config(&path);
    }

    #[cfg(feature = "qbittorrent")]
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
