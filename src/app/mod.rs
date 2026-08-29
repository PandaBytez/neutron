pub(crate) mod eligibility;
pub mod profile_list;
pub mod refresh_sync;
pub(crate) mod split_tunnel;

use clap::{Parser, Subcommand};

use crate::config;
use crate::error::AppResult;
use crate::firewall::FirewallClient;
use crate::nm::{self, NmClient, WireguardProfile};
use crate::service;

#[derive(Debug, Parser)]
#[command(name = "neutron-vpn")]
#[command(about = "Neutron VPN - WireGuard profile manager via NetworkManager")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    List,
    Gui {
        /// Start in the background with no window, showing only the tray icon.
        /// Used by the autostart entry: this launch is what connects a random
        /// eligible profile at login, and it has no reason to steal focus.
        #[arg(long)]
        hidden: bool,
    },
    Connect {
        profile: String,
    },
    Disconnect,
    Switch {
        profile: String,
    },
    Eligible {
        #[command(subcommand)]
        command: EligibleCommands,
    },
    StartupRandom,
    KillSwitch {
        #[command(subcommand)]
        command: KillSwitchCommands,
    },
    Lockdown {
        #[command(subcommand)]
        command: LockdownCommands,
    },
    SplitTunnel {
        #[command(subcommand)]
        command: SplitTunnelCommands,
    },
}

#[derive(Debug, Subcommand)]
enum EligibleCommands {
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

pub fn run<C: NmClient + FirewallClient + Clone + Send + 'static>(client: &C) -> AppResult<()> {
    let cli = Cli::parse();
    execute(client, cli)
}

fn execute<C: NmClient + FirewallClient + Clone + Send + 'static>(
    client: &C,
    cli: Cli,
) -> AppResult<()> {
    match cli.command {
        Commands::List => {
            let path = config::default_config_path()?;
            let app_cfg = config::load(&path)?;
            let profiles = client.list_wireguard_profiles()?;
            let rows = profile_list::build_rows(
                &profiles,
                &app_cfg.excluded_profile_ids,
                &app_cfg.profile_custom_info,
            );
            for row in rows {
                println!("{}", profile_list::format_cli_row(&row));
            }
            Ok(())
        }
        Commands::Gui { hidden } => crate::gui::run(client.clone(), hidden),
        Commands::Connect { profile } => client.connect(&profile),
        Commands::Disconnect => client.disconnect_active(),
        Commands::Switch { profile } => client.switch_to(&profile),
        Commands::StartupRandom => {
            match service::run_startup_random(client)? {
                service::StartupRandomResult::Connected(selected) => {
                    println!("Startup random connected: {selected}");
                }
                service::StartupRandomResult::SkippedAlreadyActive => {
                    println!("Startup random skipped: a WireGuard profile is already active");
                }
            }
            Ok(())
        }
        Commands::Eligible { command } => handle_eligible_command(client, command),
        Commands::KillSwitch { command } => handle_kill_switch_command(client, command),
        Commands::Lockdown { command } => handle_lockdown_command(client, command),
        Commands::SplitTunnel { command } => handle_split_tunnel_command(client, command),
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
pub(crate) fn set_global_kill_switch<C: NmClient>(
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
pub(crate) fn set_global_lockdown<C: NmClient + FirewallClient>(
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
            let st_cfg = split_tunnel::add_global_cidr(client, path, &cidr)?;
            println!(
                "Added CIDR '{}' to global split tunneling (mode: {}).",
                cidr, st_cfg.mode
            );
        }
        SplitTunnelCommands::RemoveCidr { cidr } => {
            let _ = split_tunnel::remove_global_cidr(client, path, &cidr)?;
            println!("Removed CIDR '{}' from global split tunneling.", cidr);
        }
        SplitTunnelCommands::AddDomain { domain } => {
            let st_cfg = split_tunnel::add_global_domain(client, path, &domain)?;
            println!(
                "Added domain '{}' to global split tunneling (mode: {}).",
                domain, st_cfg.mode
            );
        }
        SplitTunnelCommands::RemoveDomain { domain } => {
            let _ = split_tunnel::remove_global_domain(client, path, &domain)?;
            println!("Removed domain '{}' from global split tunneling.", domain);
        }
        SplitTunnelCommands::Clear => {
            split_tunnel::clear_global(client, path)?;
            println!("Cleared global split-tunnel configuration.");
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
#[cfg(any(test, feature = "gui"))]
pub(crate) fn rebuild_lockdown_if_enabled<C: NmClient + FirewallClient>(
    client: &C,
    path: &std::path::Path,
) -> AppResult<()> {
    if !config::load(path)?.lockdown_enabled {
        return Ok(());
    }
    let tunnels = client.wireguard_tunnels()?;
    client.enable_lockdown(&tunnels)
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

    #[cfg(not(feature = "gui"))]
    #[test]
    fn gui_command_returns_feature_unavailable_without_gui_feature() {
        let cli = Cli {
            command: Commands::Gui { hidden: false },
        };

        let result = execute(&crate::testing::MockNmClient::default(), cli);

        assert!(matches!(result, Err(AppError::FeatureUnavailable(_))));
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

        assert!(matches!(result, Err(AppError::NmCommandFailed(_))));
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

        assert!(matches!(result, Err(AppError::NmCommandFailed(_))));
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

    fn unique_test_config_path() -> std::path::PathBuf {
        crate::testing::temp_config_path("app")
    }

    fn cleanup_test_config(path: &std::path::Path) {
        crate::testing::remove_temp_config(path);
    }
}
