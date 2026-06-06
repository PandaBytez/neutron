pub(crate) mod eligibility;
pub mod profile_list;
pub mod refresh_sync;

use clap::{Parser, Subcommand};

use crate::config;
use crate::error::{AppError, AppResult};
use crate::nm::{self, NmClient, WireguardProfile};
use crate::service;

#[derive(Debug, Parser)]
#[command(name = "wireguard-manager")]
#[command(about = "WireGuard profile manager via NetworkManager")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    List,
    Gui,
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
}

#[derive(Debug, Subcommand)]
enum EligibleCommands {
    List,
    Add { profile: String },
    Remove { profile: String },
}

#[derive(Debug, Subcommand)]
enum KillSwitchCommands {
    Status { profile: String },
    Enable { profile: String },
    Disable { profile: String },
}

pub fn run<C: NmClient + Clone + Send + 'static>(client: &C) -> AppResult<()> {
    let cli = Cli::parse();
    execute(client, cli)
}

fn execute<C: NmClient + Clone + Send + 'static>(client: &C, cli: Cli) -> AppResult<()> {
    match cli.command {
        Commands::List => {
            let path = config::default_config_path()?;
            let app_cfg = config::load(&path)?;
            let profiles = client.list_wireguard_profiles()?;
            let rows = profile_list::build_rows(&profiles, &app_cfg.eligible_profile_ids);
            for row in rows {
                println!("{}", profile_list::format_cli_row(&row));
            }
            Ok(())
        }
        Commands::Gui => crate::gui::run(client.clone()),
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
    }
}

fn handle_eligible_command<C: NmClient>(client: &C, command: EligibleCommands) -> AppResult<()> {
    let path = config::default_config_path()?;
    let mut app_cfg = config::load(&path)?;
    let profiles = client.list_wireguard_profiles()?;

    match command {
        EligibleCommands::List => {
            if app_cfg.eligible_profile_ids.is_empty() {
                println!("No eligible profiles configured.");
            } else {
                for id in &app_cfg.eligible_profile_ids {
                    if let Some(profile) = profiles.iter().find(|profile| &profile.uuid == id) {
                        println!("{} ({})", profile.name, profile.uuid);
                    } else {
                        println!("<unknown> ({id})");
                    }
                }
            }
        }
        EligibleCommands::Add { profile } => {
            let profile_id = resolve_profile_id(&profiles, &profile)?;
            if eligibility::set_profile_eligible(
                &mut app_cfg.eligible_profile_ids,
                &profile_id,
                true,
            ) {
                config::save(&path, &app_cfg)?;
                println!("Eligible profile added: {profile} ({profile_id})");
            } else {
                println!("Profile already eligible: {profile} ({profile_id})");
            }
        }
        EligibleCommands::Remove { profile } => {
            let profile_id = resolve_profile_id(&profiles, &profile)?;
            if eligibility::set_profile_eligible(
                &mut app_cfg.eligible_profile_ids,
                &profile_id,
                false,
            ) {
                config::save(&path, &app_cfg)?;
                println!("Eligible profile removed: {profile} ({profile_id})");
            } else {
                return Err(AppError::Config(format!(
                    "profile is not eligible: {profile_id}"
                )));
            }
        }
    }

    Ok(())
}

fn handle_kill_switch_command<C: NmClient>(
    client: &C,
    command: KillSwitchCommands,
) -> AppResult<()> {
    match command {
        KillSwitchCommands::Status { profile } => {
            let state = client.kill_switch_status(&profile)?;
            println!("Kill switch for {profile}: {}", state.label());
        }
        KillSwitchCommands::Enable { profile } => {
            client.set_kill_switch(&profile, true)?;
            println!(
                "Kill switch enabled for {profile} (applies on next connect; full-tunnel profiles only)."
            );
        }
        KillSwitchCommands::Disable { profile } => {
            client.set_kill_switch(&profile, false)?;
            println!("Kill switch disabled for {profile} (applies on next connect).");
        }
    }

    Ok(())
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
            command: Commands::Gui,
        };

        let result = execute(&crate::testing::MockNmClient::default(), cli);

        assert!(matches!(result, Err(AppError::FeatureUnavailable(_))));
    }

    #[test]
    fn kill_switch_enable_invokes_client() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let cli = Cli {
            command: Commands::KillSwitch {
                command: KillSwitchCommands::Enable {
                    profile: "uuid-1".to_string(),
                },
            },
        };

        execute(&client, cli).expect("enable should succeed");

        assert_eq!(client.kill_switch_calls(), vec!["kill-switch:uuid-1:on"]);
    }

    #[test]
    fn kill_switch_disable_invokes_client() {
        let client = crate::testing::MockNmClient::new(vec![profile("wg-us", "uuid-1")]);
        let cli = Cli {
            command: Commands::KillSwitch {
                command: KillSwitchCommands::Disable {
                    profile: "uuid-1".to_string(),
                },
            },
        };

        execute(&client, cli).expect("disable should succeed");

        assert_eq!(client.kill_switch_calls(), vec!["kill-switch:uuid-1:off"]);
    }
}
