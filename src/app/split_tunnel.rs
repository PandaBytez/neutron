//! Application-level split tunneling handlers and persistence.

use std::path::Path;

use crate::config::{self, AppConfig, SplitTunnelConfig, SplitTunnelMode};
use crate::error::{AppError, AppResult};
use crate::nm::{self, NmClient};

/// Get the global split tunnel configuration from app config.
pub fn get_global_split_tunnel(config: &AppConfig) -> SplitTunnelConfig {
    config.global_split_tunnel.clone()
}

/// Apply global split tunnel routing rules to all WireGuard profiles in NetworkManager and persist.
///
/// Follows the apply-before-persist invariant: NetworkManager is modified first;
/// if `apply_split_tunnel_all` fails, the config is not updated.
pub fn apply_and_persist_global_split_tunnel<C: NmClient>(
    client: &C,
    path: &Path,
    st_cfg: &SplitTunnelConfig,
) -> AppResult<()> {
    let (v4_routes, v6_routes) = if st_cfg.mode.is_enabled() {
        nm::split_tunnel::collect_all_routes(&st_cfg.cidrs, &st_cfg.domains)
    } else {
        (Vec::new(), Vec::new())
    };

    client.apply_split_tunnel_all(st_cfg.mode, &v4_routes, &v6_routes)?;

    let mut app_cfg = config::load(path)?;
    app_cfg.global_split_tunnel = st_cfg.clone();
    config::save(path, &app_cfg)?;

    Ok(())
}

/// Set global split tunnel mode.
pub fn set_global_mode<C: NmClient>(
    client: &C,
    path: &Path,
    mode: SplitTunnelMode,
) -> AppResult<SplitTunnelConfig> {
    let app_cfg = config::load(path)?;
    let mut st_cfg = app_cfg.global_split_tunnel;
    st_cfg.mode = mode;
    apply_and_persist_global_split_tunnel(client, path, &st_cfg)?;
    Ok(st_cfg)
}

/// Add a CIDR or IP to the global split tunnel config.
pub fn add_global_cidr<C: NmClient>(
    client: &C,
    path: &Path,
    cidr: &str,
) -> AppResult<SplitTunnelConfig> {
    let (normalized, _) =
        nm::split_tunnel::parse_and_normalize_cidr(cidr).map_err(AppError::Config)?;

    let app_cfg = config::load(path)?;
    let mut st_cfg = app_cfg.global_split_tunnel;

    if !st_cfg.cidrs.contains(&normalized) {
        st_cfg.cidrs.push(normalized);
        apply_and_persist_global_split_tunnel(client, path, &st_cfg)?;
    }

    Ok(st_cfg)
}

/// Remove a CIDR or IP from the global split tunnel config.
pub fn remove_global_cidr<C: NmClient>(
    client: &C,
    path: &Path,
    cidr: &str,
) -> AppResult<SplitTunnelConfig> {
    let app_cfg = config::load(path)?;
    let mut st_cfg = app_cfg.global_split_tunnel;

    let before_len = st_cfg.cidrs.len();
    st_cfg
        .cidrs
        .retain(|c| c != cidr && c != &format!("{cidr}/32") && c != &format!("{cidr}/128"));

    if st_cfg.cidrs.len() != before_len {
        apply_and_persist_global_split_tunnel(client, path, &st_cfg)?;
    }

    Ok(st_cfg)
}

/// Add a domain to the global split tunnel config.
pub fn add_global_domain<C: NmClient>(
    client: &C,
    path: &Path,
    domain: &str,
) -> AppResult<SplitTunnelConfig> {
    let normalized = nm::split_tunnel::normalize_domain(domain)
        .ok_or_else(|| AppError::Config("domain cannot be empty".to_string()))?;

    let app_cfg = config::load(path)?;
    let mut st_cfg = app_cfg.global_split_tunnel;

    if !st_cfg.domains.contains(&normalized) {
        st_cfg.domains.push(normalized);
        apply_and_persist_global_split_tunnel(client, path, &st_cfg)?;
    }

    Ok(st_cfg)
}

/// Remove a domain from the global split tunnel config.
pub fn remove_global_domain<C: NmClient>(
    client: &C,
    path: &Path,
    domain: &str,
) -> AppResult<SplitTunnelConfig> {
    // An empty domain can never match a stored entry, so normalizing it away to
    // an empty string is harmless: `retain` below simply removes nothing.
    let normalized = nm::split_tunnel::normalize_domain(domain).unwrap_or_default();
    let app_cfg = config::load(path)?;
    let mut st_cfg = app_cfg.global_split_tunnel;

    let before_len = st_cfg.domains.len();
    st_cfg.domains.retain(|d| d != &normalized);

    if st_cfg.domains.len() != before_len {
        apply_and_persist_global_split_tunnel(client, path, &st_cfg)?;
    }

    Ok(st_cfg)
}

/// Clear all global split tunneling rules and restore default full-tunneling.
pub fn clear_global<C: NmClient>(client: &C, path: &Path) -> AppResult<()> {
    let st_cfg = SplitTunnelConfig::default();
    apply_and_persist_global_split_tunnel(client, path, &st_cfg)
}

/// Format the global split tunnel status for display in the CLI.
pub fn format_global_status(st_cfg: &SplitTunnelConfig) -> String {
    let mut out = format!(
        "Global Split Tunneling (all profiles):\n  Mode: {}\n",
        st_cfg.mode
    );
    if st_cfg.cidrs.is_empty() {
        out.push_str("  CIDRs: (none)\n");
    } else {
        out.push_str("  CIDRs:\n");
        for c in &st_cfg.cidrs {
            out.push_str(&format!("    - {c}\n"));
        }
    }
    if st_cfg.domains.is_empty() {
        out.push_str("  Domains: (none)\n");
    } else {
        out.push_str("  Domains:\n");
        for d in &st_cfg.domains {
            out.push_str(&format!("    - {d}\n"));
        }
    }
    out
}

/// Format a concise summary subtitle for display in the GUI Settings row.
#[cfg_attr(not(feature = "gui"), allow(dead_code))]
pub fn format_summary_subtitle(st_cfg: &SplitTunnelConfig) -> String {
    match st_cfg.mode {
        SplitTunnelMode::Disabled => "Disabled (Route all traffic through VPN)".to_string(),
        SplitTunnelMode::Include => {
            let num_routes = st_cfg.cidrs.len() + st_cfg.domains.len();
            if num_routes == 0 {
                "Include mode (no routes specified)".to_string()
            } else {
                format!("Include mode ({num_routes} destinations via VPN)")
            }
        }
        SplitTunnelMode::Exclude => {
            let num_routes = st_cfg.cidrs.len() + st_cfg.domains.len();
            if num_routes == 0 {
                "Exclude mode (no routes specified)".to_string()
            } else {
                format!("Exclude mode (bypass VPN for {num_routes} destinations)")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nm::{ProfileState, WireguardProfile};
    use crate::testing::{self, MockNmClient};

    fn test_profile() -> WireguardProfile {
        WireguardProfile {
            name: "test-wg".to_string(),
            uuid: "uuid-st-1".to_string(),
            state: ProfileState::Inactive,
        }
    }

    #[test]
    fn global_apply_and_persist_handles_include_mode() {
        let profile = test_profile();
        let client = MockNmClient::new(vec![profile.clone()]);
        let path = testing::temp_config_path("st-global-1");

        let mut st_cfg = SplitTunnelConfig {
            mode: SplitTunnelMode::Include,
            cidrs: vec!["10.0.0.0/8".to_string()],
            domains: vec!["localhost".to_string()],
        };

        apply_and_persist_global_split_tunnel(&client, &path, &st_cfg).unwrap();

        let loaded = config::load(&path).unwrap();
        let saved = get_global_split_tunnel(&loaded);
        assert_eq!(saved.mode, SplitTunnelMode::Include);
        assert_eq!(saved.cidrs, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(saved.domains, vec!["localhost".to_string()]);

        assert_eq!(client.split_tunnel_calls().len(), 1);

        // Add CIDR
        st_cfg = add_global_cidr(&client, &path, "192.168.1.0/24").unwrap();
        assert_eq!(st_cfg.cidrs.len(), 2);

        // Remove CIDR
        st_cfg = remove_global_cidr(&client, &path, "10.0.0.0/8").unwrap();
        assert_eq!(st_cfg.cidrs, vec!["192.168.1.0/24".to_string()]);

        // Add Domain
        st_cfg = add_global_domain(&client, &path, "corp.internal").unwrap();
        assert!(st_cfg.domains.contains(&"corp.internal".to_string()));

        // Remove Domain
        st_cfg = remove_global_domain(&client, &path, "localhost").unwrap();
        assert_eq!(st_cfg.domains, vec!["corp.internal".to_string()]);

        // Summary subtitle
        let sub = format_summary_subtitle(&st_cfg);
        assert!(sub.contains("Include mode"));

        // Clear
        clear_global(&client, &path).unwrap();
        let loaded = config::load(&path).unwrap();
        assert_eq!(loaded.global_split_tunnel.mode, SplitTunnelMode::Disabled);

        testing::remove_temp_config(&path);
    }

    #[test]
    fn format_global_status_output() {
        let st_cfg = SplitTunnelConfig {
            mode: SplitTunnelMode::Include,
            cidrs: vec!["10.0.0.0/8".to_string()],
            domains: vec!["example.com".to_string()],
        };
        let status = format_global_status(&st_cfg);
        assert!(status.contains("Global Split Tunneling"));
        assert!(status.contains("include"));
        assert!(status.contains("10.0.0.0/8"));
        assert!(status.contains("example.com"));
    }
}
