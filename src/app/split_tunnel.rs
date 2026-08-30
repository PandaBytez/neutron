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
    let (v4_routes, v6_routes) =
        nm::split_tunnel::routes_for(st_cfg.mode, &st_cfg.cidrs, &st_cfg.domains);

    client.apply_split_tunnel_all(st_cfg.mode, &v4_routes, &v6_routes)?;

    let mut app_cfg = config::load(path)?;
    app_cfg.global_split_tunnel = st_cfg.clone();
    config::save(path, &app_cfg)?;

    Ok(())
}

/// Load the global split-tunnel config, apply `edit` to it, and persist the
/// result if `edit` reports a change.
///
/// The five mutators below all shared this load / edit / conditionally-apply
/// shape; keeping it in one place is what guarantees they all honor the
/// apply-before-persist ordering.
fn mutate_global<C, F>(client: &C, path: &Path, edit: F) -> AppResult<(SplitTunnelConfig, bool)>
where
    C: NmClient,
    F: FnOnce(&mut SplitTunnelConfig) -> AppResult<bool>,
{
    let mut st_cfg = config::load(path)?.global_split_tunnel;
    let changed = edit(&mut st_cfg)?;
    if changed {
        apply_and_persist_global_split_tunnel(client, path, &st_cfg)?;
    }
    Ok((st_cfg, changed))
}

/// Set global split tunnel mode.
pub fn set_global_mode<C: NmClient>(
    client: &C,
    path: &Path,
    mode: SplitTunnelMode,
) -> AppResult<SplitTunnelConfig> {
    let (cfg, _) = mutate_global(client, path, |st_cfg| {
        st_cfg.mode = mode;
        // Always reapplied: the mode decides how the existing routes are
        // interpreted, so it must reach NetworkManager even when unchanged.
        Ok(true)
    })?;
    Ok(cfg)
}

/// Add a CIDR or IP to the global split tunnel config.
pub fn add_global_cidr<C: NmClient>(
    client: &C,
    path: &Path,
    cidr: &str,
) -> AppResult<(SplitTunnelConfig, bool)> {
    let (normalized, _) =
        nm::split_tunnel::parse_and_normalize_cidr(cidr).map_err(AppError::Config)?;

    mutate_global(client, path, |st_cfg| {
        if st_cfg.cidrs.contains(&normalized) {
            return Ok(false);
        }
        st_cfg.cidrs.push(normalized);
        Ok(true)
    })
}

/// Remove a CIDR or IP from the global split tunnel config.
pub fn remove_global_cidr<C: NmClient>(
    client: &C,
    path: &Path,
    cidr: &str,
) -> AppResult<(SplitTunnelConfig, bool)> {
    // Matched both as given and as normalized, so `10.0.0.0/8` removes an entry
    // stored from `10.1.2.3/8`, and a bare IP removes its `/32` form.
    let normalized = nm::split_tunnel::parse_and_normalize_cidr(cidr)
        .map(|(value, _)| value)
        .unwrap_or_default();

    mutate_global(client, path, |st_cfg| {
        let before = st_cfg.cidrs.len();
        st_cfg
            .cidrs
            .retain(|entry| entry != cidr && *entry != normalized);
        Ok(st_cfg.cidrs.len() != before)
    })
}

/// Add a domain to the global split tunnel config.
pub fn add_global_domain<C: NmClient>(
    client: &C,
    path: &Path,
    domain: &str,
) -> AppResult<(SplitTunnelConfig, bool)> {
    let normalized = nm::split_tunnel::normalize_domain(domain)
        .ok_or_else(|| AppError::Config("domain cannot be empty".to_string()))?;

    mutate_global(client, path, |st_cfg| {
        if st_cfg.domains.contains(&normalized) {
            return Ok(false);
        }
        st_cfg.domains.push(normalized);
        Ok(true)
    })
}

/// Remove a domain from the global split tunnel config.
pub fn remove_global_domain<C: NmClient>(
    client: &C,
    path: &Path,
    domain: &str,
) -> AppResult<(SplitTunnelConfig, bool)> {
    // An empty domain can never match a stored entry, so normalizing it away to
    // an empty string is harmless: `retain` below simply removes nothing.
    let normalized = nm::split_tunnel::normalize_domain(domain).unwrap_or_default();

    mutate_global(client, path, |st_cfg| {
        let before = st_cfg.domains.len();
        st_cfg.domains.retain(|entry| entry != &normalized);
        Ok(st_cfg.domains.len() != before)
    })
}

/// Clear all global split tunneling rules and restore default full-tunneling.
pub fn clear_global<C: NmClient>(client: &C, path: &Path) -> AppResult<()> {
    apply_and_persist_global_split_tunnel(client, path, &SplitTunnelConfig::default())
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

        let st_cfg = SplitTunnelConfig {
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
        let (st_cfg, changed) = add_global_cidr(&client, &path, "192.168.1.0/24").unwrap();
        assert!(changed);
        assert_eq!(st_cfg.cidrs.len(), 2);

        // Add duplicate CIDR (no change)
        let (st_cfg, changed) = add_global_cidr(&client, &path, "192.168.1.0/24").unwrap();
        assert!(!changed);
        assert_eq!(st_cfg.cidrs.len(), 2);

        // Remove CIDR
        let (st_cfg, changed) = remove_global_cidr(&client, &path, "10.0.0.0/8").unwrap();
        assert!(changed);
        assert_eq!(st_cfg.cidrs, vec!["192.168.1.0/24".to_string()]);

        // Remove non-existent CIDR (no change)
        let (st_cfg, changed) = remove_global_cidr(&client, &path, "10.0.0.0/8").unwrap();
        assert!(!changed);
        assert_eq!(st_cfg.cidrs, vec!["192.168.1.0/24".to_string()]);

        // Add Domain
        let (st_cfg, changed) = add_global_domain(&client, &path, "ip6-localhost").unwrap();
        assert!(changed);
        assert!(st_cfg.domains.contains(&"ip6-localhost".to_string()));

        // Add duplicate Domain (no change)
        let (_st_cfg, changed) = add_global_domain(&client, &path, "ip6-localhost").unwrap();
        assert!(!changed);

        // Remove Domain
        let (st_cfg, changed) = remove_global_domain(&client, &path, "localhost").unwrap();
        assert!(changed);
        assert_eq!(st_cfg.domains, vec!["ip6-localhost".to_string()]);

        // Remove non-existent Domain (no change)
        let (st_cfg, changed) = remove_global_domain(&client, &path, "localhost").unwrap();
        assert!(!changed);
        assert_eq!(st_cfg.domains, vec!["ip6-localhost".to_string()]);

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
