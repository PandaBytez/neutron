//! NetworkManager split tunneling configuration for WireGuard profiles.
//!
//! Split tunneling allows routing only specific traffic (or bypassing specific traffic)
//! through the WireGuard VPN connection.
//!
//! In **Include** mode:
//! - `ipv4.never-default = yes` and `ipv6.never-default = yes` are set on the connection.
//!   This prevents NetworkManager from setting the VPN tunnel as the default gateway.
//! - `ipv4.routes` and `ipv6.routes` are populated with the target subnets / IPs, so only
//!   traffic destined for those subnets enters the WireGuard tunnel.
//!
//! In **Disabled** mode:
//! - `ipv4.never-default = no` and `ipv6.never-default = no` are restored.
//! - `ipv4.routes = ""` and `ipv6.routes = ""` are cleared.

use std::net::{IpAddr, ToSocketAddrs};

use crate::config::SplitTunnelMode;

/// Resolve a domain name to a list of IP addresses.
///
/// Returns an empty list if resolution fails or the domain is invalid.
pub fn resolve_domain_ips(domain: &str) -> Vec<IpAddr> {
    let host = domain.trim();
    if host.is_empty() {
        return Vec::new();
    }
    let target = format!("{host}:0");
    match target.to_socket_addrs() {
        Ok(addrs) => {
            let mut ips = Vec::new();
            for addr in addrs {
                let ip = addr.ip();
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            ips
        }
        Err(e) => {
            tracing::warn!("failed to resolve domain '{domain}': {e}");
            Vec::new()
        }
    }
}

/// Collect and resolve all configured CIDRs and domain names into partitioned IPv4 and IPv6 route lists.
pub fn collect_all_routes(cidrs: &[String], domains: &[String]) -> (Vec<String>, Vec<String>) {
    let mut all_targets = cidrs.to_vec();

    for domain in domains {
        for ip in resolve_domain_ips(domain) {
            match ip {
                IpAddr::V4(v4) => all_targets.push(format!("{v4}/32")),
                IpAddr::V6(v6) => all_targets.push(format!("{v6}/128")),
            }
        }
    }

    let target_refs: Vec<&str> = all_targets.iter().map(|s| s.as_str()).collect();
    partition_routes(target_refs)
}

/// Parse and normalize a CIDR or IP literal string into `(normalized_cidr, is_ipv4)`.
///
/// Accepts `10.0.0.0/8`, `192.168.1.1` (normalized to `192.168.1.1/32`),
/// `2001:db8::/32`, and `::1` (normalized to `::1/128`).
pub fn parse_and_normalize_cidr(input: &str) -> Result<(String, bool), String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("route cannot be empty".to_string());
    }

    if let Some((ip_str, prefix_str)) = trimmed.split_once('/') {
        let ip: IpAddr = ip_str
            .trim()
            .parse()
            .map_err(|e| format!("invalid IP address '{ip_str}': {e}"))?;
        let prefix: u8 = prefix_str
            .trim()
            .parse()
            .map_err(|e| format!("invalid prefix length '{prefix_str}': {e}"))?;

        let is_v4 = match ip {
            IpAddr::V4(_) => {
                if prefix > 32 {
                    return Err(format!("IPv4 prefix length must be <= 32, got {prefix}"));
                }
                true
            }
            IpAddr::V6(_) => {
                if prefix > 128 {
                    return Err(format!("IPv6 prefix length must be <= 128, got {prefix}"));
                }
                false
            }
        };
        Ok((format!("{ip}/{prefix}"), is_v4))
    } else {
        let ip: IpAddr = trimmed
            .parse()
            .map_err(|e| format!("invalid IP or CIDR '{trimmed}': {e}"))?;
        match ip {
            IpAddr::V4(_) => Ok((format!("{ip}/32"), true)),
            IpAddr::V6(_) => Ok((format!("{ip}/128"), false)),
        }
    }
}

/// Partition a list of CIDR strings into separate IPv4 and IPv6 route lists,
/// filtering out any unparseable entries.
pub fn partition_routes<'a, I>(routes: I) -> (Vec<String>, Vec<String>)
where
    I: IntoIterator<Item = &'a str>,
{
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    for r in routes {
        if let Ok((normalized, is_v4)) = parse_and_normalize_cidr(r) {
            if is_v4 {
                if !v4.contains(&normalized) {
                    v4.push(normalized);
                }
            } else if !v6.contains(&normalized) {
                v6.push(normalized);
            }
        }
    }

    (v4, v6)
}

/// `nmcli` arguments that modify connection `uuid` with the desired split-tunnel configuration.
pub fn set_args(
    uuid: &str,
    mode: SplitTunnelMode,
    v4_routes: &[String],
    v6_routes: &[String],
) -> Vec<String> {
    let (never_default, v4_routes_str, v6_routes_str) = match mode {
        SplitTunnelMode::Include => ("yes", v4_routes.join(", "), v6_routes.join(", ")),
        SplitTunnelMode::Exclude => ("no", v4_routes.join(", "), v6_routes.join(", ")),
        SplitTunnelMode::Disabled => ("no", String::new(), String::new()),
    };

    vec![
        "connection".to_string(),
        "modify".to_string(),
        uuid.to_string(),
        "ipv4.never-default".to_string(),
        never_default.to_string(),
        "ipv6.never-default".to_string(),
        never_default.to_string(),
        "ipv4.routes".to_string(),
        v4_routes_str,
        "ipv6.routes".to_string(),
        v6_routes_str,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_normalize_valid_cidrs() {
        assert_eq!(
            parse_and_normalize_cidr("10.0.0.0/8").unwrap(),
            ("10.0.0.0/8".to_string(), true)
        );
        assert_eq!(
            parse_and_normalize_cidr("192.168.1.50").unwrap(),
            ("192.168.1.50/32".to_string(), true)
        );
        assert_eq!(
            parse_and_normalize_cidr("2001:db8::/32").unwrap(),
            ("2001:db8::/32".to_string(), false)
        );
        assert_eq!(
            parse_and_normalize_cidr("fe80::1").unwrap(),
            ("fe80::1/128".to_string(), false)
        );
    }

    #[test]
    fn parse_and_normalize_rejects_invalid() {
        assert!(parse_and_normalize_cidr("").is_err());
        assert!(parse_and_normalize_cidr("999.999.999.999").is_err());
        assert!(parse_and_normalize_cidr("10.0.0.0/33").is_err());
        assert!(parse_and_normalize_cidr("2001:db8::/129").is_err());
        assert!(parse_and_normalize_cidr("example.com").is_err());
    }

    #[test]
    fn partition_routes_separates_v4_and_v6() {
        let input = [
            "10.0.0.0/8",
            "2001:db8::/32",
            "192.168.1.1",
            "::1",
            "invalid",
        ];
        let (v4, v6) = partition_routes(input.iter().copied());

        assert_eq!(v4, vec!["10.0.0.0/8", "192.168.1.1/32"]);
        assert_eq!(v6, vec!["2001:db8::/32", "::1/128"]);
    }

    #[test]
    fn set_args_include_mode() {
        let args = set_args(
            "test-uuid",
            SplitTunnelMode::Include,
            &["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()],
            &["2001:db8::/32".to_string()],
        );

        assert_eq!(args[0], "connection");
        assert_eq!(args[1], "modify");
        assert_eq!(args[2], "test-uuid");
        assert_eq!(args[3], "ipv4.never-default");
        assert_eq!(args[4], "yes");
        assert_eq!(args[5], "ipv6.never-default");
        assert_eq!(args[6], "yes");
        assert_eq!(args[7], "ipv4.routes");
        assert_eq!(args[8], "10.0.0.0/8, 192.168.0.0/16");
        assert_eq!(args[9], "ipv6.routes");
        assert_eq!(args[10], "2001:db8::/32");
    }

    #[test]
    fn collect_all_routes_combines_cidrs_and_resolved() {
        let cidrs = vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()];
        let domains = vec!["localhost".to_string()];
        let (v4, v6) = collect_all_routes(&cidrs, &domains);

        assert!(v4.contains(&"10.0.0.0/8".to_string()));
        assert!(v6.contains(&"2001:db8::/32".to_string()));
        // localhost resolves to 127.0.0.1 and/or ::1
        assert!(v4.contains(&"127.0.0.1/32".to_string()) || v6.contains(&"::1/128".to_string()));
    }
}
