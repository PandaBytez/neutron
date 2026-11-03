//! NetworkManager split tunneling configuration for WireGuard profiles.
//!
//! Split tunneling allows routing only specific traffic (or bypassing specific traffic)
//! through the WireGuard VPN connection.
//!
//! Both active modes install `ipv4.routes` / `ipv6.routes` in a dedicated table
//! matching the WireGuard fwmark. An early `not fwmark` lookup selects specific
//! split routes before physical routes, but skips encrypted VPN transport.
//! NetworkManager's automatic rules handle full-tunnel defaults afterward.
//! Unmatched traffic uses the physical default route.
//! `never-default = yes` suppresses peer defaults unless a whole family is tunneled.
//!
//! In **Include** mode the routes *are* the configured CIDRs and resolved
//! domains: only that traffic enters the tunnel.
//!
//! In **Exclude** mode the routes are the **complement** of the configured
//! CIDRs -- every address except the ones listed. This is the only way to make
//! traffic bypass the tunnel: adding an excluded range to `ipv4.routes` would
//! route it *into* the tunnel, which is the opposite of excluding it. The
//! complement is computed by [`complement_routes`].
//!
//! In **Disabled** mode `never-default` is restored to `no` and both route
//! lists are cleared, so the tunnel is a normal full-tunnel default route.

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Mutex;

use crate::config::SplitTunnelMode;
use crate::error::{AppError, AppResult};

// Neutron's table and mark must match NM's automatic not-fwmark lookup.
const SPLIT_ROUTE_TABLE: u32 = 0x4e455554;

/// Checked policy resolution with a caller-supplied resolver (no implicit DNS or cache).
pub(crate) fn routes_for_checked_with(
    mode: SplitTunnelMode,
    cidrs: &[String],
    domains: &[String],
    mut resolve: impl FnMut(&str) -> Vec<IpAddr>,
) -> AppResult<(Vec<String>, Vec<String>)> {
    if !mode.is_enabled() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut targets = Vec::new();
    for cidr in cidrs {
        let (normalized, _) = parse_and_normalize_cidr(cidr).map_err(AppError::Config)?;
        targets.push(normalized);
    }
    for domain in domains {
        let ips = resolve(domain);
        if ips.is_empty() {
            return Err(AppError::Config(format!(
                "could not resolve split-tunnel domain '{domain}'; policy was not applied"
            )));
        }
        targets.extend(ips.into_iter().map(|ip| ip.to_string()));
    }
    Ok(routes_for(mode, &targets, &[]))
}

static LAST_KNOWN_GOOD: Mutex<Option<HashMap<String, Vec<IpAddr>>>> = Mutex::new(None);

/// Resolve a domain name to a list of IP addresses.
///
/// Returns an empty list if resolution fails or the domain is invalid.
/// Retains last-known-good resolutions to avoid dropping split-tunnel routes
/// on transient DNS failure (which would fail open in Include mode).
pub fn resolve_domain_ips(domain: &str) -> Vec<IpAddr> {
    resolve_domain_ips_with(domain, &LAST_KNOWN_GOOD, |host| {
        let target = format!("{host}:0");
        match target.to_socket_addrs() {
            Ok(addrs) => addrs.map(|addr| addr.ip()).collect(),
            Err(e) => {
                tracing::warn!("failed to resolve domain '{domain}': {e}");
                Vec::new()
            }
        }
    })
}

fn resolve_domain_ips_with(
    domain: &str,
    cache: &Mutex<Option<HashMap<String, Vec<IpAddr>>>>,
    resolve: impl FnOnce(&str) -> Vec<IpAddr>,
) -> Vec<IpAddr> {
    let host = domain.trim().to_lowercase();
    if host.is_empty() {
        return Vec::new();
    }
    // RFC 6761 special-use loopback domain handling
    match host.as_str() {
        "localhost" => {
            return vec![
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            ];
        }
        "ip6-localhost" | "ip6-loopback" | "ipv6-localhost" | "ipv6-loopback" => {
            return vec![IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)];
        }
        "ip4-localhost" | "ip4-loopback" | "ipv4-localhost" | "ipv4-loopback" => {
            return vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
        }
        _ => {}
    }
    let mut ips = Vec::new();
    for ip in resolve(&host) {
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    if !ips.is_empty() {
        if let Ok(mut lock) = cache.lock() {
            lock.get_or_insert_with(HashMap::new)
                .insert(host.clone(), ips.clone());
        }
        return ips;
    }

    if let Ok(lock) = cache.lock()
        && let Some(cache) = lock.as_ref()
        && let Some(cached) = cache.get(&host)
    {
        tracing::warn!("using retained last-known-good resolution for '{domain}': {cached:?}");
        return cached.clone();
    }

    Vec::new()
}

/// Normalize a domain name for storage and comparison, or `None` if it is not usable.
pub fn normalize_domain(input: &str) -> Option<String> {
    let trimmed = input.trim().to_lowercase();
    (!trimmed.is_empty()).then_some(trimmed)
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

/// Zero the host bits of `ip`, so `10.1.2.3/8` becomes `10.0.0.0/8`.
///
/// Shifting by the full width is undefined, so a `/0` prefix (mask of zero) is
/// handled explicitly.
fn network_address(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (V4_BITS - prefix)
            };
            IpAddr::V4(std::net::Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (V6_BITS - prefix)
            };
            IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

/// Parse and normalize a CIDR or IP literal string into `(normalized_cidr, is_ipv4)`.
///
/// Accepts `10.0.0.0/8`, `192.168.1.1` (normalized to `192.168.1.1/32`),
/// `2001:db8::/32`, and `::1` (normalized to `::1/128`).
///
/// Host bits are cleared, so `10.1.2.3/8` normalizes to `10.0.0.0/8`. That is
/// what makes the value a *range* rather than an address with a prefix glued on:
/// [`complement_routes`] derives the end of the block by setting the host bits,
/// so leaving the start unmasked would describe the half-open range
/// `10.1.2.3 - 10.255.255.255` and quietly route `10.0.0.0 - 10.1.2.2` into the
/// tunnel the user asked to exclude it from.
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
        Ok((format!("{}/{prefix}", network_address(ip, prefix)), is_v4))
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
fn partition_routes<'a, I>(routes: I) -> (Vec<String>, Vec<String>)
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

/// Total address bits per family, and therefore the widest possible prefix.
const V4_BITS: u8 = 32;
const V6_BITS: u8 = 128;

/// The inclusive last address of the block `addr/prefix`.
///
/// `prefix` must not exceed `bits`. Shifting a `u128` by 128 is undefined, so an
/// IPv6 `/0` is handled explicitly.
fn block_end(addr: u128, prefix: u8, bits: u8) -> u128 {
    debug_assert!(
        prefix <= bits,
        "prefix /{prefix} is too wide for {bits} bits"
    );
    let host_bits = bits - prefix;
    if host_bits >= 128 {
        u128::MAX
    } else {
        addr | ((1u128 << host_bits) - 1)
    }
}

/// Recursively carve `excluded` out of the block `addr/prefix`, appending what
/// remains to `out`.
///
/// A block that no exclusion touches is kept whole; one an exclusion fully
/// covers is dropped; anything in between is split in half and revisited. That
/// yields the smallest set of aligned CIDRs covering the block minus the
/// exclusions, which is exactly what `ipv4.routes` needs.
fn subtract_into(
    addr: u128,
    prefix: u8,
    bits: u8,
    excluded: &[(u128, u128)],
    out: &mut Vec<(u128, u8)>,
) {
    let end = block_end(addr, prefix, bits);

    if excluded
        .iter()
        .any(|(start, stop)| *start <= addr && *stop >= end)
    {
        return; // Fully excluded.
    }
    if !excluded
        .iter()
        .any(|(start, stop)| *start <= end && *stop >= addr)
    {
        out.push((addr, prefix)); // Untouched.
        return;
    }
    if prefix == bits {
        return; // A single address that overlaps an exclusion.
    }

    let half = prefix + 1;
    subtract_into(addr, half, bits, excluded, out);
    subtract_into(block_end(addr, half, bits) + 1, half, bits, excluded, out);
}

/// Parse normalized CIDRs of one family into inclusive `(start, end)` ranges.
fn to_ranges(cidrs: &[String], want_v6: bool) -> Vec<(u128, u128)> {
    let bits = if want_v6 { V6_BITS } else { V4_BITS };
    cidrs
        .iter()
        .filter_map(|cidr| {
            let (ip_str, prefix_str) = cidr.split_once('/')?;
            let prefix: u8 = prefix_str.parse().ok()?;
            // A prefix wider than the family would underflow `block_end`.
            if prefix > bits {
                return None;
            }
            // Masked again here rather than trusting the caller: this is `pub`
            // via `complement_routes`, and an unmasked start silently shrinks
            // the excluded range.
            let ip = ip_str.parse::<IpAddr>().ok()?;
            let start = match (network_address(ip, prefix), want_v6) {
                (IpAddr::V4(v4), false) => u32::from(v4) as u128,
                (IpAddr::V6(v6), true) => u128::from(v6),
                _ => return None,
            };
            Some((start, block_end(start, prefix, bits)))
        })
        .collect()
}

pub(crate) fn address_in_routes(routes: &[String], address: IpAddr) -> bool {
    let target = match address {
        IpAddr::V4(ip) => u32::from(ip) as u128,
        IpAddr::V6(ip) => u128::from(ip),
    };
    to_ranges(routes, address.is_ipv6())
        .iter()
        .any(|(start, end)| *start <= target && target <= *end)
}

/// Every address of one family *except* those in `excluded`, as CIDR strings.
///
/// This is what makes Exclude mode actually exclude: the returned routes are
/// installed on the tunnel, so traffic to `excluded` is the only traffic left to
/// the physical default route. An empty `excluded` yields the full space
/// (`0.0.0.0/0` or `::/0`), i.e. a full tunnel.
pub fn complement_routes(excluded: &[String], want_v6: bool) -> Vec<String> {
    let bits = if want_v6 { V6_BITS } else { V4_BITS };
    let ranges = to_ranges(excluded, want_v6);

    let mut blocks = Vec::new();
    subtract_into(0, 0, bits, &ranges, &mut blocks);

    blocks
        .into_iter()
        .map(|(addr, prefix)| {
            if want_v6 {
                format!("{}/{prefix}", std::net::Ipv6Addr::from(addr))
            } else {
                format!("{}/{prefix}", std::net::Ipv4Addr::from(addr as u32))
            }
        })
        .collect()
}

/// The `(v4, v6)` routes to install on the tunnel for `mode`.
///
/// The single place that decides what each mode means in terms of routes, so
/// the CLI, the TUI and profile import cannot disagree.
pub fn routes_for(
    mode: SplitTunnelMode,
    cidrs: &[String],
    domains: &[String],
) -> (Vec<String>, Vec<String>) {
    match mode {
        SplitTunnelMode::Disabled => (Vec::new(), Vec::new()),
        SplitTunnelMode::Include => collect_all_routes(cidrs, domains),
        SplitTunnelMode::Exclude => {
            let (v4, v6) = collect_all_routes(cidrs, domains);
            (complement_routes(&v4, false), complement_routes(&v6, true))
        }
    }
}

/// `nmcli` arguments that modify connection `uuid` with the desired
/// split-tunnel configuration.
///
/// `v4_routes`/`v6_routes` are the routes that should enter the tunnel; build
/// them with [`routes_for`] rather than passing the user's CIDRs directly, or
/// Exclude mode will route the excluded ranges *into* the tunnel.
/// Requires automatic default-route handling pinned by [`super::tunnel_routing`].
/// When disabling, callers must clear the mark only if Neutron owns it.
pub fn set_args(
    uuid: &str,
    mode: SplitTunnelMode,
    v4_routes: &[String],
    v6_routes: &[String],
) -> Vec<String> {
    let format_routes = |routes: &[String]| {
        if mode.is_enabled() {
            routes
                .iter()
                .map(|route| format!("{route} table={SPLIT_ROUTE_TABLE}"))
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            String::new()
        }
    };
    let v4_never_default = never_default_for(mode, v4_routes);
    let v6_never_default = never_default_for(mode, v6_routes);
    let mut args = vec![
        "connection".to_string(),
        "modify".to_string(),
        uuid.to_string(),
        "ipv4.never-default".to_string(),
        v4_never_default.to_string(),
        "ipv6.never-default".to_string(),
        v6_never_default.to_string(),
        "ipv4.routes".to_string(),
        format_routes(v4_routes),
        "ipv6.routes".to_string(),
        format_routes(v6_routes),
        "ipv4.routed-dns".to_string(),
        "yes".to_string(),
        "ipv6.routed-dns".to_string(),
        "yes".to_string(),
    ];
    if mode.is_enabled() {
        args.extend([
            "wireguard.fwmark".into(),
            format!("0x{SPLIT_ROUTE_TABLE:x}"),
        ]);
    }
    // NM's automatic main-table lookup wins otherwise, even against a split /32.
    let rule = format!(
        "priority 30000 not fwmark 0x{SPLIT_ROUTE_TABLE:x} table {SPLIT_ROUTE_TABLE} suppress_prefixlength 0"
    );
    for (family, routes) in [("ipv4", v4_routes), ("ipv6", v6_routes)] {
        args.extend([format!("-{family}.routing-rules"), rule.clone()]);
        if mode.is_enabled() && !routes.is_empty() {
            args.extend([format!("+{family}.routing-rules"), rule.clone()]);
        }
    }
    args
}

/// Preserve user-configured transport marks; only undo Neutron's split override.
pub(crate) fn reset_owned_fwmark_args(
    uuid: &str,
    mode: SplitTunnelMode,
    run: &mut impl FnMut(&[&str]) -> AppResult<String>,
) -> AppResult<Vec<String>> {
    if mode.is_enabled() {
        return Ok(Vec::new());
    }
    let value = run(&["-g", "wireguard.fwmark", "connection", "show", uuid])?;
    let value = value.trim();
    let mark = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .or_else(|| value.parse::<u32>().ok());
    Ok(if mark == Some(SPLIT_ROUTE_TABLE) {
        vec!["wireguard.fwmark".into(), "0".into()]
    } else {
        Vec::new()
    })
}

/// Whether one address family should be barred from taking the tunnel's default
/// route. Whole-family tunnel routes need default-route eligibility; an empty
/// Exclude list instead means the whole family must bypass the tunnel (BUG-009).
fn never_default_for(mode: SplitTunnelMode, routes: &[String]) -> &'static str {
    if routes.iter().any(|route| route.ends_with("/0")) {
        return "no";
    }
    match mode {
        SplitTunnelMode::Disabled => "no",
        SplitTunnelMode::Include => {
            if routes.is_empty() {
                "no"
            } else {
                "yes"
            }
        }
        SplitTunnelMode::Exclude => "yes",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_domain_trims_and_lowercases() {
        assert_eq!(
            normalize_domain("  EXAMPLE.COM  "),
            Some("example.com".to_string())
        );
        assert_eq!(normalize_domain(""), None);
        assert_eq!(normalize_domain("   "), None);
    }

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

    /// Whether `address` is inside any of `routes`.
    fn routed(routes: &[String], address: &str) -> bool {
        let target: u128 = match address
            .parse::<IpAddr>()
            .expect("test address should parse")
        {
            IpAddr::V4(v4) => u32::from(v4) as u128,
            IpAddr::V6(v6) => u128::from(v6),
        };
        let want_v6 = address.contains(':');
        to_ranges(routes, want_v6)
            .iter()
            .any(|(start, end)| *start <= target && target <= *end)
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
        assert_eq!(
            args[8],
            "10.0.0.0/8 table=1313166676, 192.168.0.0/16 table=1313166676"
        );
        assert_eq!(args[9], "ipv6.routes");
        assert_eq!(args[10], "2001:db8::/32 table=1313166676");
    }

    #[test]
    fn split_routes_use_the_fwmark_table_and_disabled_mode_does_not_overwrite_marks() {
        for mode in [SplitTunnelMode::Include, SplitTunnelMode::Exclude] {
            let args = set_args("uuid", mode, &["192.0.2.0/24".into()], &[]);
            assert!(
                args.windows(2)
                    .any(|pair| pair == ["wireguard.fwmark", "0x4e455554"])
            );
            assert_eq!(args[8], "192.0.2.0/24 table=1313166676");
        }
        let args = set_args("uuid", SplitTunnelMode::Disabled, &[], &[]);
        assert!(!args.iter().any(|arg| arg == "wireguard.fwmark"));
    }

    #[test]
    fn disabling_only_resets_neutrons_owned_fwmark() {
        for value in ["0x4e455554", "0X4E455554", "1313166676"] {
            assert_eq!(
                reset_owned_fwmark_args("uuid", SplitTunnelMode::Disabled, &mut |_| {
                    Ok(value.into())
                })
                .unwrap(),
                ["wireguard.fwmark", "0"]
            );
        }
        for value in ["0x2a", "42", "0x0", "0", "--"] {
            assert!(
                reset_owned_fwmark_args("uuid", SplitTunnelMode::Disabled, &mut |_| {
                    Ok(value.into())
                })
                .unwrap()
                .is_empty()
            );
        }
        assert!(
            reset_owned_fwmark_args("uuid", SplitTunnelMode::Include, &mut |_| {
                panic!("enabling does not need to read the old mark")
            })
            .unwrap()
            .is_empty()
        );
        assert!(
            reset_owned_fwmark_args("uuid", SplitTunnelMode::Disabled, &mut |_| {
                Err(AppError::CommandFailed("read failed".into()))
            })
            .is_err()
        );
    }

    #[test]
    fn split_lookup_precedes_main_routes_without_capturing_transport_or_defaults() {
        let rule = "priority 30000 not fwmark 0x4e455554 table 1313166676 suppress_prefixlength 0";
        let args = set_args(
            "uuid",
            SplitTunnelMode::Include,
            &["192.0.2.1/32".into()],
            &[],
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["+ipv4.routing-rules", rule])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["-ipv6.routing-rules", rule])
        );
        assert!(!args.iter().any(|arg| arg == "+ipv6.routing-rules"));
        let args = set_args("uuid", SplitTunnelMode::Disabled, &[], &[]);
        for family in ["ipv4", "ipv6"] {
            assert!(
                args.windows(2)
                    .any(|pair| pair[0] == format!("-{family}.routing-rules") && pair[1] == rule)
            );
            assert!(
                !args
                    .iter()
                    .any(|arg| arg == &format!("+{family}.routing-rules"))
            );
        }
    }

    #[test]
    fn whole_family_tunnel_routes_are_not_suppressed_by_never_default() {
        for mode in [SplitTunnelMode::Include, SplitTunnelMode::Exclude] {
            let args = set_args("uuid", mode, &["0.0.0.0/0".into()], &["::/0".into()]);
            assert_eq!(args[4], "no");
            assert_eq!(args[6], "no");
        }
    }

    #[test]
    fn a_family_with_no_routes_keeps_its_default_route() {
        // Regression: `never-default` was set for both families whenever split
        // tunneling was on, even for a family with an empty route list. That
        // family was then barred from the tunnel's default route while having
        // no route of its own -- a black hole. Splitting on IPv4-only domains
        // (github.com and friends) killed all IPv6 traffic exactly this way.
        let args = set_args(
            "uuid-1",
            SplitTunnelMode::Include,
            &["140.82.121.4/32".to_string()],
            &[],
        );

        assert_eq!(args[3], "ipv4.never-default");
        assert_eq!(args[4], "yes", "IPv4 has routes, so it is split");
        assert_eq!(args[5], "ipv6.never-default");
        assert_eq!(
            args[6], "no",
            "IPv6 has no routes, so it must keep the ordinary default route \
             instead of being left with nowhere to go"
        );
        assert_eq!(args[10], "", "and no IPv6 routes are written");
    }

    #[test]
    fn the_mirrored_case_keeps_ipv4_working() {
        let args = set_args(
            "uuid-1",
            SplitTunnelMode::Include,
            &[],
            &["2001:db8::1/128".to_string()],
        );

        assert_eq!(args[4], "no", "IPv4 has no routes, so it must keep working");
        assert_eq!(args[6], "yes");
    }

    #[test]
    fn both_families_are_split_when_both_have_routes() {
        let args = set_args(
            "uuid-1",
            SplitTunnelMode::Include,
            &["10.0.0.0/8".to_string()],
            &["2001:db8::/32".to_string()],
        );

        assert_eq!(args[4], "yes");
        assert_eq!(args[6], "yes");
    }

    #[test]
    fn no_family_is_ever_barred_from_routing_with_an_empty_route_list() {
        // The invariant behind BUG-012, checked for Disabled and Include modes:
        // an un-split family may only be barred from the default route if it has
        // routes of its own. In Exclude mode, an empty route list means the whole
        // family was intentionally excluded and must use physical routing (BUG-009).
        for mode in [SplitTunnelMode::Disabled, SplitTunnelMode::Include] {
            for (v4, v6) in [
                (vec![], vec![]),
                (vec!["10.0.0.0/8".to_string()], vec![]),
                (vec![], vec!["2001:db8::/32".to_string()]),
                (
                    vec!["10.0.0.0/8".to_string()],
                    vec!["2001:db8::/32".to_string()],
                ),
            ] {
                let args = set_args("uuid-1", mode, &v4, &v6);
                for (never_default, routes, family) in
                    [(&args[4], &args[8], "ipv4"), (&args[6], &args[10], "ipv6")]
                {
                    if never_default == "yes" {
                        assert!(
                            !routes.is_empty(),
                            "{mode} left {family} barred from the default route with no \
                             routes of its own, which black-holes that family"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn exclude_mode_whole_family_exclusion_sets_never_default_yes() {
        // BUG-009: When 0.0.0.0/0 is excluded, routes_for produces an empty v4 list.
        // set_args must still set ipv4.never-default = yes so NetworkManager does
        // not re-install the tunnel default route and send excluded traffic into the VPN.
        let (v4, v6) = routes_for(
            SplitTunnelMode::Exclude,
            &["0.0.0.0/0".to_string(), "::/0".to_string()],
            &[],
        );
        assert!(v4.is_empty());
        assert!(v6.is_empty());

        let args = set_args("test-uuid", SplitTunnelMode::Exclude, &v4, &v6);
        assert_eq!(
            args[4], "yes",
            "ipv4.never-default must be yes when all ipv4 is excluded"
        );
        assert_eq!(
            args[6], "yes",
            "ipv6.never-default must be yes when all ipv6 is excluded"
        );
        assert_eq!(args[8], "", "ipv4.routes must be empty");
        assert_eq!(args[10], "", "ipv6.routes must be empty");
    }

    #[test]
    fn set_args_disabled_mode_clears_routes_and_restores_the_default_route() {
        // Stale routes left behind would keep steering traffic after the user
        // turned split tunneling off.
        let args = set_args(
            "test-uuid",
            SplitTunnelMode::Disabled,
            &["10.0.0.0/8".to_string()],
            &["2001:db8::/32".to_string()],
        );

        assert_eq!(args[4], "no");
        assert_eq!(args[6], "no");
        assert_eq!(args[8], "");
        assert_eq!(args[10], "");
    }

    #[test]
    fn normalization_clears_host_bits() {
        // "Normalize" has to mean the network address, not just the prefix
        // glued back on -- see `exclude_mode_masks_an_unaligned_cidr`.
        assert_eq!(
            parse_and_normalize_cidr("10.1.2.3/8").unwrap(),
            ("10.0.0.0/8".to_string(), true)
        );
        assert_eq!(
            parse_and_normalize_cidr("192.168.1.77/24").unwrap(),
            ("192.168.1.0/24".to_string(), true)
        );
        assert_eq!(
            parse_and_normalize_cidr("2001:db8:dead:beef::1/32").unwrap(),
            ("2001:db8::/32".to_string(), false)
        );
        // A /0 masks to the whole space, and a host route is unchanged.
        assert_eq!(
            parse_and_normalize_cidr("8.8.8.8/0").unwrap(),
            ("0.0.0.0/0".to_string(), true)
        );
        assert_eq!(
            parse_and_normalize_cidr("192.168.1.50/32").unwrap(),
            ("192.168.1.50/32".to_string(), true)
        );
    }

    #[test]
    fn exclude_mode_masks_an_unaligned_cidr() {
        // Regression: the range start was taken verbatim while its end was
        // derived by setting the host bits, so excluding "10.1.2.3/8" only
        // excluded 10.1.2.3 upwards -- and 10.0.0.0-10.1.2.2 was still routed
        // into the tunnel the user had excluded it from.
        let (v4, _) = routes_for(SplitTunnelMode::Exclude, &["10.1.2.3/8".to_string()], &[]);

        for address in ["10.0.0.0", "10.1.2.2", "10.1.2.3", "10.255.255.255"] {
            assert!(
                !routed(&v4, address),
                "{address} is inside the excluded /8 and must not be tunneled: {v4:?}"
            );
        }
        assert!(routed(&v4, "9.255.255.255") && routed(&v4, "11.0.0.0"));
    }

    #[test]
    fn complement_ignores_prefixes_too_wide_for_the_family() {
        // `complement_routes` is public, so a malformed entry must be skipped
        // rather than underflow the block-width arithmetic.
        assert_eq!(
            complement_routes(&["10.0.0.0/64".to_string()], false),
            vec!["0.0.0.0/0".to_string()]
        );
    }

    #[test]
    fn exclude_mode_keeps_the_excluded_range_off_the_tunnel() {
        // Regression: Exclude was a copy of Include, so it put the excluded
        // range into `ipv4.routes` -- routing it *through* the VPN, the exact
        // opposite of excluding it.
        let (v4, _) = routes_for(SplitTunnelMode::Exclude, &["10.0.0.0/8".to_string()], &[]);

        assert!(
            !routed(&v4, "10.1.2.3"),
            "an excluded address must not be routed into the tunnel: {v4:?}"
        );
        assert!(
            routed(&v4, "1.1.1.1") && routed(&v4, "192.168.1.1") && routed(&v4, "9.255.255.255"),
            "everything else must still go through the tunnel: {v4:?}"
        );
    }

    #[test]
    fn exclude_mode_covers_the_boundaries_of_the_excluded_block() {
        let (v4, _) = routes_for(
            SplitTunnelMode::Exclude,
            &["192.168.1.0/24".to_string()],
            &[],
        );

        // The addresses immediately outside the block stay tunneled, and both
        // edges inside it stay excluded.
        assert!(routed(&v4, "192.168.0.255"));
        assert!(!routed(&v4, "192.168.1.0"));
        assert!(!routed(&v4, "192.168.1.255"));
        assert!(routed(&v4, "192.168.2.0"));
    }

    #[test]
    fn exclude_mode_handles_several_disjoint_ranges() {
        let (v4, _) = routes_for(
            SplitTunnelMode::Exclude,
            &["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()],
            &[],
        );

        assert!(!routed(&v4, "10.0.0.1"));
        assert!(!routed(&v4, "172.16.5.5"));
        assert!(!routed(&v4, "172.31.255.255"));
        assert!(routed(&v4, "172.32.0.0"));
        assert!(routed(&v4, "8.8.8.8"));
    }

    #[test]
    fn exclude_mode_with_nothing_excluded_is_a_full_tunnel() {
        let (v4, v6) = routes_for(SplitTunnelMode::Exclude, &[], &[]);

        assert_eq!(v4, vec!["0.0.0.0/0".to_string()]);
        assert_eq!(v6, vec!["::/0".to_string()]);
    }

    #[test]
    fn excluding_everything_leaves_no_routes_at_all() {
        let (v4, _) = routes_for(SplitTunnelMode::Exclude, &["0.0.0.0/0".to_string()], &[]);

        assert!(
            v4.is_empty(),
            "nothing may be routed into the tunnel: {v4:?}"
        );
    }

    #[test]
    fn exclude_mode_families_do_not_leak_into_each_other() {
        // An IPv4-only exclusion must not shrink the IPv6 routes, and the
        // complement of each family must stay in that family.
        let (v4, v6) = routes_for(SplitTunnelMode::Exclude, &["10.0.0.0/8".to_string()], &[]);

        assert_eq!(v6, vec!["::/0".to_string()]);
        assert!(v4.iter().all(|route| !route.contains(':')));
    }

    #[test]
    fn exclude_mode_complements_ipv6_ranges() {
        let (_, v6) = routes_for(
            SplitTunnelMode::Exclude,
            &["2001:db8::/32".to_string()],
            &[],
        );

        assert!(!routed(&v6, "2001:db8::1"));
        assert!(routed(&v6, "2001:db9::1"));
        assert!(routed(&v6, "::1"));
    }

    #[test]
    fn complement_routes_are_valid_normalized_cidrs() {
        // The result is fed straight to `nmcli`, so every entry must be a CIDR
        // NetworkManager accepts.
        let (v4, v6) = routes_for(
            SplitTunnelMode::Exclude,
            &["10.11.12.13/32".to_string(), "2001:db8::/48".to_string()],
            &[],
        );

        for route in v4.iter().chain(v6.iter()) {
            parse_and_normalize_cidr(route)
                .unwrap_or_else(|e| panic!("'{route}' should be a valid CIDR: {e}"));
        }
    }

    #[test]
    fn include_mode_routes_exactly_what_was_asked_for() {
        let (v4, v6) = routes_for(
            SplitTunnelMode::Include,
            &["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()],
            &[],
        );

        assert_eq!(v4, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(v6, vec!["2001:db8::/32".to_string()]);
    }

    #[test]
    fn disabled_mode_produces_no_routes() {
        let (v4, v6) = routes_for(SplitTunnelMode::Disabled, &["10.0.0.0/8".to_string()], &[]);

        assert!(v4.is_empty());
        assert!(v6.is_empty());
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

    #[test]
    fn last_known_good_resolution_retained_on_dns_failure() {
        let domain = "nonexistent.vpn.test";
        let fake_ip = "192.0.2.123".parse::<IpAddr>().unwrap();
        let cache = Mutex::new(None);

        assert!(resolve_domain_ips_with(domain, &cache, |_| Vec::new()).is_empty());

        assert_eq!(
            resolve_domain_ips_with("  NONEXISTENT.VPN.TEST  ", &cache, |host| {
                assert_eq!(host, domain);
                vec![fake_ip, fake_ip]
            }),
            vec![fake_ip]
        );

        let ips = resolve_domain_ips_with(domain, &cache, |_| Vec::new());
        assert_eq!(ips, vec![fake_ip]);

        let (v4, _) = routes_for_checked_with(
            SplitTunnelMode::Include,
            &[],
            &[domain.to_string()],
            |host| resolve_domain_ips_with(host, &cache, |_| Vec::new()),
        )
        .expect("should use last-known-good resolution");
        assert_eq!(v4, vec!["192.0.2.123/32".to_string()]);
    }

    #[test]
    fn routes_for_checked_rejects_unresolved_domain_without_cache() {
        let domain = "unresolvable-domain-1234567.invalid";
        let res =
            routes_for_checked_with(SplitTunnelMode::Include, &[], &[domain.to_string()], |_| {
                Vec::new()
            });
        assert!(res.is_err());
        let err = res.unwrap_err().to_string();
        assert!(err.contains("could not resolve split-tunnel domain"));
    }
}
