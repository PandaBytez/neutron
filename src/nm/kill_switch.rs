//! NetworkManager-native kill switch for WireGuard profiles.
//!
//! The kill switch is implemented purely through NetworkManager connection
//! properties, keeping NetworkManager the single source of truth (no firewall
//! rules, no `wg-quick`, no privileged helper). Enabling it forces
//! NetworkManager's automatic default-route policy routing on the WireGuard
//! connection -- the same "improved rule-based routing" that `wg-quick`
//! performs: the tunnel's default route is installed in a dedicated routing
//! table guarded by an `fwmark` and a `suppress_prefixlength 0` policy rule.
//! While the tunnel is active, every non-tunnel packet is forced into that
//! table, so if the encrypted path fails there is no fallback to the physical
//! default route and traffic is dropped instead of leaking. A negative DNS
//! priority additionally gives the tunnel's resolvers exclusive priority.
//!
//! This routing policy only takes effect for full-tunnel profiles (a peer whose
//! allowed IPs include `0.0.0.0/0` / `::/0`) and applies the next time the
//! profile is activated.

use crate::error::{AppError, AppResult};

/// Whether the NetworkManager kill-switch routing policy is explicitly enforced
/// on a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillSwitchState {
    Enabled,
    Disabled,
}

impl KillSwitchState {
    pub fn is_enabled(self) -> bool {
        matches!(self, KillSwitchState::Enabled)
    }

    /// Short human-readable label (`on` / `off`) for CLI output.
    pub fn label(self) -> &'static str {
        match self {
            KillSwitchState::Enabled => "on",
            KillSwitchState::Disabled => "off",
        }
    }
}

/// DNS priority applied to the tunnel when the kill switch is enabled. A
/// negative priority makes the tunnel's DNS servers exclusive, preventing DNS
/// queries from leaking to other connections' resolvers.
const ENABLED_DNS_PRIORITY: &str = "-1500";

/// Default DNS priority restored when the kill switch is disabled.
const DEFAULT_DNS_PRIORITY: &str = "0";

/// The two WireGuard automatic-default-route properties whose forced-on state
/// constitutes the routing kill switch, queried (and parsed) in this order.
const STATUS_FIELDS: &str = "wireguard.ip4-auto-default-route,wireguard.ip6-auto-default-route";

/// `nmcli` arguments that enable the kill switch on connection `uuid`.
pub fn enable_args(uuid: &str) -> Vec<String> {
    vec![
        "connection".to_string(),
        "modify".to_string(),
        uuid.to_string(),
        "wireguard.ip4-auto-default-route".to_string(),
        "yes".to_string(),
        "wireguard.ip6-auto-default-route".to_string(),
        "yes".to_string(),
        "ipv4.dns-priority".to_string(),
        ENABLED_DNS_PRIORITY.to_string(),
        "ipv6.dns-priority".to_string(),
        ENABLED_DNS_PRIORITY.to_string(),
    ]
}

/// `nmcli` arguments that disable the kill switch, restoring NetworkManager
/// defaults (automatic default-route handling and default DNS priority).
pub fn disable_args(uuid: &str) -> Vec<String> {
    vec![
        "connection".to_string(),
        "modify".to_string(),
        uuid.to_string(),
        "wireguard.ip4-auto-default-route".to_string(),
        "default".to_string(),
        "wireguard.ip6-auto-default-route".to_string(),
        "default".to_string(),
        "ipv4.dns-priority".to_string(),
        DEFAULT_DNS_PRIORITY.to_string(),
        "ipv6.dns-priority".to_string(),
        DEFAULT_DNS_PRIORITY.to_string(),
    ]
}

/// `nmcli` arguments that read the kill-switch routing properties of `uuid`.
///
/// `-g` (get-values) prints just the requested values, one per line, in the
/// order given by [`STATUS_FIELDS`].
pub fn status_args(uuid: &str) -> Vec<String> {
    vec![
        "-g".to_string(),
        STATUS_FIELDS.to_string(),
        "connection".to_string(),
        "show".to_string(),
        uuid.to_string(),
    ]
}

/// Classify the kill-switch state from the [`status_args`] query output.
///
/// NetworkManager renders the ternary `*-auto-default-route` properties as
/// `1` (forced on), `0` (forced off), or `-1` (automatic). The kill switch is
/// considered enabled only when both the IPv4 and IPv6 policies are explicitly
/// forced on (`1`) -- the state [`enable_args`] applies.
pub fn parse_status(output: &str) -> AppResult<KillSwitchState> {
    let mut lines = output.lines();
    let ip4 = lines
        .next()
        .ok_or_else(|| AppError::NmParseFailed(output.to_string()))?
        .trim();
    let ip6 = lines
        .next()
        .ok_or_else(|| AppError::NmParseFailed(output.to_string()))?
        .trim();

    if ip4 == "1" && ip6 == "1" {
        Ok(KillSwitchState::Enabled)
    } else {
        Ok(KillSwitchState::Disabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_args_target_the_uuid_and_force_routing_on() {
        let args = enable_args("uuid-1");

        assert_eq!(args[0], "connection");
        assert_eq!(args[1], "modify");
        assert_eq!(args[2], "uuid-1");
        assert!(window_contains(
            &args,
            "wireguard.ip4-auto-default-route",
            "yes"
        ));
        assert!(window_contains(
            &args,
            "wireguard.ip6-auto-default-route",
            "yes"
        ));
        assert!(window_contains(
            &args,
            "ipv4.dns-priority",
            ENABLED_DNS_PRIORITY
        ));
        assert!(window_contains(
            &args,
            "ipv6.dns-priority",
            ENABLED_DNS_PRIORITY
        ));
    }

    #[test]
    fn disable_args_restore_networkmanager_defaults() {
        let args = disable_args("uuid-1");

        assert_eq!(args[2], "uuid-1");
        assert!(window_contains(
            &args,
            "wireguard.ip4-auto-default-route",
            "default"
        ));
        assert!(window_contains(
            &args,
            "wireguard.ip6-auto-default-route",
            "default"
        ));
        assert!(window_contains(
            &args,
            "ipv4.dns-priority",
            DEFAULT_DNS_PRIORITY
        ));
        assert!(window_contains(
            &args,
            "ipv6.dns-priority",
            DEFAULT_DNS_PRIORITY
        ));
    }

    #[test]
    fn status_args_request_both_auto_default_route_fields() {
        let args = status_args("uuid-1");

        assert_eq!(args[0], "-g");
        assert_eq!(args[1], STATUS_FIELDS);
        assert_eq!(
            args,
            vec!["-g", STATUS_FIELDS, "connection", "show", "uuid-1"]
        );
    }

    #[test]
    fn parse_status_reports_enabled_when_both_forced_on() {
        let state = parse_status("1\n1\n").expect("status should parse");

        assert_eq!(state, KillSwitchState::Enabled);
    }

    #[test]
    fn parse_status_reports_disabled_for_automatic_values() {
        let state = parse_status("-1\n-1\n").expect("status should parse");

        assert_eq!(state, KillSwitchState::Disabled);
    }

    #[test]
    fn parse_status_reports_disabled_when_only_ipv4_forced_on() {
        let state = parse_status("1\n-1\n").expect("status should parse");

        assert_eq!(state, KillSwitchState::Disabled);
    }

    #[test]
    fn parse_status_fails_on_truncated_output() {
        let result = parse_status("1\n");

        assert!(matches!(result, Err(AppError::NmParseFailed(_))));
    }

    /// True when `args` contains `key` immediately followed by `value`.
    fn window_contains(args: &[String], key: &str, value: &str) -> bool {
        args.windows(2)
            .any(|pair| pair[0] == key && pair[1] == value)
    }
}
