//! NetworkManager's automatic default-route handling for WireGuard tunnels.
//!
//! This is what actually makes a full-tunnel profile carry traffic. With it on,
//! NetworkManager places the peers' `0.0.0.0/0` / `::/0` route in a dedicated
//! routing table and installs two policy rules -- a `suppress_prefixlength 0`
//! rule so the physical default route cannot be used as a fallback, and an
//! `fwmark` rule that sends everything else to the tunnel table. It is the same
//! "Improved Rule-based Routing" that `wg-quick`'s `Table=auto` performs.
//!
//! Neutron sets this explicitly rather than leaving it at NetworkManager's
//! `default`. NetworkManager documents `default` as "enable when the peer has a
//! default-route allowed-ips and `never-default` is unset", which describes
//! every full-tunnel profile -- but in practice it was observed installing *no
//! routes at all*: the tunnel activated, NetworkManager reported the connection
//! as fully activated, and traffic silently kept using the physical interface
//! while the UI said "Connected". A VPN client that reports a connection while
//! leaking the real address is the worst possible failure, so the property is
//! pinned instead of inferred.

/// The value pinned onto every managed profile. See the module docs for why
/// this is never left at NetworkManager's `default`.
pub const AUTO_DEFAULT_ROUTE: &str = "yes";

/// `nmcli` arguments that pin automatic default-route handling on connection
/// `uuid`.
///
/// IPv4 is always pinned to `yes`. IPv6 is pinned to `yes` when the profile has
/// an IPv6 address/method configured, and `no` otherwise -- setting IPv6 default
/// route on an IPv4-only profile creates a default route to an interface without
/// an IPv6 address, black-holing all IPv6 traffic.
///
/// Applied immediately before activation (see [`crate::nm::NmClient::connect`]),
/// so a profile imported out-of-band -- or one left at `default` by an older
/// version -- routes correctly the first time it is used.
pub fn set_args(uuid: &str, has_ipv6: bool) -> Vec<String> {
    let v6_auto = if has_ipv6 { AUTO_DEFAULT_ROUTE } else { "no" };
    vec![
        "connection".to_string(),
        "modify".to_string(),
        uuid.to_string(),
        "wireguard.ip4-auto-default-route".to_string(),
        AUTO_DEFAULT_ROUTE.to_string(),
        "wireguard.ip6-auto-default-route".to_string(),
        v6_auto.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_args_pins_both_families_when_ipv6_is_enabled() {
        let args = set_args("uuid-1", true);

        assert_eq!(args[0], "connection");
        assert_eq!(args[1], "modify");
        assert_eq!(args[2], "uuid-1");
        assert_eq!(args[3], "wireguard.ip4-auto-default-route");
        assert_eq!(args[4], "yes");
        assert_eq!(args[5], "wireguard.ip6-auto-default-route");
        assert_eq!(args[6], "yes");
    }

    #[test]
    fn set_args_disables_ipv6_auto_default_when_ipv6_is_absent() {
        let args = set_args("uuid-1", false);

        assert_eq!(args[3], "wireguard.ip4-auto-default-route");
        assert_eq!(args[4], "yes");
        assert_eq!(args[5], "wireguard.ip6-auto-default-route");
        assert_eq!(args[6], "no");
    }

    #[test]
    fn the_pinned_value_is_never_networkmanagers_default() {
        // Regression: leaving this at `default` meant NetworkManager installed
        // no routes, so activating a profile exposed the real IP while the UI
        // reported a working connection.
        assert_ne!(AUTO_DEFAULT_ROUTE, "default");
        assert_ne!(AUTO_DEFAULT_ROUTE, "no");
    }
}
