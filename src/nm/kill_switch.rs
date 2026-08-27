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
//! The kill switch is a *global* setting: the application applies these
//! properties to every WireGuard profile at once (see
//! [`crate::nm::NmClient::set_kill_switch_all`]) rather than per profile. The
//! routing policy only takes effect for full-tunnel profiles (a peer whose
//! allowed IPs include `0.0.0.0/0` / `::/0`) and applies the next time a
//! profile is activated.

/// DNS priority applied to the tunnel when the kill switch is enabled. A
/// negative priority makes the tunnel's DNS servers exclusive, preventing DNS
/// queries from leaking to other connections' resolvers.
const ENABLED_DNS_PRIORITY: &str = "-1500";

/// Default DNS priority restored when the kill switch is disabled.
const DEFAULT_DNS_PRIORITY: &str = "0";

/// `nmcli` arguments that set the kill switch on connection `uuid` to enabled or disabled.
pub fn set_args(uuid: &str, enable: bool) -> Vec<String> {
    let (auto_route, dns_priority) = if enable {
        ("yes", ENABLED_DNS_PRIORITY)
    } else {
        ("default", DEFAULT_DNS_PRIORITY)
    };
    vec![
        "connection".to_string(),
        "modify".to_string(),
        uuid.to_string(),
        "wireguard.ip4-auto-default-route".to_string(),
        auto_route.to_string(),
        "wireguard.ip6-auto-default-route".to_string(),
        auto_route.to_string(),
        "ipv4.dns-priority".to_string(),
        dns_priority.to_string(),
        "ipv6.dns-priority".to_string(),
        dns_priority.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_args_target_the_uuid_and_force_routing_on() {
        let args = set_args("uuid-1", true);

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
        let args = set_args("uuid-1", false);

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
    fn enable_and_disable_toggle_the_same_properties() {
        let enable = set_args("uuid-1", true);
        let disable = set_args("uuid-1", false);

        // Disabling must touch exactly the same properties, in the same order,
        // that enabling sets. Otherwise the kill switch could leave a property
        // stuck at its enabled value with no way to revert it to the
        // NetworkManager default.
        assert_eq!(enable.len(), disable.len());
        assert_eq!(property_keys(&enable), property_keys(&disable));
    }

    /// True when `args` contains `key` immediately followed by `value`.
    fn window_contains(args: &[String], key: &str, value: &str) -> bool {
        args.windows(2)
            .any(|pair| pair[0] == key && pair[1] == value)
    }

    /// The property names from an `nmcli connection modify <uuid> k v k v ...`
    /// argument list. The first three slots are the `connection modify <uuid>`
    /// prefix; after that, keys and values alternate, so the keys are every
    /// other slot starting at index 3.
    fn property_keys(args: &[String]) -> Vec<String> {
        args[3..].iter().step_by(2).cloned().collect()
    }
}
