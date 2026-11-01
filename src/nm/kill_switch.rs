//! NetworkManager-native kill switch for WireGuard profiles.
//!
//! The kill switch is implemented purely through NetworkManager connection
//! properties, keeping NetworkManager the single source of truth (no firewall
//! rules, no `wg-quick`, no privileged helper).
//!
//! The routing half of the guarantee -- the tunnel's default route in a
//! dedicated table behind an `fwmark` and a `suppress_prefixlength 0` rule, so a
//! failing tunnel drops packets instead of falling back to the physical default
//! route -- lives in [`crate::nm::tunnel_routing`] and is pinned on *every*
//! profile, whether or not the kill switch is on.
//!
//! That split is deliberate. Those policy rules are also what makes a
//! full-tunnel profile carry traffic at all, so tying them to this toggle meant
//! turning the kill switch off silently stopped the VPN routing anything: the
//! profile connected, the UI reported "Connected", and traffic kept leaving over
//! the physical interface with the real IP exposed. Routing is therefore not
//! optional. This toggle selects exclusive DNS, routes resolvers via the tunnel,
//! and refuses activation without both protected IP families unless lockdown
//! blocks the unsupported traffic. Explicit split bypasses remain intentional.
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
///
/// Automatic default-route handling is re-pinned here as well as in
/// [`crate::nm::tunnel_routing`]: this is a bulk sweep over every profile, so it
/// is the cheapest place to repair one left at NetworkManager's `default` by an
/// older version. It is pinned identically in both states -- see the module docs
/// for why disabling the kill switch must not switch routing off.
pub fn set_args(uuid: &str, enable: bool, has_ipv6: bool) -> Vec<String> {
    let dns_priority = if enable {
        ENABLED_DNS_PRIORITY
    } else {
        DEFAULT_DNS_PRIORITY
    };
    let v6_priority = if enable && has_ipv6 {
        ENABLED_DNS_PRIORITY
    } else {
        DEFAULT_DNS_PRIORITY
    };
    let auto_route = crate::nm::tunnel_routing::AUTO_DEFAULT_ROUTE;
    let v6_auto = if has_ipv6 { auto_route } else { "no" };
    vec![
        "connection".to_string(),
        "modify".to_string(),
        uuid.to_string(),
        "wireguard.ip4-auto-default-route".to_string(),
        auto_route.to_string(),
        "wireguard.ip6-auto-default-route".to_string(),
        v6_auto.to_string(),
        "ipv4.dns-priority".to_string(),
        dns_priority.to_string(),
        "ipv6.dns-priority".to_string(),
        v6_priority.to_string(),
        // DNS transport must stay on the tunnel even when its address is excluded.
        "ipv4.routed-dns".to_string(),
        "yes".to_string(),
        "ipv6.routed-dns".to_string(),
        "yes".to_string(),
    ]
}

/// Refuse claiming dual-family protection without a usable tunnel for both.
/// Lockdown may instead block unsupported families; split bypasses are intentional.
pub(crate) fn validate_protection(
    config: &crate::config::AppConfig,
    has_ipv4: bool,
    has_ipv6: bool,
    peers: &str,
) -> crate::error::AppResult<()> {
    if !config.kill_switch_enabled || config.lockdown_enabled {
        return Ok(());
    }
    let allowed = allowed_networks(peers);
    if !has_ipv4 || !has_ipv6 {
        return Err(crate::error::AppError::Config(
            "activation refused: kill switch cannot protect an unsupported IP family; \
             use a dual-stack tunnel or enable lockdown to block cleartext IPv4/IPv6"
                .into(),
        ));
    }
    if !config.global_split_tunnel.mode.is_enabled()
        && (!allowed.contains(&"0.0.0.0/0".to_string()) || !allowed.contains(&"::/0".to_string()))
    {
        return Err(crate::error::AppError::Config(
            "activation refused: full-tunnel kill protection requires peer AllowedIPs \
             0.0.0.0/0 and ::/0; enable lockdown for a partial tunnel"
                .into(),
        ));
    }
    Ok(())
}

pub(crate) fn allowed_networks(peers: &str) -> Vec<String> {
    peers
        .split("allowed-ips")
        .skip(1)
        .flat_map(|part| {
            part.trim_start_matches(|c: char| c.is_whitespace() || c == '=')
                .split(|c: char| c.is_whitespace() || c == ';' || c == ',')
                .filter(|token| !token.is_empty())
                .map(crate::nm::split_tunnel::parse_and_normalize_cidr)
                .map_while(Result::ok)
                .map(|(cidr, _)| cidr)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_defaults_are_read_with_spacing_and_both_address_families() {
        for peers in [
            "KEY allowed-ips=0.0.0.0/0;::/0 endpoint=192.0.2.1:51820",
            "KEY allowed-ips = 0.0.0.0/0, ::/0 persistent-keepalive = 25",
        ] {
            assert_eq!(allowed_networks(peers), ["0.0.0.0/0", "::/0"]);
        }
    }

    #[test]
    fn enable_args_target_the_uuid_and_force_routing_on() {
        let args = set_args("uuid-1", true, true);

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
    fn disable_args_restore_default_dns_priority() {
        let args = set_args("uuid-1", false, true);

        assert_eq!(args[2], "uuid-1");
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
    fn disabling_the_kill_switch_keeps_the_tunnel_routing() {
        // Regression: disabling used to write `auto-default-route = default`,
        // which made NetworkManager install no routes at all -- the profile
        // connected, the UI said "Connected", and traffic kept leaving over the
        // physical interface with the real IP exposed.
        let args = set_args("uuid-1", false, true);

        for family in [
            "wireguard.ip4-auto-default-route",
            "wireguard.ip6-auto-default-route",
        ] {
            assert!(
                window_contains(&args, family, crate::nm::tunnel_routing::AUTO_DEFAULT_ROUTE),
                "{family} must stay pinned when the kill switch is off: {args:?}"
            );
            assert!(!window_contains(&args, family, "default"));
        }
    }

    #[test]
    fn both_states_route_identically_and_differ_only_in_dns() {
        let enabled = set_args("uuid-1", true, true);
        let disabled = set_args("uuid-1", false, true);

        let differing: Vec<_> = enabled
            .iter()
            .zip(&disabled)
            .filter(|(a, b)| a != b)
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();

        assert_eq!(
            differing,
            vec![
                (ENABLED_DNS_PRIORITY, DEFAULT_DNS_PRIORITY),
                (ENABLED_DNS_PRIORITY, DEFAULT_DNS_PRIORITY),
            ],
            "only the DNS priority may differ between the two states"
        );
    }

    #[test]
    fn ipv6_is_not_forced_when_ipv6_is_absent() {
        let args = set_args("uuid-1", true, false);

        assert!(window_contains(
            &args,
            "wireguard.ip6-auto-default-route",
            "no"
        ));
        assert!(window_contains(
            &args,
            "ipv6.dns-priority",
            DEFAULT_DNS_PRIORITY
        ));
    }

    #[test]
    fn enable_and_disable_toggle_the_same_properties() {
        let enable = set_args("uuid-1", true, true);
        let disable = set_args("uuid-1", false, true);

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
