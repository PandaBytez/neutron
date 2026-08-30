//! Policy changes made while a tunnel is up.
//!
//! These cover the class of bug where toggling a policy silently breaks the
//! *active* connection. The original instance: disabling the kill switch wrote
//! `wireguard.ip4-auto-default-route = default`, NetworkManager then installed
//! no routes at all, and the profile activated while traffic kept leaving over
//! the physical interface with the real IP exposed -- with the UI still
//! reporting "Connected".
//!
//! Nothing in the suite could see that, because the mock only recorded *that*
//! `set_kill_switch_all` was called, never *what* it wrote. It now replays the
//! real `nmcli` argument builders into simulated profile settings, so these
//! tests assert on the configuration a profile actually ends up with.

use neutron::config::{self, AppConfig, SplitTunnelConfig, SplitTunnelMode};
use neutron::nm::{NmClient, ProfileState};
use neutron::testing::{self, MockNmClient, profile};

/// The properties that decide whether a tunnel carries traffic at all.
const ROUTING_KEYS: [&str; 2] = [
    "wireguard.ip4-auto-default-route",
    "wireguard.ip6-auto-default-route",
];

/// Fail if any profile has been left in a state where NetworkManager would
/// install no routes for it.
fn assert_every_profile_still_routes(client: &MockNmClient, context: &str) {
    for uuid in client.uuids() {
        for key in ROUTING_KEYS {
            let value = client.setting(&uuid, key).unwrap_or_else(|| {
                panic!("{context}: {uuid} has no {key}; the tunnel would not route")
            });
            assert_eq!(
                value, "yes",
                "{context}: {uuid} left {key}={value}, so the tunnel would carry no traffic \
                 while the UI reports a working connection"
            );
        }
    }
}

fn connected_client() -> (MockNmClient, std::path::PathBuf) {
    let client = MockNmClient::new(vec![
        profile("wg-eu", "uuid-eu", ProfileState::Active),
        profile("wg-us", "uuid-us", ProfileState::Inactive),
    ]);
    let path = testing::temp_config_path("active-policies");
    config::save(&path, &AppConfig::default()).expect("config should save");
    (client, path)
}

fn set_split_tunnel(client: &MockNmClient, path: &std::path::Path, mode: SplitTunnelMode) {
    let cfg = SplitTunnelConfig {
        mode,
        cidrs: vec!["10.0.0.0/8".to_string()],
        domains: Vec::new(),
    };
    neutron::app::split_tunnel::apply_and_persist_global_split_tunnel(client, path, &cfg)
        .expect("split tunnel should apply");
}

#[test]
fn disabling_the_kill_switch_on_a_live_tunnel_keeps_it_routing() {
    let (client, path) = connected_client();

    neutron::app::set_global_kill_switch(&client, &path, false).expect("disable should succeed");

    assert_every_profile_still_routes(&client, "kill switch disabled");
    assert_eq!(
        client.setting("uuid-eu", "ipv4.dns-priority").as_deref(),
        Some("0"),
        "disabling must still relax the DNS priority"
    );
    assert_eq!(
        client.active_uuid().as_deref(),
        Some("uuid-eu"),
        "toggling a policy must not drop the live tunnel"
    );

    testing::remove_temp_config(&path);
}

#[test]
fn enabling_the_kill_switch_on_a_live_tunnel_keeps_it_routing() {
    let (client, path) = connected_client();

    neutron::app::set_global_kill_switch(&client, &path, true).expect("enable should succeed");

    assert_every_profile_still_routes(&client, "kill switch enabled");
    assert_eq!(
        client.setting("uuid-eu", "ipv4.dns-priority").as_deref(),
        Some("-1500"),
        "enabling must give the tunnel's resolvers exclusive priority"
    );
    assert_eq!(client.active_uuid().as_deref(), Some("uuid-eu"));

    testing::remove_temp_config(&path);
}

#[test]
fn cycling_the_kill_switch_never_regresses_routing() {
    // The bug only appeared on the *off* edge, so the round trip matters: each
    // transition must leave the tunnel able to carry traffic.
    let (client, path) = connected_client();

    for enable in [true, false, true, false] {
        neutron::app::set_global_kill_switch(&client, &path, enable)
            .expect("toggle should succeed");
        assert_every_profile_still_routes(&client, &format!("kill switch -> {enable}"));
        assert_eq!(
            client.active_uuid().as_deref(),
            Some("uuid-eu"),
            "the live tunnel must survive every toggle"
        );
    }

    testing::remove_temp_config(&path);
}

#[test]
fn changing_split_tunnel_mode_on_a_live_tunnel_keeps_it_routing() {
    let (client, path) = connected_client();

    for mode in [
        SplitTunnelMode::Include,
        SplitTunnelMode::Exclude,
        SplitTunnelMode::Disabled,
    ] {
        set_split_tunnel(&client, &path, mode);

        // Split tunneling legitimately changes *which* routes exist, but it
        // must never leave the profile unable to route at all.
        let never_default = client
            .setting("uuid-eu", "ipv4.never-default")
            .expect("never-default should be written");
        let routes = client
            .setting("uuid-eu", "ipv4.routes")
            .expect("routes should be written");

        match mode {
            SplitTunnelMode::Disabled => {
                assert_eq!(
                    never_default, "no",
                    "full tunnel must own the default route"
                );
                assert!(
                    routes.is_empty(),
                    "stale routes would keep steering traffic"
                );
            }
            _ => {
                assert_eq!(never_default, "yes");
                assert!(
                    !routes.is_empty(),
                    "{mode} mode with never-default=yes and no routes sends nothing \
                     through the tunnel"
                );
            }
        }

        assert_eq!(
            client.active_uuid().as_deref(),
            Some("uuid-eu"),
            "changing split tunneling must not drop the live tunnel"
        );
    }

    testing::remove_temp_config(&path);
}

#[test]
fn exclude_mode_on_a_live_tunnel_does_not_route_the_excluded_range_into_it() {
    let (client, path) = connected_client();

    set_split_tunnel(&client, &path, SplitTunnelMode::Exclude);

    let routes = client
        .setting("uuid-eu", "ipv4.routes")
        .expect("routes should be written");
    assert!(
        !routes.split(", ").any(|route| route == "10.0.0.0/8"),
        "the excluded range must not be installed as a tunnel route: {routes}"
    );
    assert!(
        routes.split(", ").count() > 1,
        "everything outside the exclusion must still be tunneled: {routes}"
    );

    testing::remove_temp_config(&path);
}

#[test]
fn disabling_autoconnect_on_a_live_tunnel_does_not_drop_it() {
    let (client, path) = connected_client();

    // The selector relies on this sweep; it must never touch activation state.
    client
        .set_autoconnect_all(false)
        .expect("autoconnect sweep should succeed");

    assert_eq!(
        client
            .setting("uuid-eu", "connection.autoconnect")
            .as_deref(),
        Some("no")
    );
    assert_eq!(
        client.active_uuid().as_deref(),
        Some("uuid-eu"),
        "disabling autoconnect must not disturb a running tunnel"
    );

    testing::remove_temp_config(&path);
}

#[test]
fn lockdown_on_a_live_tunnel_allows_that_tunnel_through() {
    let (client, path) = connected_client();

    neutron::app::set_global_lockdown(&client, &path, true).expect("lockdown should enable");

    assert_eq!(
        client.lockdown_calls(),
        vec!["lockdown:on".to_string()],
        "the firewall must be rebuilt from the current tunnel set"
    );
    assert_eq!(
        client.active_uuid().as_deref(),
        Some("uuid-eu"),
        "enabling lockdown must not drop the live tunnel"
    );

    testing::remove_temp_config(&path);
}

#[test]
fn connecting_pins_routing_before_the_profile_is_brought_up() {
    // Self-healing: a profile that has never been through a policy sweep -- a
    // fresh import, or one left at NetworkManager's default by an older version
    // -- must still route the first time it is used.
    let client = MockNmClient::new(vec![profile("wg-eu", "uuid-eu", ProfileState::Inactive)]);

    for key in ROUTING_KEYS {
        assert!(
            client.setting("uuid-eu", key).is_none(),
            "precondition: the profile starts unconfigured"
        );
    }

    client.connect("uuid-eu").expect("connect should succeed");

    assert_every_profile_still_routes(&client, "after connect");
    assert_eq!(client.active_uuid().as_deref(), Some("uuid-eu"));
}

#[test]
fn switching_profiles_pins_routing_on_the_new_target() {
    let (client, path) = connected_client();

    client.switch_to("uuid-us").expect("switch should succeed");

    for key in ROUTING_KEYS {
        assert_eq!(
            client.setting("uuid-us", key).as_deref(),
            Some("yes"),
            "the profile being switched to must be able to route"
        );
    }
    assert_eq!(
        client.active_uuid().as_deref(),
        Some("uuid-us"),
        "switching replaces the active tunnel rather than adding to it"
    );

    testing::remove_temp_config(&path);
}
