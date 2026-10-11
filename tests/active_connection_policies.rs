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
use neutron::nm::{NmLifecycle, NmPolicy, ProfileState};
use neutron::testing::{self, MockNmClient, profile};

/// The properties that decide whether a tunnel carries traffic at all.
const ROUTING_KEYS: [&str; 2] = [
    "wireguard.ip4-auto-default-route",
    "wireguard.ip6-auto-default-route",
];

#[test]
fn activation_clears_stale_split_properties_even_when_saved_mode_is_disabled() {
    let (client, path) = connected_client();
    client
        .apply_split_tunnel_all(SplitTunnelMode::Include, &["192.0.2.0/24".into()], &[])
        .unwrap();
    client.switch_to("uuid-us").unwrap();
    for family in ["ipv4", "ipv6"] {
        assert_eq!(
            client
                .setting("uuid-us", &format!("{family}.never-default"))
                .as_deref(),
            Some("no")
        );
        assert_eq!(
            client
                .setting("uuid-us", &format!("{family}.routes"))
                .as_deref(),
            Some("")
        );
        assert_eq!(
            client
                .setting("uuid-us", &format!("{family}.routed-dns"))
                .as_deref(),
            Some("yes")
        );
    }
    testing::remove_temp_config(&path);
}

#[test]
fn protected_activation_refuses_unsupported_families_partial_peers_and_dns() {
    let path = testing::temp_toml_config_path("activation-security");
    config::save(
        &path,
        &AppConfig {
            kill_switch_enabled: true,
            ..Default::default()
        },
    )
    .unwrap();
    for (key, value, warning) in [
        ("ipv6.method", "disabled", "unsupported IP family"),
        ("ipv4.method", "disabled", "unsupported IP family"),
        (
            "wireguard.peers",
            "KEY allowed-ips=10.0.0.0/8;::/0",
            "AllowedIPs",
        ),
        ("ipv4.dns", "", "explicit tunnel DNS"),
    ] {
        let client = MockNmClient::new(vec![testing::inactive("wg", "uuid")])
            .with_config_path(path.clone())
            .with_setting("uuid", key, value);
        let error = client.connect("uuid").unwrap_err().to_string();
        assert!(error.contains(warning), "{error}");
        assert!(client.active_uuids().is_empty());
        assert!(client.setting("uuid", "ipv4.routes").is_none());
    }
    let client =
        MockNmClient::new(vec![testing::inactive("wg", "uuid")]).with_config_path(path.clone());
    client.connect("uuid").unwrap();
    assert_eq!(
        client.setting("uuid", "ipv4.dns-search").as_deref(),
        Some("~.")
    );
    assert_eq!(
        client.setting("uuid", "ipv4.routed-dns").as_deref(),
        Some("no")
    );
    testing::remove_temp_config(&path);
}

#[test]
fn protected_dns_host_routes_survive_split_replacement_and_disabled_mode() {
    let path = testing::temp_toml_config_path("dns-host-routes");
    config::save(
        &path,
        &AppConfig {
            kill_switch_enabled: true,
            ..Default::default()
        },
    )
    .unwrap();
    let client = MockNmClient::new(vec![testing::inactive("wg", "uuid")])
        .with_config_path(path.clone())
        .with_setting("uuid", "ipv4.dns", "198.18.40.1")
        .with_setting("uuid", "ipv6.dns", "fd00:40::1");
    client.connect("uuid").unwrap();
    for mode in [
        SplitTunnelMode::Exclude,
        SplitTunnelMode::Include,
        SplitTunnelMode::Disabled,
    ] {
        let split = SplitTunnelConfig {
            mode,
            cidrs: vec!["198.18.40.0/24".into(), "fd00:40::/64".into()],
            domains: vec![],
        };
        neutron::app::split_tunnel::apply_and_persist_global_split_tunnel(&client, &path, &split)
            .unwrap();
        assert!(
            client
                .setting("uuid", "ipv4.routes")
                .unwrap()
                .contains("198.18.40.1/32 0.0.0.0 5 table=254")
        );
        assert!(
            client
                .setting("uuid", "ipv6.routes")
                .unwrap()
                .contains("fd00:40::1/128 :: 5 table=254")
        );
        if mode == SplitTunnelMode::Disabled {
            assert_eq!(
                client.setting("uuid", "ipv4.never-default").as_deref(),
                Some("no")
            );
            assert_eq!(
                client.setting("uuid", "ipv6.never-default").as_deref(),
                Some("no")
            );
        }
    }
    testing::remove_temp_config(&path);
}

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
    let path = testing::temp_toml_config_path("active-policies");
    config::save(&path, &AppConfig::default()).expect("config should save");
    let client = MockNmClient::new(vec![
        profile("wg-eu", "uuid-eu", ProfileState::Active),
        profile("wg-us", "uuid-us", ProfileState::Inactive),
    ])
    .with_config_path(path.clone());
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

#[test]
fn switching_fails_when_active_profile_teardown_fails() {
    let client = MockNmClient::new(vec![
        profile("wg-eu", "uuid-eu", ProfileState::Active),
        profile("wg-us", "uuid-us", ProfileState::Inactive),
    ])
    .fail_disconnect()
    .strict_disconnect();

    let res = client.switch_to("uuid-us");
    assert!(
        res.is_err(),
        "switch_to must fail if previous active tunnel teardown fails"
    );
}

#[test]
fn sync_reconciles_lockdown_allow_rules_when_lockdown_enabled() {
    let sandbox = testing::scratch_dir("sync-lockdown");
    let config_dir = sandbox.join("neutron");
    let profiles_dir = config_dir.join("profiles");
    std::fs::create_dir_all(&profiles_dir).unwrap();
    let conf = profiles_dir.join("test-sync.conf");
    std::fs::write(&conf, "[Interface]\nPrivateKey = a\n").unwrap();

    let config_path = config_dir.join("config.toml");
    let config = AppConfig {
        general: config::GeneralConfig {
            profiles_dir: profiles_dir.to_string_lossy().to_string(),
            ..Default::default()
        },
        lockdown_enabled: true,
        ..Default::default()
    };
    config::save(&config_path, &config).expect("config should save");

    let client = MockNmClient::new(vec![]).with_config_path(config_path.clone());
    let report = neutron::app::sync::sync_profiles_dir(&client, &config).unwrap();
    assert_eq!(report.imported, vec!["test-sync".to_string()]);
    neutron::app::rebuild_lockdown_if_enabled(&client, &config_path).unwrap();

    assert!(
        !client.lockdown_calls().is_empty(),
        "importing must rebuild lockdown allowances"
    );

    let _ = std::fs::remove_dir_all(&sandbox);
}

#[test]
fn mock_policy_replay_uses_only_supplied_domain_ips_on_every_lifecycle_path() {
    let scratch = testing::scratch_dir("mock-domain-policy");
    let path = scratch.join("config.toml");
    let config = AppConfig {
        global_split_tunnel: SplitTunnelConfig {
            mode: SplitTunnelMode::Include,
            cidrs: vec!["10.1.2.3/8".into()],
            domains: vec!["  FIXTURE.EXAMPLE  ".into()],
        },
        ..Default::default()
    };
    config::save(&path, &config).unwrap();
    let client = MockNmClient::new(vec![testing::inactive("wg-fixture", "uuid-fixture")])
        .with_config_path(path.clone())
        .with_domain_ips(
            "fixture.example",
            vec![
                "192.0.2.123".parse().unwrap(),
                "2001:db8::123".parse().unwrap(),
            ],
        );
    client.connect("uuid-fixture").unwrap();
    client.switch_to("uuid-fixture").unwrap();
    client
        .import_wireguard_profile(&scratch.join("wg-imported.conf"))
        .unwrap();
    for uuid in ["uuid-fixture", "uuid-wg-imported"] {
        assert_eq!(
            client.setting(uuid, "ipv4.routes").as_deref(),
            Some("10.0.0.0/8, 192.0.2.123/32")
        );
        assert_eq!(
            client.setting(uuid, "ipv6.routes").as_deref(),
            Some("2001:db8::123/128")
        );
    }

    // A separate mock has no answers, even for the same domain and fixture path.
    let unresolved = MockNmClient::new(vec![testing::inactive("wg-fixture", "uuid-fixture")])
        .with_config_path(path);
    assert!(unresolved.connect("uuid-fixture").is_err());
    assert!(unresolved.switch_to("uuid-fixture").is_err());
    assert!(
        unresolved
            .import_wireguard_profile(&scratch.join("wg-unresolved.conf"))
            .is_err()
    );
    assert!(unresolved.active_uuids().is_empty());
    assert!(unresolved.setting("uuid-fixture", "ipv4.routes").is_none());
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn importing_profile_inherits_global_kill_switch_and_split_tunnel() {
    let config_path = testing::temp_toml_config_path("import-policy");

    let config = AppConfig {
        kill_switch_enabled: true,
        global_split_tunnel: SplitTunnelConfig {
            mode: SplitTunnelMode::Include,
            cidrs: vec!["10.0.0.0/8".to_string()],
            domains: Vec::new(),
        },
        ..Default::default()
    };
    config::save(&config_path, &config).expect("config should save");

    let client = MockNmClient::new(vec![]).with_config_path(config_path.clone());
    client
        .import_wireguard_profile(std::path::Path::new("/tmp/wg-imported.conf"))
        .expect("import should succeed");

    assert_eq!(
        client
            .setting("uuid-wg-imported", "connection.autoconnect")
            .as_deref(),
        Some("no"),
        "importing must disable autoconnect so selector manages startup"
    );
    assert_eq!(
        client
            .setting("uuid-wg-imported", "ipv4.dns-priority")
            .as_deref(),
        Some("-1500"),
        "importing must inherit active global kill switch setting"
    );
    assert_eq!(
        client
            .setting("uuid-wg-imported", "ipv4.never-default")
            .as_deref(),
        Some("yes"),
        "importing must inherit active global split tunnel configuration"
    );

    testing::remove_temp_config(&config_path);
}

#[test]
fn activating_unconfigured_profile_inherits_global_kill_switch_and_split_tunnel() {
    let config_path = testing::temp_toml_config_path("activate-policy");

    let config = AppConfig {
        kill_switch_enabled: true,
        global_split_tunnel: SplitTunnelConfig {
            mode: SplitTunnelMode::Exclude,
            cidrs: vec!["192.168.1.0/24".to_string()],
            domains: Vec::new(),
        },
        ..Default::default()
    };
    config::save(&config_path, &config).expect("config should save");

    let client = MockNmClient::new(vec![profile("wg-raw", "uuid-raw", ProfileState::Inactive)])
        .with_config_path(config_path.clone());
    client.connect("uuid-raw").expect("connect should succeed");

    assert_eq!(
        client.setting("uuid-raw", "ipv4.dns-priority").as_deref(),
        Some("-1500"),
        "connecting must apply global kill switch to previously unconfigured profile"
    );
    assert_eq!(
        client.setting("uuid-raw", "ipv4.never-default").as_deref(),
        Some("yes"),
        "connecting must apply global split tunnel routing to profile"
    );

    testing::remove_temp_config(&config_path);
}

#[test]
fn policy_sweep_and_activation_are_coordinated_without_conflicting_settings() {
    let path = testing::temp_config_path("coord-test");
    let initial_cfg = AppConfig {
        global_split_tunnel: SplitTunnelConfig {
            mode: SplitTunnelMode::Include,
            cidrs: vec!["10.0.0.0/8".to_string()],
            domains: Vec::new(),
        },
        ..Default::default()
    };
    config::save(&path, &initial_cfg).unwrap();

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let client = MockNmClient::new(vec![
        profile("wg-a", "uuid-a", ProfileState::Inactive),
        profile("wg-b", "uuid-b", ProfileState::Inactive),
    ])
    .with_config_path(path.clone())
    .with_sweep_barrier(barrier.clone());

    let client_for_sweep = client.clone();
    let path_for_sweep = path.clone();
    let sweep_handle = std::thread::spawn(move || {
        let new_st = SplitTunnelConfig {
            mode: SplitTunnelMode::Exclude,
            cidrs: vec!["192.168.0.0/16".to_string()],
            domains: Vec::new(),
        };
        neutron::app::split_tunnel::apply_and_persist_global_split_tunnel(
            &client_for_sweep,
            &path_for_sweep,
            &new_st,
        )
    });

    // Wait until policy sweep has entered apply and hit the barrier
    barrier.wait();

    let client_for_conn = client.clone();
    let conn_handle = std::thread::spawn(move || client_for_conn.connect("uuid-a"));

    let sweep_res = sweep_handle.join().unwrap();
    let conn_res = conn_handle.join().unwrap();
    assert!(sweep_res.is_ok());
    assert!(conn_res.is_ok());

    // uuid-a must end up with Exclude policy, not the stale Include policy
    let saved = config::load(&path).unwrap();
    assert_eq!(saved.global_split_tunnel.mode, SplitTunnelMode::Exclude);

    // Verify settings on uuid-a reflect Exclude mode
    let routes = client.setting("uuid-a", "ipv4.routes").unwrap();
    assert!(
        !routes.contains("10.0.0.0/8"),
        "must not retain old Include route"
    );

    testing::remove_temp_config(&path);
}
