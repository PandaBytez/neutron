//! System tests: the real [`CliNmClient`] against a real NetworkManager.
//!
//! Everything else in the suite runs against `MockNmClient`, which replays
//! Neutron's own argument builders. That proves the builders are self-consistent
//! but cannot prove NetworkManager *accepts* those arguments, *stores* them, or
//! reports them back the way the parsers expect. Every leak in `BUGS.md` lived
//! in exactly that gap.
//!
//! These tests close it by driving `nmcli` for real. They are `#[ignore]`d and
//! additionally call [`require_sandbox`], so they only ever run inside the
//! disposable container -- see `testing/README.md`.
//!
//! Run with: `./testing/run-container-tests.sh`

use std::path::PathBuf;

use neutron::config::SplitTunnelMode;
use neutron::nm::{CliNmClient, NmClient};
use neutron::testing::{require_sandbox, sample_wireguard_config, sandbox_profile_name};

/// A WireGuard profile that exists in NetworkManager for the duration of a test
/// and is removed afterwards, including on panic.
struct Fixture {
    name: String,
    uuid: String,
    path: PathBuf,
}

impl Fixture {
    /// Import a fresh profile and return a handle to it.
    fn import(label: &str, address: &str, dns: &str) -> Self {
        Self::import_config(label, &sample_wireguard_config(address, dns))
    }

    fn import_config(label: &str, config: &str) -> Self {
        let name = sandbox_profile_name(label);
        let path = std::env::temp_dir().join(format!("{name}.conf"));
        std::fs::write(&path, config).expect("fixture config should be writable");

        let client = CliNmClient;
        client
            .import_wireguard_profile(&path)
            .expect("NetworkManager should import a valid WireGuard config");

        let uuid = client
            .list_wireguard_profiles()
            .expect("profiles should list")
            .into_iter()
            .find(|profile| profile.name == name)
            .map(|profile| profile.uuid)
            .unwrap_or_else(|| panic!("imported profile '{name}' should be listed"));

        Self { name, uuid, path }
    }

    /// Read a single property back from NetworkManager.
    fn get(&self, key: &str) -> String {
        let output = std::process::Command::new("nmcli")
            .args(["-g", key, "connection", "show", &self.uuid])
            .output()
            .expect("nmcli should run");
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Runs on panic too, so one failing assertion cannot leave profiles
        // behind and make later tests non-reproducible.
        let _ = std::process::Command::new("nmcli")
            .args(["connection", "delete", &self.uuid])
            .output();
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn idle_on_demand_tunnel_stays_active_and_carries_its_first_packet() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    require_sandbox();
    fn public_key(private_key: &str) -> String {
        let mut child = Command::new("wg")
            .arg("pubkey")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(private_key.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }
    let a_key = "OMHVnT2Gm0ZBb3xF2Cq0hZ0jVQ1z3T0lQ0Z0YQ0Z0X8=";
    let b_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=";
    let peer = Fixture::import_config(
        "idlepeer",
        &format!(
            "[Interface]\nPrivateKey = {a_key}\nAddress = 10.253.34.1/32\nListenPort = 51834\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 10.253.34.2/32\n",
            public_key(b_key)
        ),
    );
    let client = Fixture::import_config(
        "idleclient",
        &format!(
            "[Interface]\nPrivateKey = {b_key}\nAddress = 10.253.34.2/32\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 10.253.34.3/32\nEndpoint = 127.0.0.1:51834\n",
            public_key(a_key)
        ),
    );
    CliNmClient
        .connect(&peer.uuid)
        .expect("passive responder should stay active");
    CliNmClient
        .connect(&client.uuid)
        .expect("idle on-demand client should stay active");
    std::thread::sleep(std::time::Duration::from_secs(16));
    for fixture in [&peer, &client] {
        assert!(
            CliNmClient
                .list_wireguard_profiles()
                .unwrap()
                .iter()
                .any(|p| p.uuid == fixture.uuid && p.is_active())
        );
    }
    assert_eq!(
        neutron::nm::network_info::interface_receive_bytes(&client.name),
        Some(0)
    );
    // Use a non-local destination so the local routing table cannot bypass the
    // tunnel. The responder authenticates the packet even without a service at .3.
    let socket = std::net::UdpSocket::bind("10.253.34.2:0").unwrap();
    socket
        .send_to(b"first on-demand packet", "10.253.34.3:12345")
        .unwrap();
    for _ in 0..30 {
        if neutron::nm::network_info::interface_receive_bytes(&client.name).unwrap_or(0) > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let rx = neutron::nm::network_info::interface_receive_bytes(&client.name).unwrap();
    assert!(
        rx > 0,
        "first packet should trigger authenticated tunnel traffic"
    );
    assert!(neutron::nm::network_info::interface_receive_bytes(&peer.name).unwrap() > 0);
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn keepalive_tunnel_with_unreachable_peer_is_still_rejected() {
    require_sandbox();
    let config = sample_wireguard_config("10.253.35.2/32", "10.253.35.1")
        .replace("0.0.0.0/0, ::/0", "10.253.35.1/32")
        .replace("192.0.2.1:51820", "127.0.0.1:51835");
    let fixture = Fixture::import_config("silent", &config);
    assert!(matches!(
        CliNmClient.connect(&fixture.uuid),
        Err(neutron::error::AppError::TunnelUnhealthy(_))
    ));
    assert!(
        CliNmClient
            .list_wireguard_profiles()
            .unwrap()
            .iter()
            .any(|p| p.uuid == fixture.uuid && !p.is_active())
    );
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn networkmanager_accepts_and_stores_our_routing_pin() {
    // BUG-011. The pin was verified by hand on a live desktop; this is what
    // should have proved it. `default` made NetworkManager install no routes at
    // all, so the tunnel connected while traffic kept using the physical
    // interface.
    require_sandbox();
    let fixture = Fixture::import("routing-pin", "10.9.0.2/32", "10.9.0.1");

    let args = neutron::nm::tunnel_routing::set_args(&fixture.uuid, true);
    let status = std::process::Command::new("nmcli")
        .args(&args[..])
        .status()
        .expect("nmcli should run");
    assert!(status.success(), "NetworkManager rejected: nmcli {args:?}");

    // `1` is how NetworkManager reports the `yes` we wrote; `-1` is its
    // "default", the value that installed no routes.
    for key in [
        "wireguard.ip4-auto-default-route",
        "wireguard.ip6-auto-default-route",
    ] {
        let stored = fixture.get(key);
        assert_eq!(
            stored, "1",
            "{key} came back as {stored:?}; -1 means NetworkManager would \
             install no routes and the tunnel would carry nothing"
        );
    }
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn a_family_without_routes_is_not_barred_from_its_default_route() {
    // BUG-012, end to end. IPv4-only domains left IPv6 with
    // `never-default = yes` and no routes, black-holing every IPv6 destination
    // -- including the handshake. This asserts the invariant against what
    // NetworkManager actually stored, not just what we intended to send.
    require_sandbox();
    let fixture = Fixture::import("v4-only-split", "10.9.1.2/32", "10.9.1.1");

    let v4 = vec!["140.82.121.4/32".to_string()];
    let args = neutron::nm::split_tunnel::set_args(
        &fixture.uuid,
        SplitTunnelMode::Include,
        &v4,
        &[], // no IPv6 routes, as IPv4-only domains produce
    );
    let status = std::process::Command::new("nmcli")
        .args(&args[..])
        .status()
        .expect("nmcli should run");
    assert!(status.success(), "NetworkManager rejected: nmcli {args:?}");

    assert_eq!(
        fixture.get("ipv4.never-default"),
        "yes",
        "IPv4 has routes, so it should be split"
    );
    assert_eq!(
        fixture.get("ipv6.never-default"),
        "no",
        "IPv6 has no routes; barring it from the default route black-holes \
         every IPv6 destination"
    );
    assert_eq!(fixture.get("ipv6.routes"), "", "and no IPv6 routes are set");
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn split_tunnel_routes_survive_a_round_trip_through_networkmanager() {
    // Excluding scattered host addresses -- which is what domain-based rules
    // produce -- fragments the complement into ~100 CIDRs in one `ipv4.routes`
    // value. Nothing proved NetworkManager accepts a value that long or returns
    // it intact, and a silent truncation would leak precisely the ranges the
    // user excluded. These are the addresses from the report in BUG-012.
    require_sandbox();
    let fixture = Fixture::import("excl", "10.9.2.2/32", "10.9.2.1");

    let excluded: Vec<String> = [
        "140.82.121.4/32",
        "140.82.121.6/32",
        "140.82.114.21/32",
        "20.250.119.64/32",
        "4.231.128.59/32",
    ]
    .iter()
    .map(|cidr| cidr.to_string())
    .collect();

    let (v4, v6) = neutron::nm::split_tunnel::routes_for(SplitTunnelMode::Exclude, &excluded, &[]);
    assert!(
        v4.len() > 50,
        "precondition: scattered hosts should fragment the complement, got {}",
        v4.len()
    );

    let args =
        neutron::nm::split_tunnel::set_args(&fixture.uuid, SplitTunnelMode::Exclude, &v4, &v6);
    let status = std::process::Command::new("nmcli")
        .args(&args[..])
        .status()
        .expect("nmcli should run");
    assert!(
        status.success(),
        "NetworkManager rejected {} routes",
        v4.len()
    );

    let stored = fixture.get("ipv4.routes");
    assert_eq!(
        stored.split(',').count(),
        v4.len(),
        "NetworkManager returned a different number of routes than we sent"
    );
    for excluded_cidr in &excluded {
        assert!(
            !stored.split(", ").any(|route| route == excluded_cidr),
            "the excluded range {excluded_cidr} must not be routed into the tunnel"
        );
    }
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn the_kill_switch_arguments_are_accepted_and_stored() {
    // Proves both states apply cleanly and that disabling leaves routing intact
    // (BUG-011) while relaxing DNS priority.
    require_sandbox();
    let fixture = Fixture::import("kill-switch", "10.9.3.2/32", "10.9.3.1");

    for (enable, expected_priority) in [(true, "-1500"), (false, "0")] {
        let args = neutron::nm::kill_switch::set_args(&fixture.uuid, enable, true);
        let status = std::process::Command::new("nmcli")
            .args(&args[..])
            .status()
            .expect("nmcli should run");
        assert!(status.success(), "NetworkManager rejected: nmcli {args:?}");

        assert_eq!(fixture.get("ipv4.dns-priority"), expected_priority);
        assert_eq!(fixture.get("ipv6.dns-priority"), expected_priority);
        assert_eq!(
            fixture.get("wireguard.ip4-auto-default-route"),
            "1",
            "routing must stay pinned in both kill-switch states"
        );
    }
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn the_profile_parser_reads_back_what_networkmanager_reports() {
    // `list_wireguard_profiles` hand-parses terse `nmcli` output, including
    // backslash-escaped separators. Only a real `nmcli` can prove the parser
    // matches the format that ships -- a format change would otherwise surface
    // as profiles silently vanishing from the list.
    require_sandbox();
    let fixture = Fixture::import("parser", "10.9.4.2/32", "10.9.4.1");

    let profiles = CliNmClient
        .list_wireguard_profiles()
        .expect("profiles should list");

    let found = profiles
        .iter()
        .find(|profile| profile.uuid == fixture.uuid)
        .expect("the imported profile must be parsed out of real nmcli output");

    assert_eq!(found.name, fixture.name);
    assert!(!found.is_active(), "an imported profile starts inactive");
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn tunnel_address_and_dns_are_read_from_a_real_profile() {
    // These feed the NAT-PMP gateway derivation and the details pane; both parse
    // real `nmcli -g` output.
    require_sandbox();
    let fixture = Fixture::import("address-dns", "10.9.5.2/32", "10.9.5.1");

    assert_eq!(
        CliNmClient.tunnel_address(&fixture.uuid).as_deref(),
        Some("10.9.5.2/32")
    );
    assert_eq!(
        CliNmClient.tunnel_dns(&fixture.uuid).as_deref(),
        Some("10.9.5.1")
    );
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn tunnel_address_derives_natpmp_gateway_and_bind_address() {
    require_sandbox();
    let fixture = Fixture::import("natpmp-gw", "10.2.0.2/32", "10.2.0.1");

    let addr = CliNmClient
        .tunnel_address(&fixture.uuid)
        .expect("tunnel address should exist");
    assert_eq!(addr, "10.2.0.2/32");

    let local_ip = neutron::portforward::parse_local_address(&addr);
    assert_eq!(local_ip, Some(std::net::Ipv4Addr::new(10, 2, 0, 2)));

    let gw = neutron::portforward::gateway_for_address(&addr);
    assert_eq!(gw, Some(std::net::Ipv4Addr::new(10, 2, 0, 1)));
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn importing_disables_autoconnect_so_nothing_activates_itself() {
    // NetworkManager defaults `autoconnect` to yes and each WireGuard profile is
    // its own interface, so without this every profile activates at boot and the
    // startup selector is defeated.
    require_sandbox();
    let fixture = Fixture::import("autoconnect", "10.9.6.2/32", "10.9.6.1");

    assert_eq!(
        fixture.get("connection.autoconnect"),
        "no",
        "an imported profile must not be able to bring itself up"
    );
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn deleting_a_profile_removes_it_from_networkmanager() {
    require_sandbox();
    let fixture = Fixture::import("delete", "10.9.7.2/32", "10.9.7.1");
    let uuid = fixture.uuid.clone();

    CliNmClient
        .delete_profile(&uuid)
        .expect("delete should succeed");

    let still_present = CliNmClient
        .list_wireguard_profiles()
        .expect("profiles should list")
        .into_iter()
        .any(|profile| profile.uuid == uuid);
    assert!(!still_present, "the profile should be gone");
}
