//! Always-on "lockdown" firewall for WireGuard.
//!
//! The kill switch (see [`crate::nm`]) only protects traffic *while a tunnel is
//! active*: it makes NetworkManager route everything through the tunnel so a
//! failing tunnel drops packets instead of leaking. It does nothing while no
//! VPN is connected.
//!
//! Lockdown closes that gap. It installs an always-on `firewalld` ruleset that
//! blocks **all** traffic except:
//!
//! * loopback and already-established connections,
//! * DNS (so endpoint hostnames can resolve),
//! * the WireGuard tunnel interfaces (decrypted traffic once connected), and
//! * the WireGuard peer endpoints (the encrypted handshake, so the VPN can
//!   still connect from a locked-down system).
//!
//! Everything else is rejected, even before any VPN is connected and across
//! reboots (the rules are made `--permanent`). Because this touches the system
//! firewall it requires privileges, so the commands run through `pkexec`; the
//! `disable` path always works to lift the block, so the user can never be
//! permanently locked out.
//!
//! Privileges note: each rule is a separate `firewall-cmd` call, but polkit's
//! default `auth_admin_keep` caching means the user is prompted for a password
//! at most once per enable/disable, not once per rule.

use std::net::IpAddr;
use std::process::Stdio;

use crate::error::{AppError, AppResult};
use crate::nm::{Endpoint, WireguardTunnel};

/// Host firewall command. Run through `pkexec` for the privilege escalation.
const FIREWALL_CMD: &str = "firewall-cmd";

/// Comment tagged onto the final reject rule so the lockdown ruleset is
/// recognizable among any other firewall rules.
const LOCKDOWN_MARKER: &str = "zento-lockdown";

/// Applies and removes the always-on lockdown firewall.
///
/// Kept separate from [`crate::nm::NmClient`] because it controls the system
/// firewall, not NetworkManager. The same concrete client implements both so
/// the application only threads a single value around.
pub trait FirewallClient {
    /// Install the lockdown ruleset, allowing the supplied tunnels' interfaces
    /// and endpoints through. Replaces any previous lockdown rules.
    fn enable_lockdown(&self, tunnels: &[WireguardTunnel]) -> AppResult<()>;
    /// Remove the lockdown ruleset, restoring normal connectivity. Idempotent:
    /// safe to call when lockdown is not currently active.
    fn disable_lockdown(&self) -> AppResult<()>;
}

impl FirewallClient for crate::nm::CliNmClient {
    fn enable_lockdown(&self, tunnels: &[WireguardTunnel]) -> AppResult<()> {
        // Clear any leftover lockdown rules first so re-enabling is idempotent
        // and cannot fail with ALREADY_ENABLED. Best-effort: a real privilege
        // failure surfaces on the strict add calls below.
        for batch in lockdown_cleanup_batches() {
            let _ = run_firewall_cmd(&batch);
        }
        for batch in lockdown_enable_batches(tunnels) {
            run_firewall_cmd(&batch)?;
        }
        Ok(())
    }

    fn disable_lockdown(&self) -> AppResult<()> {
        for batch in lockdown_disable_batches() {
            run_firewall_cmd(&batch)?;
        }
        Ok(())
    }
}

/// Run `pkexec firewall-cmd <args>`, transparently routing through
/// `flatpak-spawn --host` when sandboxed (see [`crate::nm::host_command`]).
///
/// No timeout is imposed: `pkexec` is interactive (it may wait on a password
/// prompt), so a deadline would race the user. The GUI runs this off the main
/// thread, and the CLI is a foreground command, so a stuck call cannot freeze
/// the UI.
fn run_firewall_cmd(args: &[String]) -> AppResult<()> {
    let output = crate::nm::host_command("pkexec")
        .arg(FIREWALL_CMD)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| AppError::Firewall(error.to_string()))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let code = output
        .status
        .code()
        .map(|code| code.to_string())
        .unwrap_or_else(|| "terminated by signal".to_string());
    Err(AppError::Firewall(if stderr.is_empty() {
        format!("pkexec {FIREWALL_CMD} {args:?} failed (exit {code})")
    } else {
        format!("{stderr} (exit {code})")
    }))
}

/// All `firewall-cmd` batches that install the lockdown ruleset: the IPv4 and
/// IPv6 allow/reject rules followed by a `--reload` that makes the permanent
/// rules live.
fn lockdown_enable_batches(tunnels: &[WireguardTunnel]) -> Vec<Vec<String>> {
    let mut batches = lockdown_family_batches("ipv4", tunnels);
    batches.extend(lockdown_family_batches("ipv6", tunnels));
    batches.push(reload_batch());
    batches
}

/// All `firewall-cmd` batches that remove the lockdown ruleset and reload.
fn lockdown_disable_batches() -> Vec<Vec<String>> {
    let mut batches = lockdown_cleanup_batches();
    batches.push(reload_batch());
    batches
}

/// The `--remove-rules` batches (no reload) used both to tear lockdown down and
/// to clear stale rules before a fresh enable.
fn lockdown_cleanup_batches() -> Vec<Vec<String>> {
    vec![remove_rules_batch("ipv4"), remove_rules_batch("ipv6")]
}

/// The allow + reject rules for a single address family (`ipv4`/`ipv6`).
fn lockdown_family_batches(family: &str, tunnels: &[WireguardTunnel]) -> Vec<Vec<String>> {
    // Priorities order the rules within the chain: accepts (0/1) before the
    // catch-all reject (10).
    let mut batches = vec![
        add_rule(family, 0, &["-o", "lo", "-j", "ACCEPT"]),
        add_rule(
            family,
            0,
            &[
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
        ),
        add_rule(family, 1, &["-p", "udp", "--dport", "53", "-j", "ACCEPT"]),
        add_rule(family, 1, &["-p", "tcp", "--dport", "53", "-j", "ACCEPT"]),
    ];

    for tunnel in tunnels {
        if let Some(interface) = &tunnel.interface {
            batches.push(add_rule(family, 1, &["-o", interface, "-j", "ACCEPT"]));
        }
        for endpoint in &tunnel.endpoints {
            if let Some(batch) = endpoint_rule(family, endpoint) {
                batches.push(batch);
            }
        }
    }

    batches.push(add_rule(
        family,
        10,
        &[
            "-m",
            "comment",
            "--comment",
            LOCKDOWN_MARKER,
            "-j",
            "REJECT",
        ],
    ));
    batches
}

/// The handshake allow-rule for one peer endpoint, or `None` when the endpoint
/// is an IP literal that belongs to the *other* address family.
///
/// IP-literal endpoints are pinned to their exact address in the matching
/// family. Hostname endpoints can resolve to either family, so they are allowed
/// by destination port only (in both families); DNS is already allowed above so
/// the name can resolve.
fn endpoint_rule(family: &str, endpoint: &Endpoint) -> Option<Vec<String>> {
    let port = endpoint.port.to_string();
    match endpoint.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) if family == "ipv4" => Some(add_rule(
            family,
            1,
            &[
                "-p",
                "udp",
                "-d",
                &endpoint.host,
                "--dport",
                &port,
                "-j",
                "ACCEPT",
            ],
        )),
        Ok(IpAddr::V6(_)) if family == "ipv6" => Some(add_rule(
            family,
            1,
            &[
                "-p",
                "udp",
                "-d",
                &endpoint.host,
                "--dport",
                &port,
                "-j",
                "ACCEPT",
            ],
        )),
        // IP literal for the other family: nothing to add here.
        Ok(_) => None,
        // Hostname: allow the handshake port in every family.
        Err(_) => Some(add_rule(
            family,
            1,
            &["-p", "udp", "--dport", &port, "-j", "ACCEPT"],
        )),
    }
}

/// Build a permanent `--direct --add-rule <family> filter OUTPUT <priority>
/// <rule...>` argument batch.
fn add_rule(family: &str, priority: u8, rule: &[&str]) -> Vec<String> {
    let mut batch = vec![
        "--permanent".to_string(),
        "--direct".to_string(),
        "--add-rule".to_string(),
        family.to_string(),
        "filter".to_string(),
        "OUTPUT".to_string(),
        priority.to_string(),
    ];
    batch.extend(rule.iter().map(|arg| arg.to_string()));
    batch
}

/// Build the permanent `--direct --remove-rules <family> filter OUTPUT` batch
/// that clears every lockdown rule from a family's OUTPUT chain.
fn remove_rules_batch(family: &str) -> Vec<String> {
    [
        "--permanent",
        "--direct",
        "--remove-rules",
        family,
        "filter",
        "OUTPUT",
    ]
    .iter()
    .map(|arg| arg.to_string())
    .collect()
}

fn reload_batch() -> Vec<String> {
    vec!["--reload".to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunnel(interface: &str, endpoints: &[(&str, u16)]) -> WireguardTunnel {
        WireguardTunnel {
            interface: Some(interface.to_string()),
            endpoints: endpoints
                .iter()
                .map(|(host, port)| Endpoint {
                    host: host.to_string(),
                    port: *port,
                })
                .collect(),
        }
    }

    /// True when some batch is exactly `[..parts]` (after the priority slot,
    /// any order-independent rule fragment).
    fn has_rule(batches: &[Vec<String>], fragment: &[&str]) -> bool {
        batches.iter().any(|batch| {
            fragment
                .windows(2)
                .all(|pair| contains_pair(batch, pair[0], pair[1]))
        })
    }

    fn contains_pair(batch: &[String], a: &str, b: &str) -> bool {
        batch.windows(2).any(|pair| pair[0] == a && pair[1] == b)
    }

    #[test]
    fn enable_batches_cover_both_families_and_reload_last() {
        let batches = lockdown_enable_batches(&[]);

        assert!(
            batches
                .iter()
                .any(|batch| batch.contains(&"ipv4".to_string()))
        );
        assert!(
            batches
                .iter()
                .any(|batch| batch.contains(&"ipv6".to_string()))
        );
        assert_eq!(batches.last().expect("non-empty"), &reload_batch());
    }

    #[test]
    fn enable_batches_allow_loopback_dns_and_reject_marker() {
        let batches = lockdown_enable_batches(&[]);

        assert!(has_rule(&batches, &["-o", "lo", "-j", "ACCEPT"]));
        assert!(has_rule(&batches, &["--ctstate", "ESTABLISHED,RELATED"]));
        assert!(has_rule(&batches, &["--dport", "53"]));
        // The catch-all reject carries the recognizable marker.
        assert!(has_rule(&batches, &["--comment", LOCKDOWN_MARKER]));
        assert!(
            batches
                .iter()
                .any(|batch| batch.contains(&"REJECT".to_string()))
        );
    }

    #[test]
    fn enable_batches_allow_tunnel_interface() {
        let batches = lockdown_enable_batches(&[tunnel("wg0", &[])]);

        assert!(has_rule(&batches, &["-o", "wg0", "-j", "ACCEPT"]));
    }

    #[test]
    fn ipv4_endpoint_is_pinned_only_in_ipv4_family() {
        let ipv4 = lockdown_family_batches("ipv4", &[tunnel("wg0", &[("1.2.3.4", 51820)])]);
        let ipv6 = lockdown_family_batches("ipv6", &[tunnel("wg0", &[("1.2.3.4", 51820)])]);

        assert!(has_rule(&ipv4, &["-d", "1.2.3.4", "--dport", "51820"]));
        // The IPv4 literal must not appear in the IPv6 ruleset.
        assert!(
            !ipv6
                .iter()
                .any(|batch| batch.contains(&"1.2.3.4".to_string()))
        );
    }

    #[test]
    fn ipv6_endpoint_is_pinned_only_in_ipv6_family() {
        let ipv4 = lockdown_family_batches("ipv4", &[tunnel("wg0", &[("2001:db8::1", 51820)])]);
        let ipv6 = lockdown_family_batches("ipv6", &[tunnel("wg0", &[("2001:db8::1", 51820)])]);

        assert!(has_rule(&ipv6, &["-d", "2001:db8::1", "--dport", "51820"]));
        assert!(
            !ipv4
                .iter()
                .any(|batch| batch.contains(&"2001:db8::1".to_string()))
        );
    }

    #[test]
    fn hostname_endpoint_allows_port_in_both_families() {
        let ipv4 = lockdown_family_batches("ipv4", &[tunnel("wg0", &[("vpn.example.com", 1194)])]);
        let ipv6 = lockdown_family_batches("ipv6", &[tunnel("wg0", &[("vpn.example.com", 1194)])]);

        // Port-only allow (no `-d`) so the resolved address can be either family.
        for family in [&ipv4, &ipv6] {
            assert!(has_rule(family, &["-p", "udp", "--dport", "1194"]));
            assert!(
                !family
                    .iter()
                    .any(|batch| batch.contains(&"vpn.example.com".to_string()))
            );
        }
    }

    #[test]
    fn disable_batches_remove_both_families_then_reload() {
        let batches = lockdown_disable_batches();

        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0], remove_rules_batch("ipv4"));
        assert_eq!(batches[1], remove_rules_batch("ipv6"));
        assert_eq!(batches[2], reload_batch());
    }

    #[test]
    fn every_rule_batch_is_permanent() {
        // Permanence (across reboots) is part of the lockdown guarantee, so
        // every add/remove batch must carry `--permanent` (only `--reload`
        // does not).
        for batch in lockdown_enable_batches(&[tunnel("wg0", &[("1.2.3.4", 51820)])]) {
            assert!(
                batch == reload_batch() || batch.contains(&"--permanent".to_string()),
                "non-reload batch must be permanent: {batch:?}"
            );
        }
    }
}
