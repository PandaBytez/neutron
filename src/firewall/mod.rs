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
//! * private/link-local networks (so LAN devices — router, printer, NAS, other
//!   local hosts — stay reachable; these are not internet-routable, so allowing
//!   them does not weaken the "no VPN, no internet" guarantee),
//! * DNS (so endpoint hostnames can resolve),
//! * the WireGuard tunnel interfaces (decrypted traffic once connected), and
//! * the WireGuard peer endpoints (the encrypted handshake, so the VPN can
//!   still connect from a locked-down system).
//!
//! Everything else is rejected, even before any VPN is connected and across
//! reboots (the rules are made `--permanent`). Changing the system firewall
//! requires privileges, so the rule changes run through `pkexec`; the `disable`
//! path always works to lift the block, so the user can never be permanently
//! locked out.
//!
//! Scope: lockdown only ever touches its *own* rules. Every rule it installs is
//! tagged with a marker comment, and teardown enumerates the chain and removes
//! exactly those tagged rules one by one — so the user's (or other software's)
//! own `firewalld` direct rules are never disturbed. Teardown never falls back
//! to a chain-wide clear: if it cannot remove one of its own rules it reports an
//! error rather than wipe rules it did not create.
//!
//! Privileges note: *reading* the ruleset (`--get-rules`) does not require root,
//! so those queries run unprivileged and never prompt. All rule *changes* for a
//! single enable/disable are collected and executed in one `pkexec` invocation
//! (a small `/bin/sh` script that runs each `firewall-cmd` in turn), so the user
//! authenticates exactly once per action rather than once per rule. Profile-
//! derived values (interface names, endpoint hosts) are shell-quoted into that
//! script so they cannot break out of their argument position.

use std::net::IpAddr;
use std::process::Stdio;

use crate::error::{AppError, AppResult};
use crate::nm::{Endpoint, WireguardTunnel};

/// Host firewall command. Run through `pkexec` for the privilege escalation.
const FIREWALL_CMD: &str = "firewall-cmd";

/// Comment tagged onto *every* lockdown rule so our ruleset is recognizable
/// among any other firewall rules and can be removed surgically at teardown
/// without disturbing the user's own direct rules.
const LOCKDOWN_MARKER: &str = "neutron-lockdown";

/// The iptables `comment` match that stamps [`LOCKDOWN_MARKER`] onto a rule.
const MARKER_ARGS: [&str; 4] = ["-m", "comment", "--comment", LOCKDOWN_MARKER];

/// Address families lockdown manages, each with its own OUTPUT chain.
const FAMILIES: [&str; 2] = ["ipv4", "ipv6"];

/// IPv4 destination ranges kept reachable under lockdown so the local network
/// keeps working: RFC 1918 private space, link-local, multicast (mDNS/SSDP) and
/// the limited broadcast address (DHCP). None are internet-routable, so allowing
/// them does not let traffic leak past a down VPN.
const LOCAL_NETWORKS_V4: [&str; 6] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",     // link-local
    "224.0.0.0/4",        // multicast (mDNS, SSDP)
    "255.255.255.255/32", // limited broadcast (DHCP)
];

/// IPv6 counterpart of [`LOCAL_NETWORKS_V4`]: link-local, unique-local (ULA) and
/// multicast destinations that must stay reachable for local networking.
const LOCAL_NETWORKS_V6: [&str; 3] = [
    "fe80::/10", // link-local
    "fc00::/7",  // unique local addresses
    "ff00::/8",  // multicast
];

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
        // Everything that mutates the firewall runs in ONE privileged batch so
        // the user is prompted for a password at most once. Reads are
        // unprivileged and never prompt.
        //
        // The batch first clears any leftover Neutron rules (so re-enabling is
        // idempotent and cannot fail with ALREADY_ENABLED), then installs the
        // new ruleset and reloads.
        let mut batches = marked_removal_batches()?;
        batches.extend(lockdown_enable_batches(tunnels));
        run_privileged_batches(&batches)
    }

    fn disable_lockdown(&self) -> AppResult<()> {
        // Collect surgical removals from an unprivileged read of each family,
        // then remove them and reload in a single privileged batch (one prompt).
        let mut batches = marked_removal_batches()?;
        batches.push(reload_batch());
        run_privileged_batches(&batches)?;

        // Strictly scoped teardown: only our own tagged rules are ever removed,
        // never the user's (or other software's) direct rules. If one of ours
        // somehow survived surgical removal, surface an error rather than fall
        // back to a chain-wide wipe that would clobber foreign rules we never
        // created. These verification reads are unprivileged, so they add no
        // extra prompt.
        for family in FAMILIES {
            if family_has_marked_rule(family)? {
                return Err(AppError::Firewall(format!(
                    "lockdown could not remove all of its own rules from the {family} \
                     OUTPUT chain; left foreign rules untouched"
                )));
            }
        }
        Ok(())
    }
}

/// Read `family`'s permanent direct OUTPUT rules with an *unprivileged*
/// `firewall-cmd --get-rules`, returning its captured stdout.
///
/// Querying the ruleset does not require root, so this deliberately does **not**
/// go through `pkexec`: it never triggers a password prompt. That is what lets
/// enable/disable read the current rules freely and confine privilege to the
/// single batched write below (see [`crate::process::host_command`]).
fn read_marked_rules(family: &str) -> AppResult<String> {
    let output = crate::process::host_command(FIREWALL_CMD)
        .args(get_rules_batch(family))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| AppError::Firewall(error.to_string()))?;

    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(AppError::Firewall(if stderr.is_empty() {
        format!("{FIREWALL_CMD} --get-rules ({family}) failed")
    } else {
        stderr
    }))
}

/// Execute every `firewall-cmd` batch in a *single* `pkexec` invocation, so the
/// user authenticates at most once regardless of how many rules change.
///
/// The batches are rendered into one `/bin/sh` script (see
/// [`build_firewall_script`]) which `pkexec` runs. This is the only privileged
/// call in the module. A no-op when there is nothing to do.
///
/// `SHELL` is forced to `/bin/sh` because `pkexec` refuses to run (exit 127,
/// "The value for the SHELL variable was not found in the /etc/shells file")
/// when the caller's `SHELL` is not whitelisted in `/etc/shells` — which is the
/// case for shells installed outside the system, e.g. a Homebrew `zsh`.
/// `/bin/sh` is always present and listed, so this makes the escalation work
/// regardless of the user's login shell.
///
/// No timeout is imposed: `pkexec` is interactive (it may wait on a password
/// prompt), so a deadline would race the user. The GUI runs this off the main
/// thread, and the CLI is a foreground command, so a stuck call cannot freeze
/// the UI.
fn run_privileged_batches(batches: &[Vec<String>]) -> AppResult<()> {
    if batches.is_empty() {
        return Ok(());
    }

    let script = build_firewall_script(batches);
    let output = crate::process::host_command_with_env("pkexec", &[("SHELL", "/bin/sh")])
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| AppError::Firewall(error.to_string()))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = format!("pkexec {FIREWALL_CMD} batch failed");
    Err(AppError::Firewall(crate::process::format_command_error(
        &prefix,
        output.status,
        &stderr,
    )))
}

/// Render `firewall-cmd` argument batches into a single `/bin/sh` script that
/// runs each in order and aborts on the first failure (`set -e`), so a partial
/// failure cannot silently leave a half-applied ruleset.
///
/// Every argument is shell-quoted (see [`shell_quote`]); values taken from
/// WireGuard profiles (interface names, endpoint hosts) therefore cannot break
/// out of their argument position. This is what makes batching all privileged
/// commands into one `sh -c` safe against command injection.
fn build_firewall_script(batches: &[Vec<String>]) -> String {
    let mut script = String::from("set -e\n");
    for batch in batches {
        script.push_str(FIREWALL_CMD);
        for arg in batch {
            script.push(' ');
            script.push_str(&shell_quote(arg));
        }
        script.push('\n');
    }
    script
}

/// POSIX-safe single-quote escaping: wrap `arg` in single quotes, rewriting any
/// embedded single quote as `'\''`. The result is one shell word whose literal
/// value is exactly `arg`, immune to word-splitting and to every shell
/// metacharacter (`;`, `$`, `` ` ``, newline, …). This is the mechanism that
/// lets [`build_firewall_script`] safely embed profile-derived strings.
fn shell_quote(arg: &str) -> String {
    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

/// All `firewall-cmd` batches that install the lockdown ruleset: the IPv4 and
/// IPv6 allow/reject rules followed by a `--reload` that makes the permanent
/// rules live.
fn lockdown_enable_batches(tunnels: &[WireguardTunnel]) -> Vec<Vec<String>> {
    let mut batches = Vec::new();
    for family in FAMILIES {
        batches.extend(lockdown_family_batches(family, tunnels));
    }
    batches.push(reload_batch());
    batches
}

/// Whether `family`'s OUTPUT chain still contains a Neutron-tagged rule. Used as a
/// teardown safety check so we never leave the user locked out. The read is
/// unprivileged, so this check costs no password prompt.
fn family_has_marked_rule(family: &str) -> AppResult<bool> {
    let listing = read_marked_rules(family)?;
    Ok(listing.lines().any(line_is_marked))
}

/// Whether a `--get-rules` output line is one of ours (carries the marker).
fn line_is_marked(line: &str) -> bool {
    line.split_whitespace()
        .any(|token| token == LOCKDOWN_MARKER)
}

/// Direct rule argument prefix for permanent OUTPUT chain operations.
fn direct_args(verb: &str, family: &str) -> Vec<String> {
    ["--permanent", "--direct", verb, family, "filter", "OUTPUT"]
        .iter()
        .map(|a| a.to_string())
        .collect()
}

/// Removal batches for every Neutron-tagged rule across all families.
fn marked_removal_batches() -> AppResult<Vec<Vec<String>>> {
    let mut batches = Vec::new();
    for family in FAMILIES {
        batches.extend(parse_marked_removals(family, &read_marked_rules(family)?));
    }
    Ok(batches)
}

/// Parse `--get-rules` output (a newline-separated list of `<priority> <args>`)
/// into a `--remove-rule` batch for each Neutron-tagged rule. Untagged (foreign)
/// rules are skipped so user-defined direct rules are preserved.
fn parse_marked_removals(family: &str, listing: &str) -> Vec<Vec<String>> {
    listing
        .lines()
        .filter(|line| line_is_marked(line))
        .filter_map(|line| {
            let mut tokens = line.split_whitespace();
            // The first field is the rule priority; the rest are the iptables
            // args, fed back verbatim so `--remove-rule` matches exactly.
            let priority = tokens.next()?;
            let mut batch = direct_args("--remove-rule", family);
            batch.push(priority.to_string());
            batch.extend(tokens.map(|token| token.to_string()));
            Some(batch)
        })
        .collect()
}

/// The allow + reject rules for a single address family (`ipv4`/`ipv6`).
fn lockdown_family_batches(family: &str, tunnels: &[WireguardTunnel]) -> Vec<Vec<String>> {
    // Priorities order the rules within the chain: accepts (0/1) before the
    // catch-all reject (10).
    let mut batches = vec![add_rule(family, 0, &["-o", "lo", "-j", "ACCEPT"])];

    // When disconnected (no tunnels active), allow broad DNS so peer endpoints
    // can resolve before connecting. When a tunnel is active, DNS travels through
    // the tunnel interface (-o <iface> -j ACCEPT) without leaking outside.
    if tunnels.is_empty() {
        batches.push(add_rule(
            family,
            1,
            &["-p", "udp", "--dport", "53", "-j", "ACCEPT"],
        ));
        batches.push(add_rule(
            family,
            1,
            &["-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
        ));
    }

    // Keep the local network reachable (LAN devices, DHCP, mDNS).
    batches.extend(local_network_batches(family));

    for tunnel in tunnels {
        if let Some(interface) = &tunnel.interface {
            batches.push(add_rule(family, 1, &["-o", interface, "-j", "ACCEPT"]));
        }
        for endpoint in &tunnel.endpoints {
            batches.extend(endpoint_rules(family, endpoint));
        }
    }

    // Catch-all reject. The marker (added to every rule by `add_rule`) is what
    // makes this and the allow rules above identifiable for surgical teardown.
    batches.push(add_rule(family, 10, &["-j", "REJECT"]));
    batches
}

/// Allow-rules that keep `family`'s private/link-local destinations reachable
/// (see [`LOCAL_NETWORKS_V4`]/[`LOCAL_NETWORKS_V6`]). Each range is pinned to its
/// own address family so an IPv4 range never lands in the IPv6 chain.
fn local_network_batches(family: &str) -> Vec<Vec<String>> {
    let networks: &[&str] = if family == "ipv4" {
        &LOCAL_NETWORKS_V4
    } else {
        &LOCAL_NETWORKS_V6
    };
    networks
        .iter()
        .map(|network| add_rule(family, 1, &["-d", network, "-j", "ACCEPT"]))
        .collect()
}

/// The handshake allow-rules for one peer endpoint.
///
/// IP-literal endpoints are pinned to their exact address in the matching
/// family. Hostname endpoints are resolved to IP addresses and pinned to
/// those addresses in the matching family so destination ports are not open
/// broadly.
fn endpoint_rules(family: &str, endpoint: &Endpoint) -> Vec<Vec<String>> {
    let port = endpoint.port.to_string();
    if let Ok(ip) = endpoint.host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(_) if family == "ipv4" => {
                let rule = [
                    "-p",
                    "udp",
                    "-d",
                    endpoint.host.as_str(),
                    "--dport",
                    port.as_str(),
                    "-j",
                    "ACCEPT",
                ];
                return vec![add_rule(family, 1, &rule)];
            }
            IpAddr::V6(_) if family == "ipv6" => {
                let rule = [
                    "-p",
                    "udp",
                    "-d",
                    endpoint.host.as_str(),
                    "--dport",
                    port.as_str(),
                    "-j",
                    "ACCEPT",
                ];
                return vec![add_rule(family, 1, &rule)];
            }
            _ => return Vec::new(),
        }
    }

    let ips = crate::nm::split_tunnel::resolve_domain_ips(&endpoint.host);
    let mut rules = Vec::new();
    for ip in ips {
        match ip {
            IpAddr::V4(v4) if family == "ipv4" => {
                let v4_str = v4.to_string();
                let rule = [
                    "-p",
                    "udp",
                    "-d",
                    v4_str.as_str(),
                    "--dport",
                    port.as_str(),
                    "-j",
                    "ACCEPT",
                ];
                rules.push(add_rule(family, 1, &rule));
            }
            IpAddr::V6(v6) if family == "ipv6" => {
                let v6_str = v6.to_string();
                let rule = [
                    "-p",
                    "udp",
                    "-d",
                    v6_str.as_str(),
                    "--dport",
                    port.as_str(),
                    "-j",
                    "ACCEPT",
                ];
                rules.push(add_rule(family, 1, &rule));
            }
            _ => {}
        }
    }
    rules
}

/// Build a permanent `--direct --add-rule <family> filter OUTPUT <priority>
/// <rule...>` argument batch, tagging the rule with [`LOCKDOWN_MARKER`].
///
/// The marker is inserted right before the trailing `-j <target>` (iptables
/// requires matches to precede the jump) so every rule we install is
/// identifiable and can be removed surgically at teardown without disturbing
/// foreign direct rules. Each `rule` therefore must end with `-j <target>`.
fn add_rule(family: &str, priority: u8, rule: &[&str]) -> Vec<String> {
    let mut batch = direct_args("--add-rule", family);
    batch.push(priority.to_string());
    let jump_at = rule.len().saturating_sub(2);
    batch.extend(rule[..jump_at].iter().map(|arg| arg.to_string()));
    batch.extend(MARKER_ARGS.iter().map(|arg| arg.to_string()));
    batch.extend(rule[jump_at..].iter().map(|arg| arg.to_string()));
    batch
}

/// The permanent `--direct --get-rules <family> filter OUTPUT` query batch,
/// whose output drives [`parse_marked_removals`]. This is the only chain-wide
/// `--direct` action lockdown issues: it reads the chain so teardown can target
/// our own rules individually; it never clears the chain wholesale.
fn get_rules_batch(family: &str) -> Vec<String> {
    direct_args("--get-rules", family)
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

    /// True when some batch contains every token in `fragment` (order- and
    /// adjacency-independent). The marker `add_rule` injects interleaves with
    /// the rule body, so we match by token presence rather than adjacency.
    fn has_rule(batches: &[Vec<String>], fragment: &[&str]) -> bool {
        batches.iter().any(|batch| {
            fragment
                .iter()
                .all(|token| batch.iter().any(|arg| arg == token))
        })
    }

    /// Render an `--add-rule … <priority> <args>` batch exactly the way
    /// `firewall-cmd --direct --get-rules` prints it back: `<priority> <args>`,
    /// dropping the leading `--permanent --direct --add-rule <family> filter
    /// OUTPUT` (6 tokens). Lets tests feed what we *installed* straight back
    /// into the teardown parser to prove the round-trip.
    fn as_get_rules_line(add_batch: &[String]) -> String {
        let prefix_len = direct_args("--add-rule", "ipv4").len();
        add_batch[prefix_len..].join(" ")
    }

    /// The removal batch that must result from tearing down `add_batch`: the
    /// identical argument vector with `--add-rule` swapped for `--remove-rule`.
    fn expected_removal(add_batch: &[String]) -> Vec<String> {
        add_batch
            .iter()
            .map(|token| {
                if token == "--add-rule" {
                    "--remove-rule".to_string()
                } else {
                    token.clone()
                }
            })
            .collect()
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
    fn hostname_endpoint_pins_resolved_addresses() {
        let ipv4 = lockdown_family_batches("ipv4", &[tunnel("wg0", &[("localhost", 1194)])]);
        let ipv6 = lockdown_family_batches("ipv6", &[tunnel("wg0", &[("localhost", 1194)])]);

        assert!(has_rule(&ipv4, &["-d", "127.0.0.1", "--dport", "1194"]));
        assert!(has_rule(&ipv6, &["-d", "::1", "--dport", "1194"]));
    }

    #[test]
    fn local_networks_are_allowed_per_family() {
        // LAN destinations (router, printer, NAS, DHCP, mDNS) must stay
        // reachable under lockdown so a kill switch never breaks the local
        // network, even with no tunnels configured.
        let ipv4 = lockdown_family_batches("ipv4", &[]);
        let ipv6 = lockdown_family_batches("ipv6", &[]);

        for network in LOCAL_NETWORKS_V4 {
            assert!(
                has_rule(&ipv4, &["-d", network, "-j", "ACCEPT"]),
                "missing IPv4 local-network allow for {network}"
            );
        }
        for network in LOCAL_NETWORKS_V6 {
            assert!(
                has_rule(&ipv6, &["-d", network, "-j", "ACCEPT"]),
                "missing IPv6 local-network allow for {network}"
            );
        }
    }

    #[test]
    fn local_networks_are_pinned_to_their_own_family() {
        // An IPv4 range must never land in the IPv6 chain (and vice versa) or
        // firewalld would reject the rule for the wrong address family.
        let ipv4 = lockdown_family_batches("ipv4", &[]);
        let ipv6 = lockdown_family_batches("ipv6", &[]);

        for network in LOCAL_NETWORKS_V4 {
            let in_ipv6 = ipv6
                .iter()
                .any(|batch| batch.contains(&network.to_string()));
            assert!(!in_ipv6, "IPv4 range {network} leaked into the IPv6 chain");
        }
        for network in LOCAL_NETWORKS_V6 {
            let in_ipv4 = ipv4
                .iter()
                .any(|batch| batch.contains(&network.to_string()));
            assert!(!in_ipv4, "IPv6 range {network} leaked into the IPv4 chain");
        }
    }

    #[test]
    fn every_lockdown_rule_is_tagged_with_the_marker() {
        // Surgical teardown depends on *every* rule carrying the marker, not
        // just the reject, so the whole ruleset can be removed by tag.
        for batch in lockdown_enable_batches(&[tunnel("wg0", &[("1.2.3.4", 51820)])]) {
            assert!(
                batch == reload_batch() || batch.contains(&LOCKDOWN_MARKER.to_string()),
                "every non-reload batch must be tagged: {batch:?}"
            );
        }
    }

    #[test]
    fn parse_marked_removals_skips_foreign_rules() {
        // A `--get-rules` listing mixing a user's own rule with two of ours.
        let listing = "\
0 -o eth0 -j DROP
0 -o lo -m comment --comment neutron-lockdown -j ACCEPT
10 -m comment --comment neutron-lockdown -j REJECT
";
        let removals = parse_marked_removals("ipv4", listing);

        // Only the two tagged rules are removed; the foreign `eth0` rule is left.
        assert_eq!(removals.len(), 2);
        assert!(
            removals
                .iter()
                .all(|batch| batch.contains(&"--remove-rule".to_string()))
        );
        assert!(
            !removals
                .iter()
                .any(|batch| batch.contains(&"eth0".to_string()))
        );
    }

    #[test]
    fn parse_marked_removals_round_trips_priority_and_args() {
        // The removal must mirror `--get-rules` output verbatim: priority slot
        // followed by the exact iptables args, so `--remove-rule` matches.
        let listing = "10 -m comment --comment neutron-lockdown -j REJECT\n";

        let removals = parse_marked_removals("ipv6", listing);

        assert_eq!(
            removals,
            vec![vec![
                "--permanent".to_string(),
                "--direct".to_string(),
                "--remove-rule".to_string(),
                "ipv6".to_string(),
                "filter".to_string(),
                "OUTPUT".to_string(),
                "10".to_string(),
                "-m".to_string(),
                "comment".to_string(),
                "--comment".to_string(),
                LOCKDOWN_MARKER.to_string(),
                "-j".to_string(),
                "REJECT".to_string(),
            ]]
        );
    }

    #[test]
    fn parse_marked_removals_ignores_blank_lines() {
        assert!(parse_marked_removals("ipv4", "\n   \n").is_empty());
    }

    #[test]
    fn get_rules_batch_is_permanent_and_scoped_to_output() {
        assert_eq!(
            get_rules_batch("ipv4"),
            vec![
                "--permanent".to_string(),
                "--direct".to_string(),
                "--get-rules".to_string(),
                "ipv4".to_string(),
                "filter".to_string(),
                "OUTPUT".to_string(),
            ]
        );
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

    #[test]
    fn line_is_marked_requires_an_exact_marker_token() {
        // Ours: carries the marker as a standalone token.
        assert!(line_is_marked(
            "0 -o lo -m comment --comment neutron-lockdown -j ACCEPT"
        ));
        // Foreign with no marker at all.
        assert!(!line_is_marked("0 -o eth0 -j DROP"));
        // A comment that only *contains* the marker as a substring is not ours;
        // matching whole tokens stops us from removing a foreign look-alike.
        assert!(!line_is_marked(
            "0 --comment neutron-lockdown-custom -j DROP"
        ));
        assert!(!line_is_marked("0 --comment not-neutron-lockdown -j DROP"));
    }

    #[test]
    fn parse_marked_removals_ignores_a_foreign_rule_with_its_own_comment() {
        // A foreign rule that uses the comment match with a *different* comment
        // must be left alone: teardown keys off our exact marker, not the mere
        // presence of a `--comment`.
        let listing = "\
0 -o lo -m comment --comment other-app -j ACCEPT
10 -m comment --comment neutron-lockdown -j REJECT
";
        let removals = parse_marked_removals("ipv4", listing);

        assert_eq!(removals.len(), 1);
        assert!(
            !removals
                .iter()
                .any(|batch| batch.contains(&"other-app".to_string()))
        );
        assert!(removals[0].contains(&LOCKDOWN_MARKER.to_string()));
    }

    #[test]
    fn teardown_removals_are_individually_targeted_never_chain_wide() {
        // Regression guard: every teardown batch removes one specific rule
        // (`--remove-rule`), never the chain-wide `--remove-rules` that would
        // drop foreign rules along with ours.
        let listing = "\
0 -o lo -m comment --comment neutron-lockdown -j ACCEPT
10 -m comment --comment neutron-lockdown -j REJECT
";
        let removals = parse_marked_removals("ipv4", listing);

        assert!(!removals.is_empty());
        for batch in &removals {
            assert!(batch.contains(&"--remove-rule".to_string()));
            assert!(!batch.contains(&"--remove-rules".to_string()));
        }
    }

    #[test]
    fn every_installed_rule_round_trips_to_its_own_removal() {
        // The core safety property: each rule we install can be torn down by
        // tag, and the teardown targets *exactly* that rule (same family,
        // priority and args). We render every installed rule the way
        // `--get-rules` echoes it back, parse it, and require the result to be
        // precisely that one rule's targeted removal — proving teardown only
        // ever touches what we added.
        let tunnels = [tunnel(
            "wg0",
            &[("1.2.3.4", 51820), ("vpn.example.com", 1194)],
        )];
        for add in lockdown_enable_batches(&tunnels) {
            if add == reload_batch() {
                continue;
            }
            let family = &add[3];
            let removals = parse_marked_removals(family, &as_get_rules_line(&add));
            assert_eq!(
                removals,
                vec![expected_removal(&add)],
                "installed rule must tear down to exactly its own removal: {add:?}"
            );
        }
    }

    #[test]
    fn shell_quote_wraps_plain_values_in_single_quotes() {
        assert_eq!(shell_quote("wg0"), "'wg0'");
        assert_eq!(shell_quote("--add-rule"), "'--add-rule'");
        assert_eq!(shell_quote("1.2.3.4"), "'1.2.3.4'");
    }

    #[test]
    fn shell_quote_neutralizes_metacharacters_and_embedded_quotes() {
        // Shell metacharacters become literal text inside the single quotes.
        assert_eq!(
            shell_quote("a; rm -rf /"),
            "'a; rm -rf /'",
            "semicolons must not start a new command"
        );
        assert_eq!(shell_quote("$(reboot)"), "'$(reboot)'");
        assert_eq!(shell_quote("`reboot`"), "'`reboot`'");
        // An embedded single quote is closed, escaped, and reopened.
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn build_firewall_script_aborts_on_error_and_quotes_every_argument() {
        let batches = vec![
            vec!["--reload".to_string()],
            vec!["-o".to_string(), "wg0".to_string()],
        ];
        let script = build_firewall_script(&batches);

        // `set -e` so a failed command stops the rest (no half-applied ruleset).
        assert!(script.starts_with("set -e\n"));
        // One `firewall-cmd` line per batch, each argument single-quoted.
        assert!(script.contains("\nfirewall-cmd '--reload'\n"));
        assert!(script.contains("\nfirewall-cmd '-o' 'wg0'\n"));
    }

    #[test]
    fn build_firewall_script_cannot_be_broken_out_of_by_profile_values() {
        // A malicious interface/host name must stay a single argument and never
        // become its own shell command, even though the script is `sh`-parsed.
        let batches = vec![vec![
            "-o".to_string(),
            "wg0'; reboot; echo '".to_string(),
            "-j".to_string(),
            "ACCEPT".to_string(),
        ]];
        let script = build_firewall_script(&batches);

        // The whole rule renders to exactly one `firewall-cmd` line in which the
        // injected `reboot` is sealed inside a single-quoted word: every `'` in
        // the value is emitted as the inert `'\''` sequence, so it can never
        // close the quote early and start a new command.
        assert_eq!(
            script,
            "set -e\nfirewall-cmd '-o' 'wg0'\\''; reboot; echo '\\''' '-j' 'ACCEPT'\n"
        );
    }

    #[test]
    fn shell_quote_round_trips_through_real_sh() {
        // Behavioural proof of injection-safety: hand each hostile value to a
        // real `/bin/sh` as a quoted word and confirm it comes back verbatim —
        // i.e. it was treated purely as data, never executed.
        for hostile in [
            "wg0",
            "a; rm -rf /",
            "$(reboot)",
            "`reboot`",
            "it's a \"trap\"",
            "new\nline",
        ] {
            let output = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("printf %s {}", shell_quote(hostile)))
                .output()
                .expect("run /bin/sh");
            assert!(output.status.success());
            assert_eq!(String::from_utf8_lossy(&output.stdout), hostile);
        }
    }

    #[test]
    fn build_firewall_script_of_no_batches_is_just_the_guard() {
        assert_eq!(build_firewall_script(&[]), "set -e\n");
    }
}
