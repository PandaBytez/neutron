//! System tests: the real [`FirewallClient`] against a real firewalld.
//!
//! The 24 unit tests in `src/firewall` assert the *arguments* passed to
//! `firewall-cmd`. They cannot show that firewalld accepts those arguments, that
//! the resulting rules say what was intended, or that teardown removes exactly
//! the rules Neutron installed. BUG-018 and BUG-019 live in precisely that gap:
//! rules that are present, correctly spelled, and too permissive.
//!
//! Safety: netfilter tables are per network namespace, so the REJECT-all
//! ruleset installed here is confined to the container. This was verified before
//! being relied upon -- see the note in `testing/Containerfile`.
//!
//! Two groups of test live here:
//!
//! * ordinary ones, which assert behaviour that is correct today and must stay
//!   that way; and
//! * `leak_*` ones, which **document open leaks from `BUGS.md` and are expected
//!   to fail**. They are skipped by the default runner and run on demand with
//!   `./testing/run-container-tests.sh --leaks`, so an open leak is
//!   demonstrable without turning CI permanently red.
//!
//! Run with: `./testing/run-container-tests.sh --firewall`

use neutron::firewall::FirewallClient;
use neutron::nm::{CliNmClient, Endpoint, WireguardTunnel};
use neutron::testing::require_sandbox;

/// The marker Neutron stamps onto every rule it installs.
const MARKER: &str = "neutron-lockdown";

/// Every direct rule currently installed, one per line.
fn all_rules() -> String {
    let output = std::process::Command::new("firewall-cmd")
        .args(["--permanent", "--direct", "--get-all-rules"])
        .output()
        .expect("firewall-cmd should run");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn marked_rules() -> Vec<String> {
    all_rules()
        .lines()
        .filter(|line| line.contains(MARKER))
        .map(|line| line.to_string())
        .collect()
}

/// Ensures lockdown is torn down even if an assertion panics, so one failure
/// cannot leave a REJECT-all ruleset behind for the next test.
struct Lockdown;

impl Drop for Lockdown {
    fn drop(&mut self) {
        let _ = CliNmClient.disable_lockdown();
    }
}

fn tunnel(interface: &str, host: &str, port: u16) -> WireguardTunnel {
    WireguardTunnel {
        interface: Some(interface.to_string()),
        endpoints: vec![Endpoint {
            host: host.to_string(),
            port,
        }],
    }
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn firewalld_accepts_the_lockdown_ruleset() {
    // The whole ruleset is built and applied through the real `pkexec sh -c`
    // path, so this also exercises `build_firewall_script` and `shell_quote`
    // against a real shell.
    require_sandbox();
    let _guard = Lockdown;

    CliNmClient
        .enable_lockdown(&[tunnel("wg-test", "192.0.2.1", 51820)])
        .expect("firewalld should accept the lockdown ruleset");

    let rules = marked_rules();
    assert!(
        !rules.is_empty(),
        "lockdown installed no marked rules:\n{}",
        all_rules()
    );
    assert!(
        rules.iter().any(|rule| rule.contains("REJECT")),
        "the terminal REJECT is what makes lockdown a deny-by-default policy"
    );
    assert!(
        rules.iter().any(|rule| rule.contains("wg-test")),
        "the tunnel interface must be allowed or the VPN cannot carry traffic"
    );
    assert!(
        rules.iter().any(|rule| rule.contains("192.0.2.1")),
        "the peer endpoint must be allowed or the handshake cannot complete"
    );
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn every_rule_lockdown_installs_carries_the_marker() {
    // Teardown finds Neutron's rules by marker. An unmarked rule would survive
    // `disable_lockdown` forever and keep blocking traffic with no way to
    // remove it from the UI.
    require_sandbox();
    let _guard = Lockdown;

    let before = all_rules().lines().count();
    CliNmClient
        .enable_lockdown(&[tunnel("wg-test", "192.0.2.1", 51820)])
        .expect("lockdown should enable");

    let added = all_rules().lines().count() - before;
    assert_eq!(
        added,
        marked_rules().len(),
        "every rule lockdown adds must carry the {MARKER} marker, or teardown \
         cannot find it:\n{}",
        all_rules()
    );
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn disabling_lockdown_removes_every_rule_it_installed() {
    require_sandbox();

    CliNmClient
        .enable_lockdown(&[tunnel("wg-test", "192.0.2.1", 51820)])
        .expect("lockdown should enable");
    assert!(!marked_rules().is_empty(), "precondition: rules installed");

    CliNmClient
        .disable_lockdown()
        .expect("lockdown should disable");

    assert!(
        marked_rules().is_empty(),
        "leftover rules keep blocking traffic after the user turned lockdown \
         off:\n{}",
        all_rules()
    );
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn teardown_leaves_foreign_rules_untouched() {
    // Lockdown must never clear the chain wholesale: a user's own direct rules,
    // or another tool's, have to survive.
    require_sandbox();

    let foreign = [
        "--permanent",
        "--direct",
        "--add-rule",
        "ipv4",
        "filter",
        "OUTPUT",
        "20",
        "-m",
        "comment",
        "--comment",
        "someone-elses-rule",
        "-j",
        "ACCEPT",
    ];
    std::process::Command::new("firewall-cmd")
        .args(foreign)
        .status()
        .expect("firewall-cmd should run");

    CliNmClient
        .enable_lockdown(&[tunnel("wg-test", "192.0.2.1", 51820)])
        .expect("lockdown should enable");
    CliNmClient
        .disable_lockdown()
        .expect("lockdown should disable");

    assert!(
        all_rules().contains("someone-elses-rule"),
        "teardown destroyed a rule Neutron did not create:\n{}",
        all_rules()
    );

    // Clean up the foreign rule so the next test starts from an empty chain.
    let mut remove = vec!["--permanent", "--direct", "--remove-rule"];
    remove.extend_from_slice(&foreign[3..]);
    let _ = std::process::Command::new("firewall-cmd")
        .args(&remove)
        .status();
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn enabling_lockdown_twice_is_idempotent() {
    // Re-enabling happens whenever the profile set changes
    // (`rebuild_lockdown_if_enabled`). Duplicated rules would accumulate on
    // every import.
    require_sandbox();
    let _guard = Lockdown;
    let tunnels = [tunnel("wg-test", "192.0.2.1", 51820)];

    CliNmClient
        .enable_lockdown(&tunnels)
        .expect("first enable should succeed");
    let first = marked_rules().len();

    CliNmClient
        .enable_lockdown(&tunnels)
        .expect("re-enabling should succeed");

    assert_eq!(
        marked_rules().len(),
        first,
        "re-enabling duplicated rules; they would accumulate on every profile \
         change:\n{}",
        all_rules()
    );
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn disabling_lockdown_that_was_never_enabled_is_harmless() {
    // The safeguard that a user can never be permanently locked out.
    require_sandbox();

    CliNmClient
        .disable_lockdown()
        .expect("disabling an inactive lockdown must succeed");
    assert!(marked_rules().is_empty());
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn an_endpoint_hostname_with_shell_metacharacters_cannot_escape_the_script() {
    // Every privileged change is rendered into one `sh -c` script, so a peer
    // endpoint taken from a profile is attacker-influenced input reaching a
    // shell. `shell_quote` is what makes that safe; this proves it against a
    // real shell rather than by inspecting the argument list.
    require_sandbox();
    let _guard = Lockdown;

    let malicious = "evil.example.com; touch /tmp/neutron-injection-probe";
    let _ = std::fs::remove_file("/tmp/neutron-injection-probe");

    // May legitimately fail (firewalld can reject the value); what must not
    // happen is the injected command running.
    let _ = CliNmClient.enable_lockdown(&[tunnel("wg-test", malicious, 51820)]);

    assert!(
        !std::path::Path::new("/tmp/neutron-injection-probe").exists(),
        "command injection: a profile-derived endpoint escaped its argument \
         position and executed in the privileged shell"
    );
}

// ---------------------------------------------------------------------------
// Open leaks. These assert the *correct* behaviour and are expected to FAIL
// until the corresponding bug is fixed. Skipped by the default runner; run with
// `./testing/run-container-tests.sh --leaks`.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn leak_bug018_established_flows_cannot_escape_a_dead_tunnel() {
    // BUG-018. `-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT` is
    // installed at priority 0 with no interface scope. conntrack tracks flows,
    // not interfaces, so a flow established through the tunnel keeps being
    // accepted after the tunnel dies -- now leaving over the physical interface
    // in the clear, which is the exact scenario lockdown exists to prevent.
    require_sandbox();
    let _guard = Lockdown;

    CliNmClient
        .enable_lockdown(&[tunnel("wg-test", "192.0.2.1", 51820)])
        .expect("lockdown should enable");

    let unscoped: Vec<String> = marked_rules()
        .into_iter()
        .filter(|rule| rule.contains("ESTABLISHED"))
        .filter(|rule| !rule.contains("-o wg") && !rule.contains("--out-interface wg"))
        .collect();

    assert!(
        unscoped.is_empty(),
        "BUG-018: an unscoped ESTABLISHED accept lets flows leak over the \
         physical interface once the tunnel drops:\n{unscoped:#?}"
    );
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn leak_bug019_dns_is_not_permitted_to_arbitrary_resolvers() {
    // BUG-019. `--dport 53` is allowed with no destination scope, so under full
    // lockdown DNS still reaches any resolver, including the ISP's.
    require_sandbox();
    let _guard = Lockdown;

    CliNmClient
        .enable_lockdown(&[tunnel("wg-test", "192.0.2.1", 51820)])
        .expect("lockdown should enable");

    let unscoped: Vec<String> = marked_rules()
        .into_iter()
        .filter(|rule| rule.contains("--dport 53"))
        .filter(|rule| !rule.contains("-d "))
        .collect();

    assert!(
        unscoped.is_empty(),
        "BUG-019: DNS is permitted to any destination under lockdown:\n{unscoped:#?}"
    );
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn leak_bug022_hostname_endpoints_are_pinned_to_an_address() {
    // BUG-022. A hostname endpoint cannot be pinned at rule-build time, so the
    // rule is written with `--dport` and no `-d`, opening that UDP port to every
    // host rather than just the VPN peer.
    require_sandbox();
    let _guard = Lockdown;

    CliNmClient
        .enable_lockdown(&[tunnel("wg-test", "vpn.example.com", 51820)])
        .expect("lockdown should enable");

    let unpinned: Vec<String> = marked_rules()
        .into_iter()
        .filter(|rule| rule.contains("--dport 51820"))
        .filter(|rule| !rule.contains("-d "))
        .collect();

    assert!(
        unpinned.is_empty(),
        "BUG-022: UDP/51820 is open to every host, not just the peer:\n{unpinned:#?}"
    );
}
