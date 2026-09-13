//! System tests: the real [`FirewallClient`] against a real firewalld.
//!
//! Unit tests in `src/firewall` assert the *arguments* passed to
//! `firewall-cmd`. They cannot show that firewalld accepts those arguments, that
//! the resulting rules say what was intended, or that teardown removes exactly
//! the rules Neutron installed. BUG-018 and BUG-019 live in precisely that gap:
//! rules that are present, correctly spelled, and too permissive.
//!
//! Safety: netfilter tables are per network namespace, so the deny-by-default
//! ruleset installed here is confined to the container. This was verified before
//! being relied upon -- see the note in `testing/Containerfile`.
//!
//! The `leak_*` tests are regression guards included in the system tier.
//! BUG-018 exercises actual packet egress; other checks inspect stored rules.
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
/// cannot leave a blocking ruleset behind for the next test.
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
        is_active: true,
    }
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn permanent_lockdown_refreshes_after_reload_without_reenabling_after_disable() {
    require_sandbox();
    let _guard = Lockdown;
    assert!(
        std::process::Command::new(env!("CARGO_BIN_EXE_neutron"))
            .args(["lockdown", "enable"])
            .status()
            .unwrap()
            .success()
    );
    let saved = marked_rules();
    // firewalld reconstructs runtime from permanent configuration at boot.
    assert!(
        std::process::Command::new("firewall-cmd")
            .arg("--reload")
            .status()
            .unwrap()
            .success()
    );
    CliNmClient.refresh_lockdown(None).unwrap();
    assert_eq!(marked_rules(), saved);
    let runtime = std::process::Command::new("firewall-cmd")
        .args(["--direct", "--get-all-rules"])
        .output()
        .unwrap();
    let runtime = String::from_utf8_lossy(&runtime.stdout);
    for rule in &saved {
        assert!(runtime.lines().any(|line| line == rule), "{runtime}");
    }
    CliNmClient.disable_lockdown().unwrap();
    CliNmClient.refresh_lockdown(None).unwrap();
    assert!(
        marked_rules().is_empty(),
        "refresh must never enable lockdown"
    );
    // Even CLI toggle arguments cannot make the installed helper disable rules.
    assert!(
        std::process::Command::new("/usr/local/libexec/neutron-lockdown-helper")
            .args(["lockdown", "enable"])
            .stdin(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert!(marked_rules().is_empty());
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn password_free_refresh_uses_real_polkit_as_an_unprivileged_user() {
    require_sandbox();
    const ACTION: &str = "io.github.pandabytez.neutron.lockdown-refresh";
    const TEST_RULE: &str = "/etc/polkit-1/rules.d/00-neutron-test-refresh.rules";
    const CHILD_ENV: &str = "NEUTRON_TEST_REFRESH_CHILD";

    if let Ok(mode) = std::env::var(CHILD_ENV) {
        let result = CliNmClient.refresh_lockdown(None);
        match mode.as_str() {
            "allowed" => result.expect("authorized unprivileged refresh should succeed"),
            "denied" | "missing" => {
                let error = result.unwrap_err().to_string();
                assert!(
                    error.contains("Password-free lockdown refresh is unavailable"),
                    "{error}"
                );
                assert!(error.contains("neutron lockdown enable"), "{error}");
                assert!(
                    error.contains(if mode == "denied" {
                        "exit 1)"
                    } else {
                        "exit 127)"
                    }),
                    "{error}"
                );
                assert!(!error.contains("Only trusted callers"), "{error}");
            }
            _ => panic!("unexpected refresh test mode: {mode}"),
        }
        return;
    }

    struct TestRule;
    impl Drop for TestRule {
        fn drop(&mut self) {
            std::fs::remove_file(TEST_RULE).expect("remove test authorization rule");
        }
    }

    let run_child = |mode| {
        let output = std::process::Command::new("runuser")
            .args(["-u", "nobody", "--"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "password_free_refresh_uses_real_polkit_as_an_unprivileged_user",
                "--nocapture",
            ])
            // Bypass the root-only firewall-test pkexec shim.
            .env("PATH", "/usr/bin:/bin")
            .env("SHELL", "/bin/sh")
            .env(CHILD_ENV, mode)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    };
    let wait_for_authorization = |expected| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let output = std::process::Command::new("runuser")
                .args([
                    "-u",
                    "nobody",
                    "--",
                    "/bin/sh",
                    "-c",
                    "exec /usr/bin/pkcheck --action-id \"$1\" --process \"$$\"",
                    "sh",
                    ACTION,
                ])
                .output()
                .unwrap();
            if output.status.code() == Some(expected) {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "{output:?}");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    };

    let _lockdown = Lockdown;
    let legacy_rule = "/etc/polkit-1/rules.d/49-neutron-lockdown-refresh.rules";
    std::fs::write(
        legacy_rule,
        r#"polkit.addRule(function(action, subject) {
            if (action.id == "org.freedesktop.policykit.exec" &&
                action.lookup("program") == "/usr/local/libexec/neutron-lockdown-helper") {
                return subject.local && subject.active ? polkit.Result.YES : polkit.Result.NO;
            }
        });
"#,
    )
    .unwrap();
    assert!(
        std::process::Command::new(env!("CARGO_BIN_EXE_neutron"))
            .args(["lockdown", "enable"])
            .status()
            .unwrap()
            .success()
    );
    assert!(!std::path::Path::new(legacy_rule).exists());
    let action_path = format!("/usr/local/share/polkit-1/actions/{ACTION}.policy");
    let policy = std::fs::read_to_string(&action_path).unwrap();
    let helper_path = std::fs::canonicalize("/usr/local/libexec/neutron-lockdown-helper").unwrap();
    assert!(policy.contains(&format!(
        "<annotate key=\"org.freedesktop.policykit.exec.path\">{}</annotate>",
        helper_path.display()
    )));
    assert!(policy.contains("<allow_any>no</allow_any>"));
    assert!(policy.contains("<allow_inactive>no</allow_inactive>"));
    assert!(policy.contains("<allow_active>yes</allow_active>"));
    let saved = marked_rules();
    wait_for_authorization(1);
    run_child("denied");
    assert_eq!(marked_rules(), saved);

    // There is no active logind session in this container. Grant only this
    // action to the test user so both pkcheck and pkexec exercise real polkit.
    std::fs::write(
        TEST_RULE,
        format!(
            "polkit.addRule(function(action, subject) {{\n\
             if (action.id == \"{ACTION}\" && subject.user == \"nobody\") \
             return polkit.Result.YES;\n\
             }});\n"
        ),
    )
    .unwrap();
    let _rule = TestRule;
    wait_for_authorization(0);
    // Removing an allowance is fail-closed and forces the helper to do real
    // privileged work instead of merely accepting already-matching rules.
    let loopback = saved.iter().find(|rule| rule.contains("-o lo ")).unwrap();
    assert!(
        std::process::Command::new("firewall-cmd")
            .args(["--direct", "--remove-rule"])
            .args(loopback.split_whitespace())
            .status()
            .unwrap()
            .success()
    );
    run_child("allowed");
    assert_eq!(marked_rules(), saved);
    let runtime = std::process::Command::new("firewall-cmd")
        .args(["--direct", "--get-all-rules"])
        .output()
        .unwrap();
    assert!(runtime.status.success(), "{runtime:?}");
    assert!(
        String::from_utf8_lossy(&runtime.stdout)
            .lines()
            .any(|line| line == loopback)
    );

    CliNmClient.disable_lockdown().unwrap();
    run_child("allowed");
    assert!(
        marked_rules().is_empty(),
        "refresh must not re-enable lockdown"
    );

    std::fs::remove_file(action_path).unwrap();
    wait_for_authorization(127);
    run_child("missing");
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
        rules
            .iter()
            .any(|rule| rule.contains("mangle OUTPUT") && rule.contains("DROP")),
        "the mangle DROP must enforce lockdown before filter-table accepts"
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

    // Upgrade from the old filter-table rules must remove our legacy entries
    // while preserving foreign rules in both tables.
    let mut legacy = foreign;
    legacy[10] = MARKER;
    assert!(
        std::process::Command::new("firewall-cmd")
            .args(legacy)
            .status()
            .unwrap()
            .success()
    );
    let mut foreign_mangle = foreign;
    foreign_mangle[4] = "mangle";
    assert!(
        std::process::Command::new("firewall-cmd")
            .args(foreign_mangle)
            .status()
            .unwrap()
            .success()
    );

    CliNmClient
        .enable_lockdown(&[tunnel("wg-test", "192.0.2.1", 51820)])
        .expect("lockdown should enable");
    assert!(
        marked_rules()
            .iter()
            .all(|rule| rule.contains("mangle OUTPUT"))
    );
    CliNmClient
        .disable_lockdown()
        .expect("lockdown should disable");

    assert!(
        all_rules()
            .lines()
            .filter(|line| line.contains("someone-elses-rule"))
            .count()
            == 2,
        "teardown destroyed a rule Neutron did not create:\n{}",
        all_rules()
    );

    // Clean up the foreign rule so the next test starts from an empty chain.
    let mut remove = vec!["--permanent", "--direct", "--remove-rule"];
    remove.extend_from_slice(&foreign[3..]);
    let _ = std::process::Command::new("firewall-cmd")
        .args(&remove)
        .status();
    remove[4] = "mangle";
    let _ = std::process::Command::new("firewall-cmd")
        .args(&remove)
        .status();
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn teardown_and_rebuild_preserve_runtime_only_foreign_rules() {
    require_sandbox();
    let _guard = Lockdown;
    let rich = "rule family=ipv4 source address=198.51.100.9 reject";
    let command = |args: &[&str]| {
        let output = std::process::Command::new("firewall-cmd")
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{args:?}: {output:?}");
    };
    command(&["--direct", "--add-chain", "ipv4", "filter", "FOREIGN_TEST"]);
    command(&[
        "--direct",
        "--add-rule",
        "ipv4",
        "filter",
        "FOREIGN_TEST",
        "0",
        "-m",
        "comment",
        "--comment",
        "foreign comment with spaces",
        "-j",
        "DROP",
    ]);
    command(&["--zone=public", "--add-rich-rule", rich]);

    let foreign_runtime = [
        "--direct",
        "--add-rule",
        "ipv4",
        "filter",
        "OUTPUT",
        "77",
        "-p",
        "tcp",
        "--dport",
        "8888",
        "-m",
        "comment",
        "--comment",
        "foreign-runtime-rule",
        "-j",
        "DROP",
    ];
    let status = std::process::Command::new("firewall-cmd")
        .args(foreign_runtime)
        .status()
        .expect("install foreign runtime rule");
    assert!(status.success());

    // Enable lockdown (which rebuilds)
    CliNmClient
        .enable_lockdown(&[tunnel("wg-test", "192.0.2.1", 51820)])
        .expect("lockdown should enable");

    // Assert foreign runtime rule survived enable/rebuild
    let runtime_rules = std::process::Command::new("firewall-cmd")
        .args(["--direct", "--get-all-rules"])
        .output()
        .expect("get runtime rules");
    let runtime_str = String::from_utf8_lossy(&runtime_rules.stdout);
    assert!(
        runtime_str.contains("foreign-runtime-rule"),
        "foreign runtime rule was lost after lockdown enable:\n{runtime_str}"
    );

    // Disable lockdown
    CliNmClient
        .disable_lockdown()
        .expect("lockdown should disable");

    // Assert foreign runtime rule survived disable
    let runtime_rules_after = std::process::Command::new("firewall-cmd")
        .args(["--direct", "--get-all-rules"])
        .output()
        .expect("get runtime rules");
    let runtime_str_after = String::from_utf8_lossy(&runtime_rules_after.stdout);
    assert!(
        runtime_str_after.contains("foreign-runtime-rule"),
        "foreign runtime rule was lost after lockdown disable:\n{runtime_str_after}"
    );
    command(&[
        "--direct",
        "--query-chain",
        "ipv4",
        "filter",
        "FOREIGN_TEST",
    ]);
    command(&[
        "--direct",
        "--query-rule",
        "ipv4",
        "filter",
        "FOREIGN_TEST",
        "0",
        "-m",
        "comment",
        "--comment",
        "foreign comment with spaces",
        "-j",
        "DROP",
    ]);
    command(&["--zone=public", "--query-rich-rule", rich]);
    command(&["--zone=public", "--remove-rich-rule", rich]);
    command(&[
        "--direct",
        "--remove-rule",
        "ipv4",
        "filter",
        "FOREIGN_TEST",
        "0",
        "-m",
        "comment",
        "--comment",
        "foreign comment with spaces",
        "-j",
        "DROP",
    ]);
    command(&[
        "--direct",
        "--remove-chain",
        "ipv4",
        "filter",
        "FOREIGN_TEST",
    ]);

    // Clean up
    let mut remove = vec!["--direct", "--remove-rule"];
    remove.extend_from_slice(&foreign_runtime[2..]);
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
// Leak regression guards, also selectable with --leaks.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn leak_bug018_established_flows_cannot_escape_a_dead_tunnel() {
    require_sandbox();
    let mut child = std::process::Command::new("python3")
        .args(["-u", "-c", include_str!("firewall_egress.py")])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("start isolated packet fixture");
    use std::io::{BufRead, Write};
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ready", "fixture failed before lockdown");
    let _guard = Lockdown;
    CliNmClient
        .enable_lockdown(&[tunnel("wg-test", "192.0.2.1", 51820)])
        .unwrap();
    child.stdin.take().unwrap().write_all(b"go\n").unwrap();
    assert!(
        child.wait().unwrap().success(),
        "established egress escaped lockdown"
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
        .filter(|rule| rule.contains("--dport 53") && rule.contains("ACCEPT"))
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
