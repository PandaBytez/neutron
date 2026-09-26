//! Shared test utilities.
//!
//! This module is intentionally exposed unconditionally (not behind `#[cfg(test)]`
//! or a feature flag) so that integration tests under `tests/`, which compile
//! against this crate as an external library, can reuse the same mock as the
//! in-crate unit tests. Everything here is `pub`, so it never triggers
//! dead-code warnings in normal builds.
//!
//! # A test never touches the live machine
//!
//! Running the suite on a workstation has to be inert: no settings rewritten, no
//! daemon killed, no real profile or firewall touched. Anything that reaches
//! outside the process therefore takes the path it works on as an argument, and
//! a test hands it a temporary one -- [`scratch_dir`], [`temp_config_path`], the
//! autostart directory, the process root. The two that are easy to forget are
//! the ones that end in a side effect rather than a read:
//!
//! * the process scan behind `kill_other_neutron_processes`, which SIGTERMs
//!   every process named `neutron` -- a hardcoded `/proc` there kills the
//!   developer's own daemon and TUI, silently, on every `cargo test`;
//! * the lease file under `$XDG_RUNTIME_DIR`, which is what a live daemon
//!   publishes for the TUI.
//!
//! A test that genuinely needs the real thing is a *system* test: marked
//! `#[ignore = "system test: requires the disposable sandbox"]` and gated on
//! [`require_sandbox`].

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{AppError, AppResult};
use crate::firewall::FirewallClient;
use crate::nm::{
    NmIntrospect, NmLifecycle, NmPolicy, ProfileState, WireguardProfile, WireguardTunnel,
};

fn record(log: &Mutex<Vec<String>>, entry: String) {
    log.lock().expect("mock mutex poisoned").push(entry);
}

/// Environment variable that marks a disposable test sandbox. Set only by
/// `testing/Containerfile` and the VM provisioning in `testing/vm/`.
pub const SANDBOX_ENV: &str = "NEUTRON_TEST_SANDBOX";

/// Abort unless running inside a disposable sandbox.
///
/// The system tests create, modify and delete real NetworkManager profiles and
/// change real routing state. Run against a developer's own machine that
/// destroys their network configuration -- which is exactly how several of the
/// leaks in `BUGS.md` came to be verified by hand on a live desktop instead of
/// by a test.
///
/// Every such test calls this first. They are additionally marked `#[ignore]`,
/// so the layering is:
///
/// * `cargo test` on a workstation -- skipped, never even started;
/// * `cargo test -- --ignored` on a workstation -- **panics here**, changing
///   nothing;
/// * inside the sandbox -- runs.
///
/// The second case is the point: forcing the tests to run outside the sandbox
/// has to fail loudly and early rather than quietly reconfigure someone's
/// network.
pub fn require_sandbox() {
    if std::env::var(SANDBOX_ENV).as_deref() == Ok("1") {
        return;
    }

    panic!(
        "refusing to run a system test outside the disposable sandbox.\n\
         \n\
         These tests create and delete real NetworkManager profiles and change \
         real routing state, so running them against a workstation would damage \
         its network configuration.\n\
         \n\
         Run them with:  ./testing/run-container-tests.sh\n\
         (sets {SANDBOX_ENV}=1 inside a throwaway container)"
    );
}

/// A unique name for a profile created by a system test.
///
/// Constrained to a valid Linux interface name -- at most 15 characters,
/// alphanumeric. `nmcli connection import type wireguard` derives the interface
/// from the file stem and rejects anything longer with "The name of the
/// WireGuard config must be a valid interface name followed by \".conf\"", so a
/// descriptive fixture name fails at import rather than in the assertion.
///
/// Every name is prefixed `ns` so anything left behind by an interrupted run is
/// identifiable, and carries a timestamp so a fixture can never collide with an
/// existing profile.
pub fn sandbox_profile_name(label: &str) -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();

    // Keep a few characters of the label for readability in `nmcli` output,
    // then fill the rest of the budget with the timestamp.
    let short_label: String = label
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(4)
        .collect();

    let name = format!("ns{short_label}{:07}", stamp % 10_000_000);
    debug_assert!(
        name.len() <= 15,
        "fixture name must be a valid interface name: {name}"
    );
    name
}

/// A minimal but valid WireGuard configuration, for import fixtures.
///
/// The endpoint is in `TEST-NET-1` (RFC 5737, reserved for documentation) so a
/// profile built from this can never reach a real host even if something
/// activates it.
pub fn sample_wireguard_config(address: &str, dns: &str) -> String {
    format!(
        "[Interface]\n\
         PrivateKey = OMHVnT2Gm0ZBb3xF2Cq0hZ0jVQ1z3T0lQ0Z0YQ0Z0X8=\n\
         Address = {address}\n\
         DNS = {dns}\n\
         \n\
         [Peer]\n\
         PublicKey = tGZ0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0k=\n\
         AllowedIPs = 0.0.0.0/0, ::/0\n\
         Endpoint = 192.0.2.1:51820\n\
         PersistentKeepalive = 25\n"
    )
}

fn snapshot(log: &Mutex<Vec<String>>) -> Vec<String> {
    log.lock().expect("mock mutex poisoned").clone()
}

/// A directory of this run's own, named after `label`.
///
/// The clock is the only thing separating two tests that want the same label,
/// which is why every temporary path here goes through this: a shared prefix
/// would be a shared prefix, and a copied suffix would be one copy too few when
/// someone adds the next one.
fn unique_test_dir(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir().join(format!("neutron-vpn-test-{label}-{suffix}"))
}

/// Create a unique temporary path for test configuration files.
pub fn temp_config_path(label: &str) -> PathBuf {
    unique_test_dir(label).join("config.json")
}

/// Create a unique temporary path for test TOML configuration files.
pub fn temp_toml_config_path(label: &str) -> PathBuf {
    unique_test_dir(label).join("config.toml")
}

/// An empty directory to stand in for `/proc`.
///
/// Anything that walks the process table takes the root as an argument
/// precisely so a test can hand it this instead: the scan ends in `kill(2)`, and
/// reaching the real `/proc` would take down the developer's own daemon and TUI
/// as a side effect of running the suite.
pub fn scratch_dir(label: &str) -> PathBuf {
    let dir = unique_test_dir(label);
    std::fs::create_dir_all(&dir).expect("scratch dir should be created");
    dir
}

/// Clean up temporary test configuration directories.
pub fn remove_temp_config(path: &Path) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::remove_dir_all(parent);
    }
}

/// Test helper to create a WireguardProfile.
/// An inactive profile: what most lifecycle tests want, and what a two-argument
/// `profile` in a test module usually meant.
pub fn inactive(name: &str, uuid: &str) -> WireguardProfile {
    profile(name, uuid, ProfileState::Inactive)
}

pub fn profile(name: &str, uuid: &str, state: ProfileState) -> WireguardProfile {
    WireguardProfile {
        name: name.to_string(),
        uuid: uuid.to_string(),
        state,
    }
}

/// A configurable in-memory [`NmClient`] for tests.
///
/// Clones share recorded calls and simulated state through `Arc<Mutex<_>>`.
#[derive(Clone, Default)]
pub struct MockNmClient {
    profiles: Vec<WireguardProfile>,
    tunnels: Vec<WireguardTunnel>,
    fail_list: bool,
    fail_list_count: Arc<AtomicUsize>,
    fail_ids: HashSet<String>,
    fail_kill_switch: bool,
    fail_autoconnect: bool,
    fail_lockdown: bool,
    installed_lockdown_state: bool,
    fail_split_tunnel: bool,
    fail_import: bool,
    fail_disconnect: bool,
    strict_disconnect: bool,
    no_tunnel_address: bool,
    no_tunnel_interface: bool,
    tunnel_address_override: Option<String>,
    unhealthy: bool,
    calls: Arc<Mutex<Vec<String>>>,
    attempted: Arc<Mutex<Vec<String>>>,
    connected: Arc<Mutex<Vec<String>>>,
    kill_switch_calls: Arc<Mutex<Vec<String>>>,
    autoconnect_calls: Arc<Mutex<Vec<String>>>,
    lockdown_calls: Arc<Mutex<Vec<String>>>,
    split_tunnel_calls: Arc<Mutex<Vec<String>>>,
    imported: Arc<Mutex<Vec<String>>>,
    extra_profiles: Arc<Mutex<Vec<WireguardProfile>>>,
    deleted: Arc<Mutex<HashSet<String>>>,
    /// Simulated NetworkManager profile settings, keyed by UUID then property.
    ///
    /// Populated by replaying the *real* `nmcli` argument builders, so a test
    /// can assert on what a profile actually ends up configured with rather
    /// than merely that some method was called. Recording only call names is
    /// what let a policy change silently stop tunnels routing.
    settings: Arc<Mutex<BTreeMap<String, BTreeMap<String, String>>>>,
    /// The UUIDs currently up, so policy changes can be exercised against a
    /// live connection. A list rather than a single value because
    /// NetworkManager can bring several WireGuard profiles up at once -- each
    /// is its own interface, so they never compete for a device.
    active: Arc<Mutex<Vec<String>>>,
    config_path: Option<PathBuf>,
    sweep_barrier: Arc<Mutex<Option<Arc<std::sync::Barrier>>>>,
}

impl MockNmClient {
    /// A mock that returns the given profiles and succeeds for every operation.
    pub fn new(profiles: Vec<WireguardProfile>) -> Self {
        let active: Vec<String> = profiles
            .iter()
            .filter(|profile| profile.is_active())
            .map(|profile| profile.uuid.clone())
            .collect();
        Self {
            profiles,
            active: Arc::new(Mutex::new(active)),
            ..Self::default()
        }
    }

    pub fn with_config_path(mut self, path: PathBuf) -> Self {
        self.config_path = Some(path);
        self
    }

    /// The config this mock reads policies from: what a test injected, or -- like
    /// the real client -- the user's own.
    fn policy_config_path(&self) -> Option<PathBuf> {
        self.config_path
            .clone()
            .or_else(|| crate::config::default_config_path().ok())
    }

    /// The kill-switch and split-tunnel arguments the real client would pin on
    /// `identifier` for this config.
    ///
    /// One implementation for connect, switch and import: they differ only in
    /// *when* they run. Three copies is three places for an injected path to be
    /// forgotten, which is how `switch_to` and `import_wireguard_profile` came to
    /// read the developer's real settings while `connect` honoured the temp one.
    fn apply_policy_args(&self, identifier: &str, config_path: &Path) {
        let Ok(app_cfg) = crate::config::load(config_path) else {
            return;
        };
        if app_cfg.kill_switch_enabled {
            self.apply_args(&crate::nm::kill_switch::set_args(identifier, true, true));
        }
        if app_cfg.global_split_tunnel.mode.is_enabled() {
            let (v4, v6) = crate::nm::split_tunnel::routes_for(
                app_cfg.global_split_tunnel.mode,
                &app_cfg.global_split_tunnel.cidrs,
                &app_cfg.global_split_tunnel.domains,
            );
            self.apply_args(&crate::nm::split_tunnel::set_args(
                identifier,
                app_cfg.global_split_tunnel.mode,
                &v4,
                &v6,
            ));
        }
    }

    pub fn with_sweep_barrier(self, barrier: Arc<std::sync::Barrier>) -> Self {
        if let Ok(mut slot) = self.sweep_barrier.lock() {
            *slot = Some(barrier);
        }
        self
    }

    /// Replay one `nmcli connection modify <uuid> <key> <value>...` batch into
    /// the simulated profile settings.
    fn apply_args(&self, args: &[String]) {
        let [verb, action, uuid, rest @ ..] = args else {
            return;
        };
        if verb != "connection" || action != "modify" {
            return;
        }
        let mut settings = self.settings.lock().expect("mock mutex poisoned");
        let profile = settings.entry(uuid.clone()).or_default();
        for pair in rest.as_chunks::<2>().0 {
            profile.insert(pair[0].clone(), pair[1].clone());
        }
    }

    fn apply_to_all<F>(&self, build: F)
    where
        F: Fn(&str) -> Vec<String>,
    {
        if let Ok(mut slot) = self.sweep_barrier.lock()
            && let Some(barrier) = slot.take()
        {
            barrier.wait();
        }
        for uuid in self.uuids() {
            self.apply_args(&build(&uuid));
        }
    }

    /// The simulated value of `key` on profile `uuid`, if it was ever set.
    pub fn setting(&self, uuid: &str, key: &str) -> Option<String> {
        self.settings
            .lock()
            .expect("mock mutex poisoned")
            .get(uuid)
            .and_then(|profile| profile.get(key))
            .cloned()
    }

    /// Every UUID the mock currently considers active.
    pub fn active_uuids(&self) -> Vec<String> {
        self.active.lock().expect("mock mutex poisoned").clone()
    }

    /// The single active UUID, or `None` when nothing (or more than one) is up.
    pub fn active_uuid(&self) -> Option<String> {
        let active = self.active.lock().expect("mock mutex poisoned");
        match active.as_slice() {
            [uuid] => Some(uuid.clone()),
            _ => None,
        }
    }

    /// Every profile UUID the mock knows about.
    pub fn uuids(&self) -> Vec<String> {
        let deleted = self.deleted.lock().expect("mock mutex poisoned");
        let extra = self.extra_profiles.lock().expect("mock mutex poisoned");
        self.profiles
            .iter()
            .chain(extra.iter())
            .filter(|profile| !deleted.contains(&profile.uuid))
            .map(|profile| profile.uuid.clone())
            .collect()
    }

    /// Bring `uuid` up alongside whatever is already active, as `connection up`
    /// does.
    fn add_active(&self, uuid: &str) {
        let mut active = self.active.lock().expect("mock mutex poisoned");
        if !active.iter().any(|entry| entry == uuid) {
            active.push(uuid.to_string());
        }
    }

    /// Replace everything active with `uuid`, as `switch_to` does.
    fn replace_active(&self, uuid: &str) {
        let mut active = self.active.lock().expect("mock mutex poisoned");
        active.clear();
        active.push(uuid.to_string());
    }

    /// A mock whose `list_wireguard_profiles` fails, to exercise error paths.
    pub fn failing_list() -> Self {
        Self {
            fail_list: true,
            ..Self::default()
        }
    }

    /// A mock whose `list_wireguard_profiles` fails `count` times transiently.
    pub fn with_transient_list_failure(self, count: usize) -> Self {
        self.fail_list_count.store(count, Ordering::SeqCst);
        self
    }

    /// A mock that returns the given profiles but fails `connect` for any of the
    /// supplied profile ids.
    pub fn with_failures(profiles: Vec<WireguardProfile>, fail_ids: &[&str]) -> Self {
        Self {
            profiles,
            fail_ids: fail_ids.iter().map(|id| (*id).to_string()).collect(),
            ..Self::default()
        }
    }

    /// Consume this mock and return one whose `connect`/`switch_to` report the
    /// tunnel as unhealthy, as the real client does when a peer never completes
    /// a handshake.
    pub fn fail_unhealthy(mut self) -> Self {
        self.unhealthy = true;
        self
    }

    /// Consume this mock and return one whose `set_kill_switch_all` fails, to
    /// exercise the error path where NetworkManager rejects the change. The
    /// attempt is still recorded in [`Self::kill_switch_calls`] before the
    /// failure is returned.
    pub fn fail_kill_switch(mut self) -> Self {
        self.fail_kill_switch = true;
        self
    }

    /// Consume this mock and return one whose `set_autoconnect_all` fails, to
    /// exercise the best-effort path where NetworkManager rejects the change.
    /// The attempt is still recorded in [`Self::autoconnect_calls`] first.
    pub fn fail_autoconnect(mut self) -> Self {
        self.fail_autoconnect = true;
        self
    }

    /// Consume this mock and return one whose `enable_lockdown`/`teardown_lockdown`
    /// fail, to exercise the error path where the firewall rejects the change.
    /// The attempt is still recorded in [`Self::lockdown_calls`] first.
    pub fn fail_lockdown(mut self) -> Self {
        self.fail_lockdown = true;
        self
    }

    /// Consume this mock and return one that reports Neutron-owned lockdown
    /// state on the machine, so a caller tears down even when the saved config
    /// says lockdown is off (or is gone entirely).
    pub fn with_installed_lockdown_state(mut self) -> Self {
        self.installed_lockdown_state = true;
        self
    }

    /// Consume this mock and return one whose `apply_split_tunnel_all` fails.
    pub fn fail_split_tunnel(mut self) -> Self {
        self.fail_split_tunnel = true;
        self
    }

    /// Consume this mock and return one whose `import_wireguard_profile` fails,
    /// to exercise the error path in `sync_profiles_dir` that no test could
    /// previously reach (see BUGS.md test-architecture gap #12).
    pub fn fail_import(mut self) -> Self {
        self.fail_import = true;
        self
    }

    /// Consume this mock and return one whose `disconnect_active` fails with a
    /// generic command error (as opposed to `NoActiveProfile`) whenever there is
    /// something active to disconnect.
    pub fn fail_disconnect(mut self) -> Self {
        self.fail_disconnect = true;
        self
    }

    /// Consume this mock and return one whose `disconnect_active` returns
    /// `Err(AppError::NoActiveProfile)` instead of a silent `Ok(())` once
    /// nothing is active, mirroring the real client's documented behaviour.
    /// Opt-in (rather than the default) because several existing tests call
    /// `disconnect_active` speculatively and rely on the silent no-op.
    pub fn strict_disconnect(mut self) -> Self {
        self.strict_disconnect = true;
        self
    }

    /// Consume this mock and return one whose `tunnel_address` always returns
    /// `None`, as the real client does when a profile has no IPv4 address
    /// configured.
    pub fn without_tunnel_address(mut self) -> Self {
        self.no_tunnel_address = true;
        self
    }

    /// Consume this mock and return one whose `tunnel_address` is `address`
    /// instead of the default `10.2.0.2/32`. Tests that need the derived
    /// NAT-PMP gateway to be reachable point it at loopback.
    pub fn with_tunnel_address(mut self, address: &str) -> Self {
        self.tunnel_address_override = Some(address.to_string());
        self
    }

    /// Consume this mock and return one whose `tunnel_interface` always returns
    /// `None`, as the real client does when NetworkManager has no interface name
    /// configured for a profile.
    pub fn without_tunnel_interface(mut self) -> Self {
        self.no_tunnel_interface = true;
        self
    }

    /// Set the tunnels returned by `wireguard_tunnels`.
    pub fn with_tunnels(mut self, tunnels: Vec<WireguardTunnel>) -> Self {
        self.tunnels = tunnels;
        self
    }

    /// Every operation in invocation order, formatted as `connect:<id>`,
    /// `switch:<id>`, or `disconnect`.
    pub fn calls(&self) -> Vec<String> {
        snapshot(&self.calls)
    }

    /// Profile ids passed to `connect`, regardless of success.
    pub fn attempted_profiles(&self) -> Vec<String> {
        snapshot(&self.attempted)
    }

    /// Profile ids that `connect` reported as successfully connected.
    pub fn connected_profiles(&self) -> Vec<String> {
        snapshot(&self.connected)
    }

    /// Global kill-switch toggles in invocation order, formatted as
    /// `kill-switch-all:on` or `kill-switch-all:off`.
    pub fn kill_switch_calls(&self) -> Vec<String> {
        snapshot(&self.kill_switch_calls)
    }

    /// Global autoconnect toggles in invocation order, formatted as
    /// `autoconnect-all:on` or `autoconnect-all:off`.
    pub fn autoconnect_calls(&self) -> Vec<String> {
        snapshot(&self.autoconnect_calls)
    }

    /// Lockdown toggles in invocation order, formatted as `lockdown:on` or
    /// `lockdown:off`.
    pub fn lockdown_calls(&self) -> Vec<String> {
        snapshot(&self.lockdown_calls)
    }

    /// Split tunnel invocations in order, formatted as
    /// `split-tunnel-all:<mode>:<v4_count>:<v6_count>`.
    pub fn split_tunnel_calls(&self) -> Vec<String> {
        snapshot(&self.split_tunnel_calls)
    }

    /// Paths passed to `import_wireguard_profile`, in invocation order.
    pub fn imported_paths(&self) -> Vec<String> {
        snapshot(&self.imported)
    }
}

impl NmPolicy for MockNmClient {
    fn reapply_active_routes(&self) -> AppResult<()> {
        record(&self.calls, "reapply-active-routes".into());
        Ok(())
    }

    fn set_kill_switch_all(&self, enable: bool) -> AppResult<()> {
        record(
            &self.kill_switch_calls,
            format!("kill-switch-all:{}", if enable { "on" } else { "off" }),
        );

        if self.fail_kill_switch {
            return Err(AppError::CommandFailed(
                "simulated kill-switch failure".to_string(),
            ));
        }

        self.apply_to_all(|uuid| crate::nm::kill_switch::set_args(uuid, enable, true));
        Ok(())
    }

    fn set_autoconnect_all(&self, enable: bool) -> AppResult<()> {
        record(
            &self.autoconnect_calls,
            format!("autoconnect-all:{}", if enable { "on" } else { "off" }),
        );

        if self.fail_autoconnect {
            return Err(AppError::CommandFailed(
                "simulated autoconnect failure".to_string(),
            ));
        }

        self.apply_to_all(|uuid| crate::nm::autoconnect::set_args(uuid, enable));
        Ok(())
    }

    fn apply_split_tunnel_all(
        &self,
        mode: crate::config::SplitTunnelMode,
        v4_routes: &[String],
        v6_routes: &[String],
    ) -> AppResult<()> {
        record(
            &self.split_tunnel_calls,
            format!(
                "split-tunnel-all:{}:{}:{}",
                mode,
                v4_routes.len(),
                v6_routes.len()
            ),
        );

        if self.fail_split_tunnel {
            return Err(AppError::CommandFailed(
                "simulated split-tunnel failure".to_string(),
            ));
        }

        self.apply_to_all(|uuid| {
            crate::nm::split_tunnel::set_args(uuid, mode, v4_routes, v6_routes)
        });
        Ok(())
    }
}

/// Lifecycle seam.
impl NmLifecycle for MockNmClient {
    fn list_wireguard_profiles(&self) -> AppResult<Vec<WireguardProfile>> {
        if self.fail_list
            || self
                .fail_list_count
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |c| {
                    if c > 0 { Some(c - 1) } else { None }
                })
                .is_ok()
        {
            return Err(AppError::CommandFailed("simulated".to_string()));
        }
        let active = self.active_uuids();
        let deleted = self.deleted.lock().expect("mock mutex poisoned");
        let extra = self.extra_profiles.lock().expect("mock mutex poisoned");
        Ok(self
            .profiles
            .iter()
            .chain(extra.iter())
            .filter(|profile| !deleted.contains(&profile.uuid))
            .map(|profile| WireguardProfile {
                state: if active.contains(&profile.uuid) {
                    ProfileState::Active
                } else {
                    ProfileState::Inactive
                },
                ..profile.clone()
            })
            .collect())
    }

    fn connect(&self, profile_identifier: &str) -> AppResult<()> {
        record(&self.calls, format!("connect:{profile_identifier}"));
        record(&self.attempted, profile_identifier.to_string());

        if self.fail_ids.contains(profile_identifier) {
            return Err(AppError::CommandFailed(format!(
                "simulated failure for {profile_identifier}"
            )));
        }

        // Mirrors the real client: routing is pinned immediately before the
        // profile is brought up, along with active kill switch and split tunnel policies.
        self.apply_args(&crate::nm::tunnel_routing::set_args(
            profile_identifier,
            true,
        ));
        if let Some(config_path) = self.policy_config_path() {
            // Under the policy lock, as the real client does, so a concurrent
            // toggle cannot be read half-applied.
            let _ = crate::config::coordinate_policy(&config_path, || {
                self.apply_policy_args(profile_identifier, &config_path);
                Ok(())
            });
        }
        if self.unhealthy {
            // As the real client does: the tunnel came up but carries no
            // traffic, so it is rolled back rather than left black-holing.
            return Err(AppError::TunnelUnhealthy(format!(
                "{profile_identifier}: connected but no traffic is passing"
            )));
        }
        self.add_active(profile_identifier);
        record(&self.connected, profile_identifier.to_string());
        Ok(())
    }

    fn disconnect_active(&self) -> AppResult<()> {
        record(&self.calls, "disconnect".to_string());
        // Mirrors the real client, which downs the first active profile it
        // finds -- so an over-connected system needs one call per profile.
        let mut active = self.active.lock().expect("mock mutex poisoned");
        if active.is_empty() {
            return if self.strict_disconnect {
                Err(AppError::NoActiveProfile)
            } else {
                Ok(())
            };
        }
        if self.fail_disconnect {
            return Err(AppError::CommandFailed(
                "simulated disconnect failure".to_string(),
            ));
        }
        active.remove(0);
        Ok(())
    }

    fn switch_to(&self, profile_identifier: &str) -> AppResult<()> {
        record(&self.calls, format!("switch:{profile_identifier}"));
        if self.strict_disconnect && self.fail_disconnect {
            return Err(AppError::CommandFailed(
                "teardown failed and old profile is still active".to_string(),
            ));
        }
        self.apply_args(&crate::nm::tunnel_routing::set_args(
            profile_identifier,
            true,
        ));
        if let Some(config_path) = self.policy_config_path() {
            self.apply_policy_args(profile_identifier, &config_path);
        }
        if self.unhealthy {
            return Err(AppError::TunnelUnhealthy(format!(
                "{profile_identifier}: connected but no traffic is passing"
            )));
        }
        self.replace_active(profile_identifier);
        Ok(())
    }

    fn import_wireguard_profile(&self, path: &std::path::Path) -> AppResult<String> {
        record(&self.imported, path.display().to_string());
        if self.fail_import {
            return Err(AppError::CommandFailed(format!(
                "simulated import failure for {}",
                path.display()
            )));
        }

        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("imported");
        let uuid = format!("uuid-{stem}");

        let profile = WireguardProfile {
            name: stem.to_string(),
            uuid: uuid.clone(),
            state: ProfileState::Inactive,
        };
        self.extra_profiles
            .lock()
            .expect("mock mutex poisoned")
            .push(profile);

        // NetworkManager imports enable autoconnect by default, so Neutron
        // disables it immediately so startup-random works.
        self.apply_args(&crate::nm::autoconnect::set_args(&uuid, false));

        // When imported while global security settings are active, the new profile
        // immediately inherits kill switch and split-tunnel settings.
        if let Some(config_path) = self.policy_config_path() {
            self.apply_policy_args(&uuid, &config_path);
        }

        Ok(format!("Imported {}", path.display()))
    }

    fn delete_profile(&self, uuid: &str) -> AppResult<()> {
        record(&self.calls, format!("delete:{}", uuid));
        self.deleted
            .lock()
            .expect("mock mutex poisoned")
            .insert(uuid.to_string());
        self.active
            .lock()
            .expect("mock mutex poisoned")
            .retain(|u| u != uuid);
        self.settings
            .lock()
            .expect("mock mutex poisoned")
            .remove(uuid);
        self.extra_profiles
            .lock()
            .expect("mock mutex poisoned")
            .retain(|p| p.uuid != uuid);
        Ok(())
    }
}

/// Introspection seam.
impl NmIntrospect for MockNmClient {
    fn wireguard_tunnels(&self) -> AppResult<Vec<WireguardTunnel>> {
        if self.fail_list {
            return Err(AppError::CommandFailed("simulated".to_string()));
        }
        Ok(self.tunnels.clone())
    }

    fn get_profile_diagnostics(
        &self,
        _uuid: &str,
        _is_active: bool,
    ) -> AppResult<crate::nm::ProfileDiagnostics> {
        Ok(crate::nm::ProfileDiagnostics {
            interface_name: "wg0".to_string(),
            public_key: "mock_public_key_abc123".to_string(),
            endpoint: "127.0.0.1:51820".to_string(),
            allowed_ips: "0.0.0.0/0, ::/0".to_string(),
            latest_handshake: "10s ago".to_string(),
            transfer_rx: "100.00 KiB".to_string(),
            transfer_tx: "50.00 KiB".to_string(),
            keepalive: "25".to_string(),
            listen_port: None,
        })
    }

    fn tunnel_address(&self, _uuid: &str) -> Option<String> {
        if self.no_tunnel_address {
            None
        } else if let Some(address) = &self.tunnel_address_override {
            Some(address.clone())
        } else {
            Some("10.2.0.2/32".to_string())
        }
    }

    fn tunnel_interface(&self, _uuid: &str) -> Option<String> {
        if self.no_tunnel_interface {
            None
        } else {
            Some("wg0".to_string())
        }
    }

    fn tunnel_dns(&self, _uuid: &str) -> Option<String> {
        Some("10.2.0.1".to_string())
    }
}

impl FirewallClient for MockNmClient {
    fn refresh_lockdown(&self, _activating: Option<&str>) -> AppResult<()> {
        record(&self.lockdown_calls, "lockdown:refresh".to_string());
        if self.fail_lockdown {
            return Err(AppError::Firewall("simulated lockdown failure".to_string()));
        }
        Ok(())
    }

    fn enable_lockdown(&self, _tunnels: &[WireguardTunnel]) -> AppResult<()> {
        record(&self.lockdown_calls, "lockdown:on".to_string());

        if self.fail_lockdown {
            return Err(AppError::Firewall("simulated lockdown failure".to_string()));
        }

        Ok(())
    }

    fn has_installed_lockdown_state(&self) -> AppResult<bool> {
        Ok(self.installed_lockdown_state)
    }

    fn teardown_lockdown(&self, revoke_grant: bool) -> AppResult<()> {
        record(
            &self.lockdown_calls,
            if revoke_grant {
                "lockdown:teardown:rules+grant"
            } else {
                "lockdown:teardown:rules"
            }
            .to_string(),
        );

        if self.fail_lockdown {
            return Err(AppError::Firewall("simulated lockdown failure".to_string()));
        }

        Ok(())
    }
}

/// A qBittorrent WebUI stub for exercising the port-sync integration.
///
/// Answers the calls [`crate::portforward::qbittorrent::QBittorrentClient::sync_port`]
/// makes and records the preferences it was handed, so a test can assert on what
/// actually reached qBittorrent rather than merely that a push was attempted.
///
/// Lives here rather than beside any one test module because all three layers
/// that push a port -- the TUI, the tray daemon and the CLI -- need it.
pub struct MockQBittorrentWebUi {
    port: u16,
    log: Arc<RequestLog>,
    done: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

/// What a stub was asked for, so a test can assert on the conversation rather
/// than on a count.
#[derive(Default)]
pub struct RequestLog {
    paths: Mutex<Vec<String>>,
    set_preferences: Mutex<String>,
}

impl RequestLog {
    /// The request target of every call received, in order.
    pub fn paths(&self) -> Vec<String> {
        self.paths
            .lock()
            .map(|paths| paths.clone())
            .unwrap_or_default()
    }

    /// The raw `setPreferences` request last received, empty if none was.
    pub fn last_set_preferences(&self) -> String {
        self.set_preferences
            .lock()
            .map(|slot| slot.clone())
            .unwrap_or_default()
    }

    fn record(&self, request: &str) {
        if let Ok(mut paths) = self.paths.lock() {
            paths.push(
                request
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string(),
            );
        }
        if request.contains("/api/v2/app/setPreferences")
            && let Ok(mut slot) = self.set_preferences.lock()
        {
            *slot = request.to_string();
        }
    }
}

impl MockQBittorrentWebUi {
    /// The session cookie the stub hands out on a successful login.
    pub const SESSION_COOKIE: &'static str = "mock_session";

    /// The `listen_port` the stub reports before a push replaces it.
    pub const INITIAL_LISTEN_PORT: u16 = 40000;

    /// Start the stub on an ephemeral loopback port.
    pub fn start() -> Self {
        Self::spawn(|request| {
            // Login is answered even though the default config sends no
            // credentials: without it, merely configuring a username would turn
            // every test into a confusing 404.
            if request.contains("/api/v2/auth/login") {
                "HTTP/1.1 200 OK\r\nSet-Cookie: SID=mock_session; Path=/\r\nContent-Length: 3\r\n\r\nOk."
            } else if request.contains("/api/v2/app/version") {
                "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nv5.0.3"
            } else if request.contains("/api/v2/app/preferences") {
                "HTTP/1.1 200 OK\r\n\r\n{\"listen_port\": 40000}"
            } else if request.contains("/api/v2/app/setPreferences") {
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            } else {
                "HTTP/1.1 404 Not Found\r\n\r\n"
            }
        })
    }

    /// A stub that answers each request with the next of `responses`, repeating
    /// the last one.
    ///
    /// For the paths where the client is supposed to *react* to a failure -- an
    /// expired session, a rejected write -- where routing by request would have
    /// to model a state machine the test is trying to provoke.
    pub fn scripted(responses: Vec<&'static str>) -> Self {
        let index = Arc::new(Mutex::new(0usize));
        Self::spawn(move |_| {
            let mut slot = index.lock().expect("mock mutex poisoned");
            let response = responses[(*slot).min(responses.len() - 1)];
            *slot += 1;
            response
        })
    }

    /// The listening stub every variant is built on: one accept loop, one
    /// shutdown flag, one place that records what came in.
    fn spawn<F>(respond: F) -> Self
    where
        F: Fn(&str) -> &'static str + Send + 'static,
    {
        use std::io::{Read, Write};
        use std::sync::atomic::Ordering;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("address").port();

        let log = Arc::new(RequestLog::default());
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let recorded = log.clone();
        let stop = done.clone();
        let handle = std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buffer = [0u8; 2048];
                    let read = stream.read(&mut buffer).unwrap_or(0);
                    if read == 0 {
                        continue;
                    }
                    let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                    recorded.record(&request);
                    let _ = stream.write_all(respond(&request).as_bytes());
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });

        Self {
            port,
            log,
            done,
            handle: Some(handle),
        }
    }

    /// The base URL to point a [`crate::config::QBittorrentConfig`] at.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// The request targets received, in order.
    pub fn paths(&self) -> Vec<String> {
        self.log.paths()
    }

    /// The raw `setPreferences` request last received, empty if none was.
    pub fn last_set_preferences(&self) -> String {
        self.log.last_set_preferences()
    }
}

impl Drop for MockQBittorrentWebUi {
    fn drop(&mut self) {
        self.done.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A WebUI address with nothing listening on it, so a push fails immediately
/// with a connection refusal instead of waiting out a timeout. Port 1 is
/// reserved and never bindable by an unprivileged service.
pub fn unreachable_qbittorrent_url() -> String {
    "http://127.0.0.1:1".to_string()
}

/// Whether tests run as root. Directory-permission tricks do not fail for
/// root, so tests that rely on them must skip instead of asserting.
pub fn running_as_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() == "0")
        .unwrap_or(false)
}

/// Whether `curl` is available, which the qBittorrent client shells out to.
///
/// Tests that reach the WebUI skip themselves when it is absent rather than
/// reporting a failure that says nothing about the code under test.
pub fn curl_available() -> bool {
    std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_ok()
}
