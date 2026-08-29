//! Shared test utilities.
//!
//! This module is intentionally exposed unconditionally (not behind `#[cfg(test)]`
//! or a feature flag) so that integration tests under `tests/`, which compile
//! against this crate as an external library, can reuse the same mock as the
//! in-crate unit tests. Everything here is `pub`, so it never triggers
//! dead-code warnings in normal builds.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{AppError, AppResult};
use crate::firewall::FirewallClient;
use crate::nm::{NmClient, ProfileState, WireguardProfile, WireguardTunnel};

fn record(log: &Mutex<Vec<String>>, entry: String) {
    log.lock().expect("mock mutex poisoned").push(entry);
}

fn snapshot(log: &Mutex<Vec<String>>) -> Vec<String> {
    log.lock().expect("mock mutex poisoned").clone()
}

/// Create a unique temporary path for test configuration files.
pub fn temp_config_path(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir()
        .join(format!("neutron-vpn-test-{label}-{suffix}"))
        .join("config.json")
}

/// Clean up temporary test configuration directories.
pub fn remove_temp_config(path: &Path) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::remove_dir_all(parent);
    }
}

/// Test helper to create a WireguardProfile.
pub fn profile(name: &str, uuid: &str, state: ProfileState) -> WireguardProfile {
    WireguardProfile {
        name: name.to_string(),
        uuid: uuid.to_string(),
        state,
    }
}

/// A configurable in-memory [`NmClient`] for tests.
///
/// Recorded-call state lives behind `Arc<Mutex<_>>`, so clones share the same
/// history. This keeps the mock `Clone + Send + 'static` (as required by the GUI
/// code paths) while still letting a clone handed to background work report its
/// calls back to the original handle.
#[derive(Clone, Default)]
pub struct MockNmClient {
    profiles: Vec<WireguardProfile>,
    tunnels: Vec<WireguardTunnel>,
    fail_list: bool,
    fail_ids: HashSet<String>,
    fail_kill_switch: bool,
    fail_autoconnect: bool,
    fail_lockdown: bool,
    fail_split_tunnel: bool,
    calls: Arc<Mutex<Vec<String>>>,
    attempted: Arc<Mutex<Vec<String>>>,
    connected: Arc<Mutex<Vec<String>>>,
    kill_switch_calls: Arc<Mutex<Vec<String>>>,
    autoconnect_calls: Arc<Mutex<Vec<String>>>,
    lockdown_calls: Arc<Mutex<Vec<String>>>,
    split_tunnel_calls: Arc<Mutex<Vec<String>>>,
    imported: Arc<Mutex<Vec<String>>>,
}

impl MockNmClient {
    /// A mock that returns the given profiles and succeeds for every operation.
    pub fn new(profiles: Vec<WireguardProfile>) -> Self {
        Self {
            profiles,
            ..Self::default()
        }
    }

    /// A mock whose `list_wireguard_profiles` fails, to exercise error paths.
    pub fn failing_list() -> Self {
        Self {
            fail_list: true,
            ..Self::default()
        }
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

    /// Consume this mock and return one whose `enable_lockdown`/`disable_lockdown`
    /// fail, to exercise the error path where the firewall rejects the change.
    /// The attempt is still recorded in [`Self::lockdown_calls`] first.
    pub fn fail_lockdown(mut self) -> Self {
        self.fail_lockdown = true;
        self
    }

    /// Consume this mock and return one whose `apply_split_tunnel` fails.
    pub fn fail_split_tunnel(mut self) -> Self {
        self.fail_split_tunnel = true;
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

    /// Split tunnel invocations in order, formatted as `split-tunnel:<uuid>:<mode>:<v4_count>:<v6_count>`.
    pub fn split_tunnel_calls(&self) -> Vec<String> {
        snapshot(&self.split_tunnel_calls)
    }

    /// Paths passed to `import_wireguard_profile`, in invocation order.
    pub fn imported_paths(&self) -> Vec<String> {
        snapshot(&self.imported)
    }
}

impl NmClient for MockNmClient {
    fn list_wireguard_profiles(&self) -> AppResult<Vec<WireguardProfile>> {
        if self.fail_list {
            return Err(AppError::NmCommandFailed("simulated".to_string()));
        }
        Ok(self.profiles.clone())
    }

    fn connect(&self, profile_identifier: &str) -> AppResult<()> {
        record(&self.calls, format!("connect:{profile_identifier}"));
        record(&self.attempted, profile_identifier.to_string());

        if self.fail_ids.contains(profile_identifier) {
            return Err(AppError::NmCommandFailed(format!(
                "simulated failure for {profile_identifier}"
            )));
        }

        record(&self.connected, profile_identifier.to_string());
        Ok(())
    }

    fn disconnect_active(&self) -> AppResult<()> {
        record(&self.calls, "disconnect".to_string());
        Ok(())
    }

    fn switch_to(&self, profile_identifier: &str) -> AppResult<()> {
        record(&self.calls, format!("switch:{profile_identifier}"));
        Ok(())
    }

    fn set_kill_switch_all(&self, enable: bool) -> AppResult<()> {
        record(
            &self.kill_switch_calls,
            format!("kill-switch-all:{}", if enable { "on" } else { "off" }),
        );

        if self.fail_kill_switch {
            return Err(AppError::NmCommandFailed(
                "simulated kill-switch failure".to_string(),
            ));
        }

        Ok(())
    }

    fn set_autoconnect_all(&self, enable: bool) -> AppResult<()> {
        record(
            &self.autoconnect_calls,
            format!("autoconnect-all:{}", if enable { "on" } else { "off" }),
        );

        if self.fail_autoconnect {
            return Err(AppError::NmCommandFailed(
                "simulated autoconnect failure".to_string(),
            ));
        }

        Ok(())
    }

    fn wireguard_tunnels(&self) -> AppResult<Vec<WireguardTunnel>> {
        if self.fail_list {
            return Err(AppError::NmCommandFailed("simulated".to_string()));
        }
        Ok(self.tunnels.clone())
    }

    fn import_wireguard_profile(&self, path: &std::path::Path) -> AppResult<String> {
        record(&self.imported, path.display().to_string());
        Ok(format!("Imported {}", path.display()))
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
        })
    }

    fn tunnel_address(&self, _uuid: &str) -> Option<String> {
        Some("10.2.0.2/32".to_string())
    }

    fn edit_connection(&self, uuid: &str, _is_dark: bool) -> AppResult<()> {
        record(&self.calls, format!("edit:{}", uuid));
        Ok(())
    }

    fn delete_profile(&self, uuid: &str) -> AppResult<()> {
        record(&self.calls, format!("delete:{}", uuid));
        Ok(())
    }

    fn apply_split_tunnel(
        &self,
        uuid: &str,
        mode: crate::config::SplitTunnelMode,
        v4_routes: &[String],
        v6_routes: &[String],
    ) -> AppResult<()> {
        record(
            &self.split_tunnel_calls,
            format!(
                "split-tunnel:{}:{}:{}:{}",
                uuid,
                mode,
                v4_routes.len(),
                v6_routes.len()
            ),
        );

        if self.fail_split_tunnel {
            return Err(AppError::NmCommandFailed(
                "simulated split-tunnel failure".to_string(),
            ));
        }

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
            return Err(AppError::NmCommandFailed(
                "simulated split-tunnel failure".to_string(),
            ));
        }

        Ok(())
    }
}

impl FirewallClient for MockNmClient {
    fn enable_lockdown(&self, _tunnels: &[WireguardTunnel]) -> AppResult<()> {
        record(&self.lockdown_calls, "lockdown:on".to_string());

        if self.fail_lockdown {
            return Err(AppError::Firewall("simulated lockdown failure".to_string()));
        }

        Ok(())
    }

    fn disable_lockdown(&self) -> AppResult<()> {
        record(&self.lockdown_calls, "lockdown:off".to_string());

        if self.fail_lockdown {
            return Err(AppError::Firewall("simulated lockdown failure".to_string()));
        }

        Ok(())
    }
}
