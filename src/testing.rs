//! Shared test utilities.
//!
//! This module is intentionally exposed unconditionally (not behind `#[cfg(test)]`
//! or a feature flag) so that integration tests under `tests/`, which compile
//! against this crate as an external library, can reuse the same mock as the
//! in-crate unit tests. Everything here is `pub`, so it never triggers
//! dead-code warnings in normal builds.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::error::{AppError, AppResult};
use crate::nm::{NmClient, WireguardProfile};

/// A configurable in-memory [`NmClient`] for tests.
///
/// Recorded-call state lives behind `Arc<Mutex<_>>`, so clones share the same
/// history. This keeps the mock `Clone + Send + 'static` (as required by the GUI
/// code paths) while still letting a clone handed to background work report its
/// calls back to the original handle.
#[derive(Clone, Default)]
pub struct MockNmClient {
    profiles: Vec<WireguardProfile>,
    fail_list: bool,
    fail_ids: HashSet<String>,
    fail_kill_switch: bool,
    calls: Arc<Mutex<Vec<String>>>,
    attempted: Arc<Mutex<Vec<String>>>,
    connected: Arc<Mutex<Vec<String>>>,
    kill_switch_calls: Arc<Mutex<Vec<String>>>,
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

    /// Every operation in invocation order, formatted as `connect:<id>`,
    /// `switch:<id>`, or `disconnect`.
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("mock mutex poisoned").clone()
    }

    /// Profile ids passed to `connect`, regardless of success.
    pub fn attempted_profiles(&self) -> Vec<String> {
        self.attempted.lock().expect("mock mutex poisoned").clone()
    }

    /// Profile ids that `connect` reported as successfully connected.
    pub fn connected_profiles(&self) -> Vec<String> {
        self.connected.lock().expect("mock mutex poisoned").clone()
    }

    /// Global kill-switch toggles in invocation order, formatted as
    /// `kill-switch-all:on` or `kill-switch-all:off`.
    pub fn kill_switch_calls(&self) -> Vec<String> {
        self.kill_switch_calls
            .lock()
            .expect("mock mutex poisoned")
            .clone()
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
        self.calls
            .lock()
            .expect("mock mutex poisoned")
            .push(format!("connect:{profile_identifier}"));
        self.attempted
            .lock()
            .expect("mock mutex poisoned")
            .push(profile_identifier.to_string());

        if self.fail_ids.contains(profile_identifier) {
            return Err(AppError::NmCommandFailed(format!(
                "simulated failure for {profile_identifier}"
            )));
        }

        self.connected
            .lock()
            .expect("mock mutex poisoned")
            .push(profile_identifier.to_string());
        Ok(())
    }

    fn disconnect_active(&self) -> AppResult<()> {
        self.calls
            .lock()
            .expect("mock mutex poisoned")
            .push("disconnect".to_string());
        Ok(())
    }

    fn switch_to(&self, profile_identifier: &str) -> AppResult<()> {
        self.calls
            .lock()
            .expect("mock mutex poisoned")
            .push(format!("switch:{profile_identifier}"));
        Ok(())
    }

    fn set_kill_switch_all(&self, enable: bool) -> AppResult<()> {
        self.kill_switch_calls
            .lock()
            .expect("mock mutex poisoned")
            .push(format!(
                "kill-switch-all:{}",
                if enable { "on" } else { "off" }
            ));

        if self.fail_kill_switch {
            return Err(AppError::NmCommandFailed(
                "simulated kill-switch failure".to_string(),
            ));
        }

        Ok(())
    }
}
