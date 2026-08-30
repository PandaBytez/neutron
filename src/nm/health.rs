//! Verifying that a freshly activated tunnel actually carries traffic.
//!
//! `nmcli connection up` succeeding means NetworkManager created the interface
//! and installed the routes -- not that the WireGuard handshake completed. A
//! profile whose peer is unreachable activates perfectly happily, and because a
//! full tunnel owns the default route, every packet then disappears into it.
//! The user sees "Connected" and total loss of connectivity.
//!
//! So activation is followed by a short probe. Two independent signals are
//! accepted, and either one is enough:
//!
//! * the interface's **receive counter** moving, which means decrypted packets
//!   are arriving, and
//! * a **reachability probe** succeeding, which means traffic is getting out and
//!   back through the tunnel that now owns the default route.
//!
//! Requiring only one of the two is deliberate. A false negative here
//! disconnects a working VPN, which is far worse than a slow failure, so the
//! probe errs toward declaring the tunnel healthy: an idle-but-working tunnel
//! still answers a probe, and a busy one moves its counter even if ICMP is
//! filtered. Only when *nothing* comes back by either measure is the tunnel
//! reported dead.

use std::thread;
use std::time::Duration;

use crate::nm::network_info;

/// How many times the tunnel is sampled before giving up.
const PROBE_ATTEMPTS: u32 = 6;

/// Delay between samples. `PROBE_ATTEMPTS * PROBE_INTERVAL` is the worst-case
/// wait added to a connect, so it is kept short enough not to feel like a hang
/// while still allowing for a handshake plus a round trip.
const PROBE_INTERVAL: Duration = Duration::from_millis(700);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelHealth {
    /// Traffic was observed; the tunnel is carrying packets.
    Healthy,
    /// Nothing arrived by either measure within the probe window.
    NoTraffic,
}

impl TunnelHealth {
    pub fn is_healthy(self) -> bool {
        self == TunnelHealth::Healthy
    }
}

/// Decide whether a tunnel is alive from injected samples.
///
/// Split from [`probe`] so the decision is unit-testable without a network: the
/// closures stand in for the receive counter and the reachability probe.
/// Returns as soon as either signal is positive, so a healthy tunnel costs one
/// sample rather than the full window.
pub fn probe_with<R, P>(
    attempts: u32,
    baseline_rx: u64,
    mut rx_bytes: R,
    mut reachable: P,
) -> TunnelHealth
where
    R: FnMut() -> u64,
    P: FnMut() -> bool,
{
    for _ in 0..attempts {
        if rx_bytes() > baseline_rx {
            return TunnelHealth::Healthy;
        }
        if reachable() {
            return TunnelHealth::Healthy;
        }
    }
    TunnelHealth::NoTraffic
}

/// Probe the live tunnel on `interface`.
///
/// The baseline is taken before sampling so only packets that arrive *after*
/// activation count; a counter left over from a previous activation of the same
/// interface name cannot make a dead tunnel look alive.
pub fn probe(interface: &str) -> TunnelHealth {
    let baseline = network_info::read_interface_bytes(Some(interface)).0;

    probe_with(
        PROBE_ATTEMPTS,
        baseline,
        || {
            thread::sleep(PROBE_INTERVAL);
            network_info::read_interface_bytes(Some(interface)).0
        },
        || network_info::sample_latency().is_some(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_moving_receive_counter_means_the_tunnel_is_alive() {
        let mut rx = 0;
        let health = probe_with(
            6,
            0,
            || {
                rx += 500;
                rx
            },
            || false,
        );

        assert_eq!(health, TunnelHealth::Healthy);
    }

    #[test]
    fn a_successful_reachability_probe_means_the_tunnel_is_alive() {
        // A tunnel can be working while its counter is briefly still, so the
        // probe alone must be enough.
        let health = probe_with(6, 0, || 0, || true);

        assert_eq!(health, TunnelHealth::Healthy);
    }

    #[test]
    fn no_traffic_by_either_measure_is_reported_dead() {
        // Regression: a profile whose peer never answers activates cleanly and
        // then swallows every packet, because the full tunnel owns the default
        // route. That must be detected, not reported as "Connected".
        let health = probe_with(6, 0, || 0, || false);

        assert_eq!(health, TunnelHealth::NoTraffic);
    }

    #[test]
    fn counters_left_over_from_a_previous_activation_do_not_count() {
        // The interface name is reused across activations, so a stale counter
        // must not make a dead tunnel look alive. Only growth past the baseline
        // counts.
        let health = probe_with(6, 4_096, || 4_096, || false);

        assert_eq!(health, TunnelHealth::NoTraffic);
    }

    #[test]
    fn a_healthy_tunnel_is_not_probed_for_the_whole_window() {
        // The wait is added to every connect, so a working tunnel must return
        // on the first positive sample rather than always costing the full
        // window.
        let mut samples = 0;
        let health = probe_with(
            6,
            0,
            || {
                samples += 1;
                1_000
            },
            || false,
        );

        assert_eq!(health, TunnelHealth::Healthy);
        assert_eq!(samples, 1, "a live tunnel must short-circuit");
    }

    #[test]
    fn the_probe_window_is_bounded() {
        let mut samples = 0;
        let health = probe_with(
            PROBE_ATTEMPTS,
            0,
            || {
                samples += 1;
                0
            },
            || false,
        );

        assert_eq!(health, TunnelHealth::NoTraffic);
        assert_eq!(samples, PROBE_ATTEMPTS as i32);
        assert!(
            PROBE_ATTEMPTS * PROBE_INTERVAL.as_millis() as u32 <= 5_000,
            "the worst-case wait added to a connect must stay under 5s"
        );
    }
}
