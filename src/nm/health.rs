//! Verifying that a freshly activated tunnel actually completed a handshake.
//!
//! `nmcli connection up` succeeding means NetworkManager created the interface
//! and installed the routes -- not that the WireGuard handshake completed. A
//! profile whose peer is unreachable activates perfectly happily, and because a
//! full tunnel owns the default route, every packet then disappears into it.
//! The user sees "Connected" and total loss of connectivity.
//!
//! `/proc/net/dev` exposes authenticated receive traffic without the privileges
//! required by `wg show latest-handshakes`. Treat RX as a nonzero latch on a
//! freshly created interface, not a rate: an established idle tunnel may never
//! receive another packet. Sampling only after activation can miss the initial
//! response. Third-party reachability probes cannot establish tunnel health.
//!
//! Zero RX alone does not establish failure for an on-demand tunnel: without
//! keepalive or user traffic, no handshake need have been attempted. Activation
//! only uses this probe to trigger teardown when endpoint and keepalive settings
//! indicate that the tunnel initiates a handshake automatically (BUG-034).

use std::thread;
use std::time::Duration;

use crate::nm::network_info;

/// Delay between samples.
const PROBE_INTERVAL: Duration = Duration::from_millis(500);

/// How long to wait for the peer to answer before declaring the tunnel dead.
///
/// Covers three of WireGuard's five-second handshake retry intervals.
const PROBE_WINDOW: Duration = Duration::from_secs(15);

/// Number of samples taken across [`PROBE_WINDOW`].
const PROBE_ATTEMPTS: u32 = PROBE_WINDOW.as_millis() as u32 / PROBE_INTERVAL.as_millis() as u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelHealth {
    /// The peer answered: authenticated traffic arrived on the interface.
    Handshaken,
    /// Nothing authenticated arrived within the probe window.
    NoHandshake,
}

impl TunnelHealth {
    pub fn is_healthy(self) -> bool {
        self == TunnelHealth::Handshaken
    }
}

/// Decide whether the peer answered, from injected samples.
///
/// Split from [`probe`] so the decision is unit-testable without a network:
/// `rx_bytes` stands in for the interface's receive counter. Returns as soon as
/// the counter moves, so a live tunnel costs one sample rather than the full
/// window.
pub fn probe_with<R>(attempts: u32, mut rx_bytes: R) -> TunnelHealth
where
    R: FnMut() -> u64,
{
    for _ in 0..attempts {
        if rx_bytes() > 0 {
            return TunnelHealth::Handshaken;
        }
    }
    TunnelHealth::NoHandshake
}

/// Whether `interface` already exists, sampled *before* activation.
///
/// An absent interface is the ordinary case and the only one that can be
/// verified: its counter is about to start from zero, so any growth is this
/// session's handshake. An interface that is already present carries traffic
/// from an activation that is not the one being checked, and [`probe`] must not
/// be pointed at it.
pub fn interface_exists(interface: &str) -> bool {
    network_info::interface_receive_bytes(interface).is_some()
}

/// Wait for the peer behind a freshly created `interface` to answer.
pub fn probe(interface: &str) -> TunnelHealth {
    probe_with(PROBE_ATTEMPTS, || {
        thread::sleep(PROBE_INTERVAL);
        network_info::interface_receive_bytes(interface).unwrap_or(0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_authenticated_byte_means_the_peer_answered() {
        // Measured against a real peer: the handshake response alone is
        // accounted as 92 bytes, and that is the whole signal.
        let health = probe_with(PROBE_ATTEMPTS, || 92);

        assert_eq!(health, TunnelHealth::Handshaken);
    }

    #[test]
    fn a_counter_that_never_moves_is_reported_dead() {
        // Regression: a profile whose peer never answers activates cleanly and
        // then swallows every packet, because the full tunnel owns the default
        // route. That must be detected, not reported as "Connected".
        let health = probe_with(PROBE_ATTEMPTS, || 0);

        assert_eq!(health, TunnelHealth::NoHandshake);
    }

    #[test]
    fn an_idle_tunnel_that_handshook_once_stays_healthy() {
        // Regression for the disconnect bug: an established tunnel carrying no
        // user traffic never moves its counter again, so requiring *growth*
        // rather than a non-zero latch declared healthy tunnels dead. One
        // handshake is enough, forever.
        let mut samples = 0;
        let health = probe_with(PROBE_ATTEMPTS, || {
            samples += 1;
            92 // Never grows: exactly what a real idle tunnel does.
        });

        assert_eq!(health, TunnelHealth::Handshaken);
        assert_eq!(samples, 1, "a live tunnel must short-circuit");
    }

    #[test]
    fn the_probe_window_covers_several_handshake_retries() {
        // WireGuard retries an unanswered handshake every 5s. A window that did
        // not span several retries would call a slow-but-live peer dead.
        assert!(
            PROBE_WINDOW >= Duration::from_secs(15),
            "the window must cover at least three handshake retries"
        );

        let mut samples = 0;
        let health = probe_with(PROBE_ATTEMPTS, || {
            samples += 1;
            0
        });

        assert_eq!(health, TunnelHealth::NoHandshake);
        assert_eq!(samples, PROBE_ATTEMPTS as i32);
    }

    #[test]
    fn only_a_handshake_counts_as_healthy() {
        assert!(TunnelHealth::Handshaken.is_healthy());
        assert!(!TunnelHealth::NoHandshake.is_healthy());
    }

    #[test]
    fn the_probe_never_depends_on_a_third_party_host() {
        // Regression: the probe used to accept `ping 1.1.1.1` as a liveness
        // signal, so filtered ICMP or an unreachable third party disconnected a
        // perfectly healthy tunnel. `probe_with` takes exactly one closure --
        // this tunnel's own counter -- and reintroducing another signal breaks
        // this call.
        let health = probe_with(1, || 1);

        assert_eq!(health, TunnelHealth::Handshaken);
    }
}
