//! Verifying that a freshly activated tunnel actually completed a handshake.
//!
//! `nmcli connection up` succeeding means NetworkManager created the interface
//! and installed the routes -- not that the WireGuard handshake completed. A
//! profile whose peer is unreachable activates perfectly happily, and because a
//! full tunnel owns the default route, every packet then disappears into it.
//! The user sees "Connected" and total loss of connectivity.
//!
//! # Why the receive counter is the handshake
//!
//! The native way to answer "did this tunnel handshake?" is
//! `wg show <interface> latest-handshakes`, which is what `wg-quick` and every
//! WireGuard monitoring tool read. It needs `CAP_NET_ADMIN`, so an unprivileged
//! desktop app cannot use it, and Neutron will not escalate privileges for a
//! status read.
//!
//! The interface's **receive byte counter** carries the same guarantee, and is
//! readable from `/proc/net/dev` by any user. WireGuard accounts a packet only
//! after it has been decrypted and authenticated, so a peer that never
//! completes a handshake can never move that counter -- no stray or hostile
//! traffic can forge it. Crucially the handshake *response itself* is
//! accounted, so the counter moves within milliseconds of the peer answering.
//!
//! Measured on two real WireGuard peers (`testing/`, two interfaces peered over
//! loopback):
//!
//! ```text
//! peer answers:       rx 0 -> 92 within ~0.3s, latest-handshakes set
//! peer never answers: rx 0 forever,            latest-handshakes 0
//! ```
//!
//! # Why the counter is only read once, from zero
//!
//! That same measurement showed an established but **idle** tunnel does not
//! move its receive counter at all -- it sat at 92 bytes across 30 seconds.
//! `PersistentKeepalive` does not help: it makes *us* send to the peer, and the
//! peer only sends back if it independently chose to configure a keepalive
//! toward us, which a VPN provider generally does not.
//!
//! So the counter must be treated as a **one-shot latch, baselined from before
//! the interface existed**, never as a rate. An earlier version baselined it
//! *after* activation -- capturing the handshake response it was meant to
//! detect -- and then demanded further growth that an idle tunnel never
//! produced. That left the decision to a `ping 1.1.1.1` fallback which depended
//! on a third party answering ICMP, on ICMP not being filtered along the path,
//! and on routes having converged in time. None of those are properties of this
//! tunnel, and the combination disconnected healthy tunnels roughly ten seconds
//! after connecting. There is no reachability probe any more.

use std::thread;
use std::time::Duration;

use crate::nm::network_info;

/// Delay between samples.
const PROBE_INTERVAL: Duration = Duration::from_millis(500);

/// How long to wait for the peer to answer before declaring the tunnel dead.
///
/// Sized against WireGuard's own handshake schedule rather than a round number:
/// the kernel retries an unanswered handshake every `REKEY_TIMEOUT` (5s), so
/// this window covers three attempts. A peer that has answered none of them is
/// not going to, while a peer that answers any of them moves the counter and
/// short-circuits within milliseconds.
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
/// be pointed at it -- see [`verify`] in `crate::nm`.
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
