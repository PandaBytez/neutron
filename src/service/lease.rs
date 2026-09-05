//! The forwarded-port lease, published by the daemon and read by the TUI.
//!
//! A NAT-PMP lease is not a fact you can look up; it is state with a lifetime.
//! It belongs to one tunnel, expires on its own, and has to be renewed on a
//! timer or the provider reclaims the port. Exactly one process can own that
//! timer, and it has to be one that outlives any particular session -- so it is
//! the tray daemon, not the TUI.
//!
//! The TUI used to keep its own copy: it asked the gateway for a mapping of its
//! own and pushed its own result to qBittorrent. That meant two renewers racing
//! on one lease, two writers against one qBittorrent instance, and a blocking
//! UDP round trip on the render thread. It also could not stay correct, because
//! it only ever asked once per tunnel change while the daemon kept re-leasing
//! underneath it.
//!
//! So the daemon publishes what it holds here and the TUI reads it. A file under
//! `$XDG_RUNTIME_DIR` rather than a D-Bus property because the daemon's
//! well-known name carries the standard `org.kde.StatusNotifierItem` interface,
//! which is not ours to extend, and because a file needs no async plumbing in a
//! reader that otherwise makes no bus calls.
//!
//! Exactly one daemon may publish here, which the file enforces itself: each
//! publication carries its author's pid, and a daemon that finds a *live*
//! stranger already holding the lease stands down. That matters because the
//! usual singleton check,
//! [`crate::service::indicator::is_indicator_running`], asks the session bus --
//! and when there is no session bus it cannot answer, which is exactly when
//! several daemons get spawned.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// How long a published lease stays believable.
///
/// Tied to the lease's own lifetime rather than to the daemon's poll interval,
/// because that is what the timestamp actually tells you: a mapping the gateway
/// has not been asked to renew within [`crate::portforward::LIFETIME`] has
/// expired regardless of whether the daemon is alive to say so.
///
/// Deliberately not `POLL_INTERVAL` plus a small margin. A poll can block for a
/// long time before it republishes -- NAT-PMP alone can spend two 3s timeouts,
/// and a qBittorrent push several 5s ones -- so a tight window would report a
/// merely slow daemon as a dead one, at exactly the moment the user is trying to
/// work out why port forwarding is misbehaving.
pub const STALE_AFTER: Duration = Duration::from_secs(crate::portforward::LIFETIME as u64);

/// How far ahead of the reader's clock a timestamp may sit before it is read as
/// a clock disagreement rather than as a fresh publication.
///
/// Wall time is the only clock two processes can share, and it can step. A
/// backwards step leaves timestamps written before it sitting in the reader's
/// future; without a bound here those would stay "fresh" for the whole size of
/// the step, which is precisely when nothing is renewing the lease.
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(5);

/// What became of the last attempt to push the forwarded port to qBittorrent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QbitSyncStatus {
    /// Nothing has been offered to qBittorrent for the current lease.
    #[default]
    Pending,
    /// qBittorrent accepted the current forwarded port.
    Synchronized,
    /// The last push was rejected or the WebUI could not be reached.
    Failed,
}

/// The forwarded port the daemon currently holds, and what it did with it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LeaseState {
    /// The port the gateway mapped, if a lease is held at all.
    pub port: Option<u16>,
    /// The profile the lease belongs to. A lease is only meaningful together
    /// with its tunnel, so the two are published as one value.
    pub profile_uuid: Option<String>,
    /// The verdict on the last push to qBittorrent.
    pub qbit_sync: QbitSyncStatus,
    /// Seconds since the Unix epoch when the daemon last wrote this. Doubles as
    /// the daemon's heartbeat -- see [`STALE_AFTER`].
    pub updated_at: u64,
    /// The pid of the daemon that wrote this.
    ///
    /// Identifies the owner, so a second daemon can stand down rather than
    /// fight over the file, and gives liveness that owes nothing to a clock: a
    /// daemon that is simply gone is known immediately instead of after
    /// [`STALE_AFTER`]. Defaulted so a file written before this existed still
    /// parses, and zero is read as "unknown" rather than as a dead process.
    #[serde(default)]
    pub publisher_pid: u32,
}

impl LeaseState {
    /// Whether this was published recently enough to still describe reality.
    ///
    /// Bounded on both sides. Too old means the lease has expired at the gateway;
    /// too far *ahead* means the two clocks disagree, and a timestamp that cannot
    /// be compared is no evidence that anything is still being renewed.
    pub fn is_fresh(&self) -> bool {
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return false;
        };
        let now = now.as_secs();

        if self.updated_at > now {
            return self.updated_at - now <= MAX_CLOCK_SKEW.as_secs();
        }
        now - self.updated_at < STALE_AFTER.as_secs()
    }

    /// Whether the daemon that published this is still running.
    pub fn is_publisher_alive(&self) -> bool {
        // Zero means the publisher did not say, so there is nothing to disprove.
        self.publisher_pid == 0 || is_process_alive(self.publisher_pid)
    }
}

/// Whether `pid` names a process that is still running.
///
/// Fails open. When the answer cannot be established -- no `/proc`, as in some
/// sandboxes -- the process is reported alive, so the lease falls back to being
/// judged on its timestamp. Missing evidence is not evidence of death, and
/// getting that backwards would silently disable the port display everywhere
/// `/proc` is not mounted.
fn is_process_alive(pid: u32) -> bool {
    let proc = std::path::Path::new("/proc");
    if !proc.join("self").exists() {
        return true;
    }
    proc.join(pid.to_string()).exists()
}

/// Where the daemon publishes the lease.
///
/// `$XDG_RUNTIME_DIR` is the right home: it is per-user, already mode 0700, and
/// cleared on logout, so a lease can never outlive the session that held it.
///
/// `None` when there is no runtime directory, which is a real answer rather than
/// a reason to fall back to `/tmp`. A shared `/tmp` would have the first user to
/// run Neutron create the directory, leaving every other user's daemon unable to
/// publish into it -- and since publishing is best effort, their TUI would report
/// the daemon missing for as long as that lasted, with nothing pointing at why.
pub fn path() -> Option<PathBuf> {
    Some(dirs::runtime_dir()?.join("neutron").join("lease.json"))
}

/// Publish `state`, stamping it with the current time.
///
/// Best effort and infallible: this runs on every daemon poll, and failing to
/// tell the TUI about a lease must never take down the loop that renews it.
pub fn publish(state: &LeaseState) {
    let Some(path) = path() else {
        return;
    };
    publish_to(&path, state);
}

/// The lease the daemon currently holds, or `None` when it is not publishing
/// one -- no file, unreadable, outside the window in [`LeaseState::is_fresh`],
/// or written by a process that has since exited.
///
/// A lease left behind is reported as absent rather than as its last contents,
/// so a daemon that died cannot leave the TUI advertising a port nothing is
/// renewing.
pub fn read() -> Option<LeaseState> {
    read_from(&path()?)
}

/// The pid of the daemon currently publishing the lease, if one is.
pub fn live_owner() -> Option<u32> {
    live_owner_of(&path()?)
}

/// [`publish`] to an explicit path.
///
/// Stands down when a *live* daemon other than this process already owns the
/// file, so several daemons cannot take turns overwriting each other and leave
/// the TUI watching the port flap.
///
/// Split out from [`publish`] so the round trip can be exercised against a
/// temporary file. A test that wrote to [`path`] would clobber the lease of a
/// daemon actually running on the developer's machine.
pub fn publish_to(path: &std::path::Path, state: &LeaseState) {
    let own_pid = std::process::id();
    if live_owner_of(path).is_some_and(|owner| owner != own_pid) {
        return;
    }

    let stamped = LeaseState {
        updated_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or(0),
        publisher_pid: own_pid,
        ..state.clone()
    };

    if let Ok(body) = serde_json::to_string(&stamped) {
        // Atomic, because the TUI reads this file while the daemon rewrites it.
        let _ = crate::config::write_atomically(path, &body);
    }
}

/// [`read`] from an explicit path.
pub fn read_from(path: &std::path::Path) -> Option<LeaseState> {
    let body = std::fs::read_to_string(path).ok()?;
    let state: LeaseState = serde_json::from_str(&body).ok()?;
    (state.is_fresh() && state.is_publisher_alive()).then_some(state)
}

/// [`live_owner`] for an explicit path.
pub fn live_owner_of(path: &std::path::Path) -> Option<u32> {
    // Reuses `read_from`, so a lease that is stale or whose author is gone is
    // not treated as an owner -- otherwise a crashed daemon would lock every
    // successor out of the file it left behind.
    let state = read_from(path)?;
    (state.publisher_pid != 0).then_some(state.publisher_pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the epoch")
            .as_secs()
    }

    fn held_at(updated_at: u64) -> LeaseState {
        LeaseState {
            port: Some(51820),
            profile_uuid: Some("uuid-eu".to_string()),
            qbit_sync: QbitSyncStatus::Synchronized,
            updated_at,
            publisher_pid: std::process::id(),
        }
    }

    fn temp_lease_path(label: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!("neutron-lease-test-{label}-{}", now_secs()))
            .join("lease.json")
    }

    #[test]
    fn a_just_written_lease_is_fresh() {
        assert!(held_at(now_secs()).is_fresh());
    }

    #[test]
    fn a_lease_older_than_its_own_lifetime_is_not_fresh() {
        // The gateway reclaims a mapping that goes unrenewed for this long, so
        // the port is gone whether or not the daemon is still alive.
        assert!(!held_at(now_secs() - STALE_AFTER.as_secs() - 1).is_fresh());
    }

    #[test]
    fn a_lease_from_the_readers_future_is_not_fresh() {
        // Regression: this was compared with a saturating subtraction, which
        // yields zero for any future stamp and so read as maximally fresh. A
        // backwards clock step therefore pinned the lease as valid for the whole
        // size of the step -- exactly when nothing was renewing it.
        let far_ahead = held_at(now_secs() + STALE_AFTER.as_secs() * 10);

        assert!(
            !far_ahead.is_fresh(),
            "a timestamp that cannot be compared is not evidence of a live lease"
        );
    }

    #[test]
    fn a_lease_a_moment_ahead_is_still_fresh() {
        // Two processes stamping either side of a second boundary must not make
        // the reader declare the daemon dead.
        assert!(held_at(now_secs() + 1).is_fresh());
    }

    #[test]
    fn a_published_lease_reads_back_through_the_filesystem() {
        let path = temp_lease_path("roundtrip");

        publish_to(&path, &held_at(0));
        let read = read_from(&path).expect("a just-published lease must be readable");

        assert_eq!(read.port, Some(51820));
        assert_eq!(read.profile_uuid.as_deref(), Some("uuid-eu"));
        assert_eq!(read.qbit_sync, QbitSyncStatus::Synchronized);
        assert!(
            read.updated_at > 0,
            "publishing must stamp the time, not carry the caller's placeholder"
        );

        let _ = std::fs::remove_dir_all(path.parent().expect("path has a parent"));
    }

    #[test]
    fn a_lease_left_behind_by_a_dead_daemon_reads_as_absent() {
        // The whole design rests on this: a port on screen must mean a port
        // someone is still renewing.
        let path = temp_lease_path("stale");
        write_raw(&path, &held_at(now_secs() - STALE_AFTER.as_secs() - 1));

        assert!(read_from(&path).is_none());

        let _ = std::fs::remove_dir_all(path.parent().expect("path has a parent"));
    }

    #[test]
    fn a_missing_or_corrupt_lease_reads_as_absent_rather_than_panicking() {
        let path = temp_lease_path("corrupt");
        assert!(read_from(&path).is_none(), "no file means no lease");

        std::fs::create_dir_all(path.parent().expect("path has a parent")).expect("temp dir");
        std::fs::write(&path, "{ not json").expect("should write");
        assert!(read_from(&path).is_none(), "unparsable means no lease");

        let _ = std::fs::remove_dir_all(path.parent().expect("path has a parent"));
    }

    /// A pid that is certainly not running. Beyond any plausible `pid_max`, so
    /// it cannot be recycled onto a live process mid-test.
    const DEAD_PID: u32 = u32::MAX;

    #[test]
    fn publishing_stamps_the_authors_pid() {
        let path = temp_lease_path("pid-stamp");

        publish_to(&path, &held_at(0));

        let read = read_from(&path).expect("should read back");
        assert_eq!(read.publisher_pid, std::process::id());
        assert_eq!(live_owner_of(&path), Some(std::process::id()));

        let _ = std::fs::remove_dir_all(path.parent().expect("path has a parent"));
    }

    /// A pid that is certainly running and is certainly not this process. On
    /// Linux pid 1 always exists.
    const OTHER_LIVE_PID: u32 = 1;

    /// Write `state` verbatim, bypassing the ownership guard and the pid stamp
    /// in [`publish_to`], so a test can set up a file as some other process.
    fn write_raw(path: &std::path::Path, state: &LeaseState) {
        std::fs::create_dir_all(path.parent().expect("path has a parent")).expect("temp dir");
        std::fs::write(
            path,
            serde_json::to_string(state).expect("should serialize"),
        )
        .expect("should write");
    }

    #[test]
    fn a_second_daemon_does_not_overwrite_a_live_owners_lease() {
        // Without a session bus the usual singleton check cannot answer, so
        // several daemons get spawned. They must not then take turns rewriting
        // this file, which the TUI would render as the port flapping.
        let path = temp_lease_path("two-daemons");
        write_raw(
            &path,
            &LeaseState {
                publisher_pid: OTHER_LIVE_PID,
                ..held_at(now_secs())
            },
        );

        publish_to(
            &path,
            &LeaseState {
                port: Some(9999),
                ..held_at(0)
            },
        );

        assert_eq!(
            live_owner_of(&path),
            Some(OTHER_LIVE_PID),
            "ownership must stay with the daemon that already holds it"
        );
        assert_eq!(
            read_from(&path).expect("lease survives").port,
            Some(51820),
            "the incumbent's port must be the one still published"
        );

        let _ = std::fs::remove_dir_all(path.parent().expect("path has a parent"));
    }

    #[test]
    fn a_lease_from_a_process_that_exited_reads_as_absent() {
        // The daemon is the only thing renewing the mapping, so once it is gone
        // the port is gone -- known immediately from the pid rather than only
        // after the timestamp ages out.
        let path = temp_lease_path("dead-publisher");
        let orphan = LeaseState {
            publisher_pid: DEAD_PID,
            ..held_at(now_secs())
        };
        write_raw(&path, &orphan);

        assert!(
            read_from(&path).is_none(),
            "a fresh timestamp does not make a dead daemon's lease current"
        );

        let _ = std::fs::remove_dir_all(path.parent().expect("path has a parent"));
    }

    #[test]
    fn a_crashed_daemon_does_not_lock_its_successor_out() {
        // The file it left behind names a pid that is gone, so it confers no
        // ownership; otherwise the lease would be unpublishable until reboot.
        let path = temp_lease_path("succession");
        let orphan = LeaseState {
            publisher_pid: DEAD_PID,
            ..held_at(now_secs())
        };
        write_raw(&path, &orphan);

        assert_eq!(live_owner_of(&path), None);

        publish_to(&path, &held_at(0));
        assert_eq!(live_owner_of(&path), Some(std::process::id()));

        let _ = std::fs::remove_dir_all(path.parent().expect("path has a parent"));
    }

    #[test]
    fn a_lease_written_before_pids_were_recorded_still_parses() {
        // Zero means the author did not say, which is not the same as claiming a
        // dead process -- such a lease must still be judged on its timestamp.
        let legacy = LeaseState {
            publisher_pid: 0,
            ..held_at(now_secs())
        };

        assert!(legacy.is_publisher_alive());
        assert!(legacy.is_fresh());
    }

    #[test]
    fn an_unheld_lease_round_trips_as_absent_rather_than_zero() {
        // Port 0 is what NAT-PMP returns when nothing was mapped, so "no lease"
        // must stay distinguishable from it on the wire.
        let body = serde_json::to_string(&LeaseState::default()).expect("should serialize");
        let parsed: LeaseState = serde_json::from_str(&body).expect("should parse");

        assert_eq!(parsed.port, None);
        assert_eq!(parsed.qbit_sync, QbitSyncStatus::Pending);
    }
}
