//! A progress indicator for CLI commands that block.
//!
//! `neutron lockdown enable` goes through `pkexec` and then a batched
//! `firewall-cmd` run, which can sit for a while on a password prompt. Without
//! anything on screen that reads as a hung process rather than a slow one.
//!
//! Animation only when stderr is a terminal: piped or captured output gets a
//! plain line instead, so CI logs and the system tests' captured output stay
//! free of control characters.

use crate::error::AppResult;

use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Braille spinner frames, the same set `cargo` uses.
pub const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const TICK: Duration = Duration::from_millis(80);

/// The frame to show for an animation that began `elapsed` ago.
///
/// Derived from the clock rather than a frame counter, so it is correct at any
/// refresh rate and needs no extra state to advance. Shared by the CLI spinner
/// and the TUI overlays so one set of frames defines "busy" everywhere.
pub fn spinner_frame(elapsed: Duration) -> &'static str {
    SPINNER_FRAMES[(elapsed.as_millis() / TICK.as_millis()) as usize % SPINNER_FRAMES.len()]
}

/// Run `work` behind a spinner labelled `label`, returning exactly what it
/// returns.
///
/// The label is printed before the wait, never after, so the user sees
/// something the moment they hit enter. `work` runs on the calling thread: only
/// the animation moves to a background one, and it is stopped and joined before
/// this returns so it cannot interleave with the caller's own output.
pub fn with_spinner<T>(label: &str, work: impl FnOnce() -> AppResult<T>) -> AppResult<T> {
    if !std::io::stderr().is_terminal() {
        eprintln!("{label}...");
        return work();
    }

    eprint!("{label} ");
    let _ = std::io::stderr().flush();

    let stop = Arc::new(AtomicBool::new(false));
    let animation = {
        let stop = Arc::clone(&stop);
        let label = label.to_string();
        std::thread::spawn(move || {
            for frame in SPINNER_FRAMES {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                eprint!("\r{label} {frame}");
                let _ = std::io::stderr().flush();
                std::thread::sleep(TICK);
            }
        })
    };

    let result = work();

    stop.store(true, Ordering::Relaxed);
    let _ = animation.join();
    // Erase the line the spinner left behind, so the result reads cleanly.
    eprint!("\r\x1b[2K");
    let _ = std::io::stderr().flush();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_frame_advances_with_the_clock_and_never_leaves_the_set() {
        // Clock-derived, so it cannot depend on how often the UI redraws.
        let mut seen = std::collections::BTreeSet::new();
        for ms in 0..2_000u64 {
            let frame = spinner_frame(Duration::from_millis(ms));
            assert!(
                SPINNER_FRAMES.contains(&frame),
                "{frame} is not one of the frames"
            );
            seen.insert(frame);
        }
        assert!(
            seen.len() > 1,
            "two seconds must cycle through more than one frame"
        );
    }

    #[test]
    fn animation_is_skipped_when_stderr_is_not_a_terminal() {
        // Under `cargo test` stderr is captured, so this exercises the plain
        // branch. It is the one CI and the system tests rely on: escape codes in
        // captured output would corrupt the test log.
        assert!(
            !std::io::stderr().is_terminal(),
            "the test harness is expected to capture stderr"
        );
        let r: AppResult<()> = with_spinner("Label", || Ok(()));
        assert!(r.is_ok());
    }

    #[test]
    fn the_result_passes_through_and_the_work_runs_once() {
        // The one thing that must not break: a spinner that ran the work twice,
        // swallowed an error, or reordered the result would be far worse than
        // the silence it replaces.
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let value = with_spinner("doing a thing", || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(42)
        })
        .expect("success should pass through");
        assert_eq!(value, 42);
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        let failure: AppResult<()> = with_spinner("doing a thing", || {
            calls.fetch_add(1, Ordering::Relaxed);
            Err(crate::error::AppError::NoEligibleProfile)
        });
        assert!(matches!(
            failure,
            Err(crate::error::AppError::NoEligibleProfile)
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }
}
