//! Which package manager installed this binary, so `neutron uninstall` can hand
//! itself to the right one.
//!
//! Two channels are supported, matching the two documented installs: the
//! Homebrew tap formula and `cargo install`. Anything else is refused rather
//! than guessed at -- see [`resolve`].

use std::path::Path;
use std::time::Duration;

use crate::error::{AppError, AppResult};

/// Package name in every supported package manager.
const PACKAGE: &str = "neutron";
/// Both channels remove the package the same way; only the tool differs.
const UNINSTALL_ARGS: [&str; 2] = ["uninstall", PACKAGE];
/// `cargo install --list` is local bookkeeping, but give it room on a cold
/// `$CARGO_HOME` rather than failing a decision on a slow disk.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallChannel {
    Homebrew,
    Cargo,
    Unknown,
}

impl std::fmt::Display for InstallChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Homebrew => "Homebrew",
            Self::Cargo => "cargo",
            Self::Unknown => "unknown",
        })
    }
}

/// How to remove the install, once [`resolve`] has decided.
#[derive(Debug, Clone, Copy)]
pub struct Removal {
    pub channel: InstallChannel,
    pub program: &'static str,
    pub args: &'static [&'static str],
}

/// Resolve the install channel for the running binary, probing the real system.
pub fn current() -> AppResult<Removal> {
    let exe = std::env::current_exe()?;
    // A Homebrew install is decisive, so the cargo probe (a subprocess) is only
    // worth its cost when the path did not already answer the question.
    let cargo_list = if is_homebrew(&exe) {
        None
    } else {
        probe_cargo_list()
    };
    resolve(&exe, cargo_list.as_deref(), tool_on_path)
}

/// Decide how Neutron was installed, from two facts the caller supplies.
///
/// `cargo_list` is the stdout of `cargo install --list` (`None` when cargo is
/// missing or the probe failed) and `tool_on_path` answers "is this program
/// runnable". Both are injected, so this decision is unit-testable without a
/// subprocess, a `$PATH`, or an installed copy of Neutron.
///
/// Homebrew is recognized by path: the formula `cargo install`s into a Cellar
/// and symlinks it into the prefix, and `current_exe()` resolves that symlink.
/// The pair must be exactly `Cellar/neutron` so an unrelated Cellar that happens
/// to ship a `neutron` binary is not mistaken for a tap install.
///
/// Cargo is recognized by `cargo install --list` rather than by looking for
/// `~/.cargo/bin/neutron`, because `cargo install --root` puts the binary
/// anywhere while the package list still knows about it.
///
/// An unrecognized source, or a channel whose tool is not runnable, is an error:
/// Neutron's own state (firewall rules, root-owned helper, polkit action) would
/// otherwise be torn down with the package still installed, which is worse than
/// doing nothing. This runs before anything is removed for that reason.
pub fn resolve(
    exe: &Path,
    cargo_list: Option<&str>,
    tool_on_path: impl Fn(&str) -> bool,
) -> AppResult<Removal> {
    let channel = if is_homebrew(exe) {
        InstallChannel::Homebrew
    } else if cargo_has_package(cargo_list) {
        InstallChannel::Cargo
    } else {
        InstallChannel::Unknown
    };
    let program = match channel {
        InstallChannel::Homebrew => "brew",
        InstallChannel::Cargo => "cargo",
        InstallChannel::Unknown => {
            return Err(AppError::Uninstall(unrecognized(
                exe,
                "its path is not a Homebrew Cellar install and `cargo install --list` \
                 does not list it",
            )));
        }
    };
    if !tool_on_path(program) {
        return Err(AppError::Uninstall(unrecognized(
            exe,
            &format!(
                "it looks like a {channel} install, but `{program}` is not runnable here \
                 (an installed-from-desktop or stripped PATH is the usual cause)"
            ),
        )));
    }
    Ok(Removal {
        channel,
        program,
        args: &UNINSTALL_ARGS,
    })
}

pub fn is_homebrew(exe: &Path) -> bool {
    let components: Vec<_> = exe
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    components
        .windows(2)
        .any(|pair| pair[0] == "Cellar" && pair[1] == PACKAGE)
}

/// Whether `cargo install --list` output has a `neutron v…` entry. Anchored on
/// the version marker so a different package that merely starts with the same
/// name (`neutron-vpn`) cannot match.
fn cargo_has_package(cargo_list: Option<&str>) -> bool {
    cargo_list.is_some_and(|list| {
        list.lines().any(|line| {
            line.trim()
                .strip_prefix(PACKAGE)
                .is_some_and(|rest| rest.starts_with(" v"))
        })
    })
}

fn unrecognized(exe: &Path, detail: &str) -> String {
    format!(
        "cannot uninstall automatically: {detail}, so Neutron does not know which package \
         manager owns {}. Nothing was changed. Supported: a Homebrew tap install or \
         `cargo install`; anything else has to be removed by hand.",
        exe.display()
    )
}

fn probe_cargo_list() -> Option<String> {
    crate::process::run_with_timeout("cargo", &["install", "--list"], PROBE_TIMEOUT).ok()
}

fn tool_on_path(program: &str) -> bool {
    crate::process::host_command(program)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARGO_LIST: &str = "Installed packages:\n  neutron v0.1.3:\n    neutron\n";

    fn resolve_with(exe: &str, cargo_list: Option<&str>, tools: &[&str]) -> AppResult<Removal> {
        resolve(Path::new(exe), cargo_list, |program| {
            tools.contains(&program)
        })
    }

    fn resolved(exe: &str, cargo_list: Option<&str>, tools: &[&str]) -> Removal {
        resolve_with(exe, cargo_list, tools).expect("channel should resolve")
    }

    #[test]
    fn both_homebrew_prefixes_resolve_to_brew() {
        for exe in [
            "/opt/homebrew/Cellar/neutron/0.1.3/bin/neutron",
            "/home/linuxbrew/.linuxbrew/Cellar/neutron/0.1.3/bin/neutron",
            "/home/user/.local/share/homebrew/Cellar/neutron/0.1.3/bin/neutron",
        ] {
            let removal = resolved(exe, None, &["brew"]);
            assert_eq!(removal.channel, InstallChannel::Homebrew);
            assert_eq!(removal.program, "brew");
            assert_eq!(removal.args, ["uninstall", PACKAGE]);
        }
    }

    #[test]
    fn a_cargo_list_entry_resolves_to_cargo_from_any_root() {
        // `--root` and `--debug` put the binary outside ~/.cargo/bin, which is
        // why the package list is the signal rather than the path.
        let removal = resolved("/tmp/build/neutron", Some(CARGO_LIST), &["cargo"]);
        assert_eq!(removal.channel, InstallChannel::Cargo);
        assert_eq!(removal.program, "cargo");
    }

    #[test]
    fn a_homebrew_path_wins_over_a_leftover_cargo_entry() {
        let removal = resolved(
            "/opt/homebrew/Cellar/neutron/0.1.3/bin/neutron",
            Some(CARGO_LIST),
            &["brew", "cargo"],
        );
        assert_eq!(removal.channel, InstallChannel::Homebrew);
    }

    #[test]
    fn a_cellar_belonging_to_another_package_is_not_a_tap_install() {
        // A third-party formula that happens to ship a `neutron` binary must not
        // send `brew uninstall neutron` at the user's tap.
        let error = resolve_with(
            "/opt/homebrew/Cellar/neutron-bin/0.1.3/bin/neutron",
            None,
            &["brew"],
        )
        .expect_err("another package's Cellar is not a tap install");
        assert!(error.to_string().contains("cannot uninstall automatically"));
    }

    #[test]
    fn a_similarly_named_cargo_package_is_not_a_match() {
        assert!(!cargo_has_package(Some(
            "Installed packages:\n  neutron-vpn v0.1.0:\n"
        )));
        assert!(cargo_has_package(Some("  neutron v0.1.3:")));
        assert!(!cargo_has_package(None));
    }

    #[test]
    fn an_unrecognized_source_is_refused() {
        for (exe, list) in [
            ("/usr/bin/neutron", None),
            ("/tmp/neutron.AppImage", Some("")),
        ] {
            let error = resolve_with(exe, list, &["brew", "cargo"])
                .expect_err("an unknown install source must be refused");
            let message = error.to_string();
            assert!(
                message.contains("cannot uninstall automatically"),
                "{message}"
            );
            assert!(message.contains(exe), "{message}");
            assert!(message.contains("Nothing was changed"), "{message}");
        }
    }

    #[test]
    fn a_channel_whose_tool_is_missing_is_refused_before_anything_is_touched() {
        // The desktop-entry case: a Homebrew install launched from a stripped
        // PATH. Tearing down the firewall here would strand the user with the
        // rules gone and the package still installed.
        let error = resolve_with("/opt/homebrew/Cellar/neutron/0.1.3/bin/neutron", None, &[])
            .expect_err("a missing removal tool must be refused");
        let message = error.to_string();
        assert!(message.contains("`brew` is not runnable"), "{message}");
    }
}
