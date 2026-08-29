//! Desktop autostart entry that relaunches the app at login.
//!
//! NetworkManager already brings the armed profile up at boot, so this is *not*
//! what connects the VPN. Its job is to re-roll which profile is armed: the app
//! has to run at some point between two boots for the selection to rotate, and
//! a login autostart is the only place that happens without the user opening
//! the window.
//!
//! The entry is written by the app itself so the feature stays zero-config --
//! the same approach the GUI already takes for its `.desktop` and icons.

use std::path::{Path, PathBuf};

use crate::error::{AppError, AppResult};
use crate::{APP_ID, APP_NAME};

/// Basename of the autostart entry. Derived from the application ID so desktop
/// environments associate it with the installed launcher.
fn entry_name() -> String {
    format!("{APP_ID}-autostart.desktop")
}

/// Command that relaunches this binary with `args`.
///
/// Prefers `$APPIMAGE` because `current_exe` inside an AppImage points at the
/// extracted mount (`/tmp/.mount_XXXX/usr/bin/...`), which disappears when the
/// app exits -- an autostart entry pointing there would silently fail at the
/// next login.
pub fn launch_command(args: &str) -> String {
    if let Ok(appimage) = std::env::var("APPIMAGE") {
        return format!("\"{appimage}\" {args}");
    }
    if let Ok(exe) = std::env::current_exe() {
        return format!("\"{}\" {args}", exe.display());
    }
    format!("neutron-vpn {args}")
}

/// The user's autostart directory, `~/.config/autostart`.
///
/// Callers pass the result into [`install_in`] / [`uninstall_in`] rather than
/// those functions resolving it themselves, so tests can target a temporary
/// directory instead of the real home directory.
pub fn dir() -> AppResult<PathBuf> {
    let config_dir = dirs::config_dir()
        .ok_or_else(|| AppError::Config("no XDG config directory available".to_string()))?;
    Ok(config_dir.join("autostart"))
}

/// Whether the autostart entry exists in `dir`.
pub fn is_installed_in(dir: &Path) -> bool {
    dir.join(entry_name()).exists()
}

/// Write the autostart entry into `dir`, creating it if needed.
///
/// Starts hidden: an autostarted launch has no reason to steal focus at login,
/// and the app already supports living in the tray.
pub fn install_in(dir: &Path) -> AppResult<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(
        dir.join(entry_name()),
        entry_contents(&launch_command("gui --hidden")),
    )?;
    Ok(())
}

/// Remove the autostart entry from `dir`. Succeeds when it is already absent.
pub fn uninstall_in(dir: &Path) -> AppResult<()> {
    match std::fs::remove_file(dir.join(entry_name())) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AppError::Io(error)),
    }
}

/// Render the `.desktop` body for `exec_cmd`.
///
/// Split out from [`install`] so the contents can be asserted without touching
/// the real home directory.
fn entry_contents(exec_cmd: &str) -> String {
    // `X-GNOME-Autostart-enabled` keeps GNOME from treating the entry as
    // disabled, and the AppImage `Exec` is quoted because its path may contain
    // spaces.
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={APP_NAME}\n\
         Comment=Connect a random WireGuard profile at login\n\
         Exec={exec_cmd}\n\
         Icon={APP_ID}\n\
         Terminal=false\n\
         NoDisplay=true\n\
         X-GNOME-Autostart-enabled=true\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_is_a_hidden_autostart_application() {
        let contents = entry_contents("\"/opt/neutron.AppImage\" gui --hidden");

        assert!(contents.starts_with("[Desktop Entry]\n"));
        assert!(contents.contains("Type=Application\n"));
        // Hidden from the app grid: this entry exists to run at login, not to
        // be a second launcher next to the real one.
        assert!(contents.contains("NoDisplay=true\n"));
        // GNOME treats a missing value here as disabled for some entries.
        assert!(contents.contains("X-GNOME-Autostart-enabled=true\n"));
        assert!(contents.contains("Exec=\"/opt/neutron.AppImage\" gui --hidden\n"));
    }

    #[test]
    fn launch_command_prefers_the_appimage_path() {
        // SAFETY: single-threaded test process; no other thread reads the env.
        unsafe { std::env::set_var("APPIMAGE", "/home/u/App Images/neutron.AppImage") };
        let command = launch_command("gui --hidden");
        unsafe { std::env::remove_var("APPIMAGE") };

        // Quoted: `current_exe` inside an AppImage points at a temporary mount
        // that is gone by the next login, and the path may contain spaces.
        assert_eq!(
            command,
            "\"/home/u/App Images/neutron.AppImage\" gui --hidden"
        );
    }

    #[test]
    fn autostart_dir_lives_under_xdg_config() {
        let path = dir().expect("a config dir should be available in tests");

        assert!(path.ends_with("autostart"), "{path:?}");
    }

    #[test]
    fn install_then_uninstall_round_trips_in_a_given_directory() {
        // Targets a temp directory rather than the real `~/.config/autostart`:
        // an earlier version resolved the path internally, and the service
        // tests wrote a stale entry into the developer's home directory that
        // pointed at a throwaway test binary.
        let base = std::env::temp_dir().join(format!(
            "neutron-vpn-autostart-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should move forward")
                .as_nanos()
        ));

        assert!(!is_installed_in(&base));

        install_in(&base).expect("install should create the entry");
        assert!(is_installed_in(&base));
        let written = std::fs::read_to_string(base.join(entry_name())).expect("entry should exist");
        assert!(written.contains("gui --hidden"));

        uninstall_in(&base).expect("uninstall should remove the entry");
        assert!(!is_installed_in(&base));

        // Removing an absent entry is the normal case when the feature was
        // never enabled, so it must not error.
        uninstall_in(&base).expect("uninstall should be idempotent");

        let _ = std::fs::remove_dir_all(&base);
    }
}
