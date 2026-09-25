//! System tests: `neutron uninstall` against a real `cargo install`.
//!
//! `src/install.rs` unit-tests the *decision* -- Homebrew path, cargo package
//! list, refusal when neither matches. What they cannot show is the thing that
//! actually matters to a user: that the binary removes the real install, keeps
//! the settings it promised to keep, and refuses to touch anything when it does
//! not recognize the install source. That needs a real `cargo uninstall` to
//! observe, so it lives here rather than in a test that fakes the subprocess.
//!
//! Safety: this container is `--rm` and disposable (see the note in
//! `testing/Containerfile`). The tests install Neutron into the container's own
//! `CARGO_HOME` and then delete it, which is why the destructive half of
//! `neutron uninstall` is never exercised on a host.
//!
//! Run with: `./testing/run-container-tests.sh --uninstall`

use std::path::{Path, PathBuf};
use std::process::Command;

use neutron::testing::require_sandbox;

/// A fake XDG config root holding the app directory plus decoys a purge must
/// spare. Rooted to mirror `XDG_CONFIG_HOME`, which is what the child is given.
fn decoy_config_home(label: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!("neutron-uninstall-{label}"));
    let _ = std::fs::remove_dir_all(&home);
    let config_home = home.join(".config");
    for relative in [
        "neutron/config.toml",
        "neutron/profiles/home.conf",
        "other-app/config.json",
    ] {
        let path = config_home.join(relative);
        std::fs::create_dir_all(path.parent().expect("fixture parent"))
            .expect("fixture directory should be created");
        std::fs::write(&path, "").expect("fixture file should be written");
    }
    home
}

fn cargo_home() -> PathBuf {
    std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".cargo"))
}

fn home_dir() -> PathBuf {
    PathBuf::from(std::env::var("HOME").expect("HOME should be set"))
}

fn installed_binary() -> PathBuf {
    cargo_home().join("bin").join("neutron")
}

fn cargo_installs_neutron() -> bool {
    let output = Command::new("cargo")
        .args(["install", "--list"])
        .output()
        .expect("cargo should run");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.trim().starts_with("neutron v"))
}

/// Install Neutron the documented way, so `cargo install --list` knows about it
/// and the channel resolves the way it will on a real machine.
fn cargo_install() {
    let status = Command::new("cargo")
        .args(["install", "--path", ".", "--locked", "--debug"])
        .status()
        .expect("cargo should run");
    assert!(status.success(), "cargo install should succeed");
    assert!(
        cargo_installs_neutron(),
        "the install must be visible to `cargo install --list`"
    );
}

/// Run the installed binary with Neutron's own view of the settings redirected
/// into `config_home`.
///
/// `CARGO_HOME` is pinned to the real one: the child's `HOME` is a temporary
/// directory, so cargo would otherwise look for `$HOME/.cargo`, find no
/// installed packages, and the channel could not resolve to cargo at all.
fn run_installed(config_home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(installed_binary())
        .args(args)
        .env("HOME", config_home)
        .env("XDG_CONFIG_HOME", config_home.join(".config"))
        .env("CARGO_HOME", cargo_home())
        .output()
        .expect("the installed binary should run")
}

fn settings(config_home: &Path) -> PathBuf {
    config_home.join(".config").join("neutron")
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn a_cargo_install_is_undone_in_one_shot_and_the_settings_are_kept() {
    require_sandbox();
    let config_home = decoy_config_home("keep");

    cargo_install();
    let output = run_installed(&config_home, &["uninstall"]);

    assert!(
        output.status.success(),
        "uninstall failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !installed_binary().exists(),
        "the installed binary should be gone"
    );
    assert!(
        !cargo_installs_neutron(),
        "`cargo install --list` should no longer list it"
    );
    assert!(
        settings(&config_home).join("config.toml").exists(),
        "settings are kept unless --purge is passed"
    );
    assert!(
        config_home.join(".config/other-app/config.json").exists(),
        "an unrelated application must not be touched"
    );
    let _ = std::fs::remove_dir_all(&config_home);
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn purge_removes_the_settings_directory_too() {
    require_sandbox();
    let config_home = decoy_config_home("purge");

    cargo_install();
    let output = run_installed(&config_home, &["uninstall", "--purge"]);

    assert!(
        output.status.success(),
        "uninstall --purge failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!installed_binary().exists());
    assert!(
        !settings(&config_home).exists(),
        "--purge must remove the configuration directory"
    );
    assert!(
        config_home.join(".config/other-app/config.json").exists(),
        "--purge must not reach outside the configuration directory"
    );
    let _ = std::fs::remove_dir_all(&config_home);
}

#[test]
#[ignore = "system test: requires the disposable sandbox"]
fn an_unrecognized_install_source_is_refused_without_deleting_anything() {
    require_sandbox();
    let config_home = decoy_config_home("unknown");

    // A copy outside any cargo root, with a CARGO_HOME that lists nothing: the
    // shape of an AppImage or a distro package. Tearing down the firewall here
    // and then leaving the package installed would strand the user, so this must
    // fail instead -- and it must fail *before* deleting the settings.
    let stray = config_home.join("opt/neutron");
    std::fs::create_dir_all(stray.parent().expect("stray parent"))
        .expect("stray directory should be created");
    std::fs::copy(env!("CARGO_BIN_EXE_neutron"), &stray).expect("binary should copy");

    let empty_cargo_home = config_home.join("empty-cargo-home");
    std::fs::create_dir_all(&empty_cargo_home).expect("cargo home should be created");
    let output = Command::new(&stray)
        .arg("uninstall")
        .env("HOME", &config_home)
        .env("XDG_CONFIG_HOME", config_home.join(".config"))
        .env("CARGO_HOME", &empty_cargo_home)
        .output()
        .expect("the stray binary should run");

    assert!(
        !output.status.success(),
        "an unknown install source must not report success"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot uninstall automatically"),
        "unhelpful error: {stderr}"
    );
    assert!(stderr.contains("Nothing was changed"), "{stderr}");
    assert!(stray.exists(), "the binary must still be there");
    assert!(
        settings(&config_home).join("config.toml").exists(),
        "a refused uninstall must not delete settings"
    );
    assert!(config_home.join(".config/other-app/config.json").exists());
    let _ = std::fs::remove_dir_all(&config_home);
}
