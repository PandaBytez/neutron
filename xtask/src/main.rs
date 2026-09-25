use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const IMAGE_NAME: &str = "neutron-sandbox";

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let task = args.first().map(|s| s.as_str()).unwrap_or("help");

    let workspace_root = project_root();

    let exit_code = match task {
        "test-all" | "all" => run_all_tests(&workspace_root, &args[1..]),
        "test-system" | "system-tests" => run_system_tests(&workspace_root, &args[1..]),
        "test-leaks" | "leak-tests" => run_leak_tests(&workspace_root, &args[1..]),
        "container-shell" | "shell" => run_container_shell(&workspace_root, &args[1..]),
        "build-image" => build_container_image(&workspace_root, true),
        "reinstall" | "dev-install" => run_reinstall(&workspace_root, &args[1..]),
        "docs" | "build-docs" => build_docs(&workspace_root, &args[1..]),
        "lint" => run_linter(&workspace_root),
        "help" | "--help" | "-h" => {
            print_help();
            0
        }
        unknown => {
            eprintln!("Unknown task: '{unknown}'\n");
            print_help();
            1
        }
    };

    std::process::exit(exit_code);
}

fn print_help() {
    println!(
        "Neutron Custom Cargo Tasks (xtask)\n\n\
        USAGE:\n  \
          cargo xtask <TASK> [OPTIONS]\n  \
          cargo <ALIAS> [OPTIONS]\n\n\
        TASKS:\n  \
          test-all                    Run ALL tests: unit/integration + containerized system tests\n  \
          test-system, system-tests   Run destructive system tests inside a Podman container\n  \
          test-leaks, leak-tests      Run leak protection tests inside a Podman container\n  \
          container-shell, shell      Drop into an interactive shell inside the test container\n  \
          build-image                 Build/rebuild the neutron-sandbox container image\n  \
          reinstall, dev-install      Rebuild and install the binary, keeping settings intact (`cargo reinstall`)\n  \
          docs, build-docs            Build mdBook documentation for GitHub Pages\n  \
          lint                        Run cargo fmt and clippy with strict warnings\n\n\
        OPTIONS:\n  \
          --host-only                 Run only host tests (skip container)\n  \
          --nm                        Run only NetworkManager system tests\n  \
          --firewall                  Run only Firewall lockdown system tests\n  \
          --rebuild                   Force rebuild the container image before running\n  \
          --filter <pattern>          Run specific tests matching pattern\n  \
          --serve                     Serve mdBook documentation locally\n\n\
        CARGO SHORTCUT ALIASES:\n  \
          cargo test-all              Execute entire test suite (host + container)\n  \
          cargo test-system           Run system tests in container\n  \
          cargo test-leaks            Run leak tests in container\n  \
          cargo docs                  Build static HTML docs (mdBook)\n  \
          cargo lint                  Run formatting and clippy checks"
    );
}

fn project_root() -> PathBuf {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must have a parent directory")
        .to_path_buf()
}

fn detect_container_tool() -> Result<&'static str, String> {
    if Command::new("podman").arg("--version").output().is_ok() {
        Ok("podman")
    } else if Command::new("docker").arg("--version").output().is_ok() {
        Ok("docker")
    } else {
        Err("Neither 'podman' nor 'docker' is installed or available in PATH.".to_string())
    }
}

fn image_exists(tool: &str, image: &str) -> bool {
    let output = Command::new(tool).args(["image", "exists", image]).output();

    if let Ok(out) = output {
        if out.status.success() {
            return true;
        }
    }

    let inspect = Command::new(tool)
        .args(["image", "inspect", image])
        .output();
    inspect.map(|o| o.status.success()).unwrap_or(false)
}

fn build_container_image(root: &Path, force: bool) -> i32 {
    let tool = match detect_container_tool() {
        Ok(t) => t,
        Err(err) => {
            eprintln!("Error: {err}");
            return 1;
        }
    };

    if !force && image_exists(tool, IMAGE_NAME) {
        return 0;
    }

    println!("==> Building container image '{IMAGE_NAME}' with {tool}...");
    let status = Command::new(tool)
        .args([
            "build",
            "-t",
            IMAGE_NAME,
            "-f",
            "testing/Containerfile",
            ".",
        ])
        .current_dir(root)
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("==> Container image '{IMAGE_NAME}' built successfully.\n");
            0
        }
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("Failed to run {tool} build: {e}");
            1
        }
    }
}

fn run_all_tests(root: &Path, args: &[String]) -> i32 {
    println!("==> [1/2] Running host unit & integration tests (all feature gates)...");
    let host_code = run_host_tests(root);
    if host_code != 0 {
        eprintln!("\n✖ Host tests failed with exit code {host_code}");
        return host_code;
    }

    if args.iter().any(|a| a == "--host-only") {
        println!("\n✔ Host tests passed (--host-only specified).");
        return 0;
    }

    println!("\n==> [2/2] Running containerized system & leak tests in isolated sandbox...");
    let system_code = run_system_tests(root, args);
    if system_code != 0 {
        eprintln!("\n✖ Container system tests failed with exit code {system_code}");
        return system_code;
    }

    println!("\n✔ All test tiers passed successfully (Host + Container sandbox).");
    0
}

fn run_system_tests(root: &Path, args: &[String]) -> i32 {
    let rebuild = args.iter().any(|a| a == "--rebuild");
    if build_container_image(root, rebuild) != 0 {
        return 1;
    }

    let mut test_args = vec![
        "test".to_string(),
        "--".to_string(),
        "--ignored".to_string(),
        "--test-threads=1".to_string(),
    ];

    if args.iter().any(|a| a == "--nm") {
        test_args = vec![
            "test".to_string(),
            "--test".to_string(),
            "system_nm".to_string(),
            "--".to_string(),
            "--ignored".to_string(),
            "--test-threads=1".to_string(),
        ];
    } else if args.iter().any(|a| a == "--firewall") {
        test_args = vec![
            "test".to_string(),
            "--test".to_string(),
            "system_firewall".to_string(),
            "--".to_string(),
            "--ignored".to_string(),
            "--test-threads=1".to_string(),
        ];
    } else if args.iter().any(|a| a == "--uninstall") {
        test_args = vec![
            "test".to_string(),
            "--test".to_string(),
            "system_uninstall".to_string(),
            "--".to_string(),
            "--ignored".to_string(),
            "--test-threads=1".to_string(),
        ];
    } else if let Some(idx) = args.iter().position(|a| a == "--filter") {
        if let Some(pattern) = args.get(idx + 1) {
            test_args.push(pattern.clone());
        }
    }

    run_in_container(root, &test_args)
}

fn run_leak_tests(root: &Path, args: &[String]) -> i32 {
    let rebuild = args.iter().any(|a| a == "--rebuild");
    if build_container_image(root, rebuild) != 0 {
        return 1;
    }

    let test_args = vec![
        "test".to_string(),
        "--test".to_string(),
        "system_firewall".to_string(),
        "--".to_string(),
        "--ignored".to_string(),
        "leak_".to_string(),
        "--test-threads=1".to_string(),
    ];

    run_in_container(root, &test_args)
}

fn run_container_shell(root: &Path, args: &[String]) -> i32 {
    let rebuild = args.iter().any(|a| a == "--rebuild");
    if build_container_image(root, rebuild) != 0 {
        return 1;
    }

    run_in_container_interactive(root, &["/bin/bash".to_string()])
}

fn build_docs(root: &Path, args: &[String]) -> i32 {
    let serve = args.iter().any(|a| a == "--serve");
    let cmd = if serve { "serve" } else { "build" };

    if Command::new("mdbook").arg("--version").output().is_ok() {
        let status = Command::new("mdbook").arg(cmd).current_dir(root).status();
        return run_status(status);
    }

    println!("'mdbook' is not installed locally on host. Running mdBook build via container...");
    let tool = match detect_container_tool() {
        Ok(t) => t,
        Err(err) => {
            eprintln!("Error: {err}\nPlease install mdbook with: cargo install mdbook");
            return 1;
        }
    };

    let mount = format!("{}:/src:z", root.display());
    let mut c = Command::new(tool);
    c.args([
        "run",
        "--rm",
        "-v",
        &mount,
        "-w",
        "/src",
        "ghcr.io/rust-lang/mdbook:latest",
        "mdbook",
        cmd,
    ]);
    run_status(c.status())
}

/// Paths inside the container that Neutron writes as root, and which would
/// otherwise land on the *host*: only `/src` is mounted, so `/usr/local` and
/// `/etc/polkit-1` are the host's own. The sandbox's netfilter isolation does
/// not extend to the filesystem, and a test that enables then revokes lockdown
/// would delete the developer's real helper and polkit action.
///
/// Masked with container-local tmpfs. `/usr/local/bin` is deliberately left
/// alone: the image installs its `pkexec` shim there.
const SANDBOX_PRIVATE_PATHS: [&str; 3] = [
    "/usr/local/libexec",
    "/usr/local/share/polkit-1",
    "/etc/polkit-1",
];

fn run_in_container(root: &Path, command_args: &[String]) -> i32 {
    let tool = match detect_container_tool() {
        Ok(t) => t,
        Err(err) => {
            eprintln!("Error: {err}");
            return 1;
        }
    };

    let mount = format!("{}:/src:z", root.display());
    let mut cmd = Command::new(tool);
    cmd.args([
        "run",
        "--rm",
        "--privileged",
        "-v",
        &mount,
        "-w",
        "/src",
        IMAGE_NAME,
        "cargo",
    ])
    .args(command_args)
    .current_dir(root);
    for path in SANDBOX_PRIVATE_PATHS {
        cmd.arg("--tmpfs").arg(path);
    }

    run_status(cmd.status())
}

fn run_in_container_interactive(root: &Path, command_args: &[String]) -> i32 {
    let tool = match detect_container_tool() {
        Ok(t) => t,
        Err(err) => {
            eprintln!("Error: {err}");
            return 1;
        }
    };

    let mount = format!("{}:/src:z", root.display());
    let mut cmd = Command::new(tool);
    cmd.args([
        "run",
        "--rm",
        "-it",
        "--privileged",
        "-v",
        &mount,
        "-w",
        "/src",
        IMAGE_NAME,
    ])
    .args(command_args)
    .current_dir(root);
    for path in SANDBOX_PRIVATE_PATHS {
        cmd.arg("--tmpfs").arg(path);
    }

    run_status(cmd.status())
}

fn run_host_tests(root: &Path) -> i32 {
    let status = Command::new("cargo")
        .args(["test", "--all-targets"])
        .current_dir(root)
        .status();
    run_status(status)
}

/// The settings files a reinstall must not disturb.
///
/// Directories mirror the app's own config candidates (see
/// `config::default_config_path`), and within them only the settings sidecars are
/// captured -- not the `profiles/` drop directory, which holds the user's own
/// `.conf` files. A restore only ever puts back a file that was captured, so
/// anything created while the install ran is left alone.
const SETTINGS_DIRS: [&str; 3] = ["neutron", "neutron-vpn", "wireguard-manager"];

fn config_home() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".config")
}

/// Settings as they were before the reinstall.
struct SettingsSnapshot(Vec<(PathBuf, Vec<u8>)>);

impl SettingsSnapshot {
    /// `home` is the XDG config root, taken as an argument so this is testable
    /// without mutating the environment.
    fn capture_in(home: &Path) -> Self {
        let mut files = Vec::new();
        for dir in SETTINGS_DIRS {
            let Ok(entries) = std::fs::read_dir(home.join(dir)) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && let Ok(bytes) = std::fs::read(&path)
                {
                    files.push((path, bytes));
                }
            }
        }
        Self(files)
    }

    /// Put back anything the install changed or removed. Returns what was
    /// restored, so the caller reports it rather than reverting in silence.
    fn restore_if_changed(&self) -> Vec<PathBuf> {
        let mut restored = Vec::new();
        for (path, original) in &self.0 {
            if std::fs::read(path).is_ok_and(|now| now == *original) {
                continue;
            }
            if std::fs::write(path, original).is_ok() {
                restored.push(path.clone());
            }
        }
        restored
    }

    fn describe(&self) -> String {
        if self.0.is_empty() {
            "none existed, so there was nothing to disturb".to_string()
        } else {
            self.0
                .iter()
                .map(|(path, _)| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    }
}

/// Rebuild and install the binary, leaving lockdown *and settings* alone.
///
/// The point is iteration speed. `cargo install` touches nothing privileged and
/// writes no settings, so working on the TUI or the UI does not mean disabling
/// lockdown and re-authenticating through `pkexec` on every rebuild. That is
/// asserted rather than assumed: the settings files are captured beforehand and
/// restored if the install turns out to touch them.
///
/// The trade-off is the refresh helper: `/usr/local/libexec/neutron-lockdown-helper`
/// is a *copy* of the binary taken when lockdown was enabled, and it is left
/// stale on purpose. A rule refresh runs that copy, not this build, so after
/// changing firewall code run `neutron lockdown enable` once to refresh it.
///
/// Extra arguments go straight to `cargo install`, so `--debug`, `--root DIR`,
/// and `--locked` all work: `cargo xtask reinstall -- --debug`.
/// What `cargo reinstall` does, printed for `-h` / `--help`.
///
/// Handled here rather than forwarded: `cargo install --help` would print
/// cargo's help, exit 0, and the command would then claim it installed
/// something.
const REINSTALL_USAGE: &str = "\
cargo reinstall [-- <cargo install flags>]

Rebuilds and installs Neutron, keeping your lockdown state and your settings.

  cargo reinstall                 release build, installed to $CARGO_HOME/bin
  cargo reinstall -- --debug      much faster rebuild for iterating
  cargo reinstall -- --root DIR   install somewhere other than CARGO_HOME

Left alone: the firewall rules, the root-owned refresh helper, the polkit
action, and every settings file (captured beforehand and restored if the
install touches them).

Left stale: the refresh helper is a copy of the binary from when lockdown
was enabled. After changing firewall code run `neutron lockdown enable`
once to refresh it.";

fn run_reinstall(root: &Path, args: &[String]) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{REINSTALL_USAGE}");
        return 0;
    }
    println!("==> Rebuilding and installing (lockdown and settings untouched)");
    // `cargo xtask reinstall -- --debug`: the separator belongs to xtask's own
    // argument parsing, and passing it on makes cargo reject `--debug` as a
    // package name.
    let forwarded: &[String] = match args.strip_prefix(&["--".to_string()]) {
        Some(rest) => rest,
        None => args,
    };
    let settings = SettingsSnapshot::capture_in(&config_home());
    let mut command = Command::new("cargo");
    command
        .args(["install", "--path", ".", "--force"])
        .args(forwarded)
        .current_dir(root);
    if run_status(command.status()) != 0 {
        eprintln!("Reinstall failed; nothing was changed.");
        return 1;
    }

    let root_dir = forwarded
        .iter()
        .position(|a| a == "--root")
        .and_then(|i| forwarded.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("CARGO_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    let home = std::env::var("HOME").unwrap_or_default();
                    PathBuf::from(home).join(".cargo")
                })
        });
    println!("Installed: {}", root_dir.join("bin/neutron").display());
    println!("Lockdown left alone: firewall rules, refresh helper, and polkit action unchanged.");
    let restored = settings.restore_if_changed();
    if restored.is_empty() {
        println!("Settings unchanged: {}.", settings.describe());
    } else {
        // Should not happen: `cargo install` writes no settings. Reported rather
        // than fixed silently, because it means something else is writing them.
        println!("Settings restored -- the install changed these:");
        for path in &restored {
            println!("  {}", path.display());
        }
        println!(
            "A running Neutron instance rewrites settings as it polls; restart it to pick up this build."
        );
    }
    println!(
        "If you changed firewall code, run `neutron lockdown enable` once to refresh the helper copy."
    );
    0
}

fn run_linter(root: &Path) -> i32 {
    println!("==> Checking code formatting (cargo fmt)...");
    let fmt_status = Command::new("cargo")
        .args(["fmt", "--all", "--", "--check"])
        .current_dir(root)
        .status();

    if !fmt_status.map(|s| s.success()).unwrap_or(false) {
        eprintln!("Formatting check failed. Run 'cargo fmt' to fix.");
        return 1;
    }

    println!("==> Running Clippy lints (strict mode)...");
    let clippy_status = Command::new("cargo")
        .args(["clippy", "--all-targets", "--", "-D", "warnings"])
        .current_dir(root)
        .status();

    run_status(clippy_status)
}

fn run_status(status: std::io::Result<ExitStatus>) -> i32 {
    match status {
        Ok(s) => s.code().unwrap_or(if s.success() { 0 } else { 1 }),
        Err(e) => {
            eprintln!("Failed to execute command: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "neutron-xtask-{label}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should move")
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn unchanged_settings_are_left_alone() {
        let home = scratch("unchanged");
        let config = home.join("neutron/config.toml");
        std::fs::create_dir_all(config.parent().expect("parent")).expect("dir should be created");
        std::fs::write(&config, "lockdown_enabled = true\n").expect("write should succeed");

        let snapshot = SettingsSnapshot::capture_in(&home);
        assert_eq!(snapshot.0.len(), 1, "one settings file captured");
        assert!(
            snapshot.restore_if_changed().is_empty(),
            "an untouched file must not be rewritten"
        );
        assert_eq!(
            std::fs::read_to_string(&config).expect("read should succeed"),
            "lockdown_enabled = true\n"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_clobbered_or_deleted_settings_file_is_restored() {
        let home = scratch("restored");
        let config = home.join("neutron/config.toml");
        let notes = home.join("neutron/profile-info.json");
        std::fs::create_dir_all(config.parent().expect("parent")).expect("dir should be created");
        std::fs::write(&config, "lockdown_enabled = true\n").expect("write should succeed");
        std::fs::write(&notes, "{}").expect("write should succeed");
        let snapshot = SettingsSnapshot::capture_in(&home);

        // Both ways this can go wrong: rewritten, and removed outright.
        std::fs::write(&config, "lockdown_enabled = false\n").expect("write should succeed");
        std::fs::remove_file(&notes).expect("remove should succeed");

        let mut restored = snapshot.restore_if_changed();
        restored.sort();
        assert_eq!(
            restored,
            vec![config.clone(), notes.clone()],
            "both restored"
        );
        assert_eq!(
            std::fs::read_to_string(&config).expect("read should succeed"),
            "lockdown_enabled = true\n"
        );
        assert!(notes.exists(), "a deleted sidecar must come back");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_file_created_during_the_install_is_left_alone() {
        // Restoring must never delete or overwrite something that was not
        // captured, or a reinstall would eat settings the user just made.
        let home = scratch("created");
        let config = home.join("neutron/config.toml");
        std::fs::create_dir_all(config.parent().expect("parent")).expect("dir should be created");
        std::fs::write(&config, "original\n").expect("write should succeed");
        let snapshot = SettingsSnapshot::capture_in(&home);

        let fresh = home.join("neutron/fresh.json");
        std::fs::write(&fresh, "{\"new\": true}").expect("write should succeed");

        assert!(snapshot.restore_if_changed().is_empty());
        assert!(fresh.exists(), "a new file must survive the restore");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_missing_config_directory_captures_nothing_and_does_not_panic() {
        let snapshot = SettingsSnapshot::capture_in(&scratch("absent"));
        assert!(snapshot.0.is_empty());
        assert!(snapshot.restore_if_changed().is_empty());
    }
}

#[cfg(test)]
mod reinstall_usage_tests {
    use super::REINSTALL_USAGE;

    #[test]
    fn the_usage_says_what_is_kept_and_what_is_not() {
        // This text is the only discoverability a new contributor has, so the
        // two things that surprise people -- what survives, and the stale helper
        // -- have to be in it.
        for expected in [
            "lockdown",
            "settings",
            "restored",
            "neutron lockdown enable",
            "cargo install",
        ] {
            assert!(
                REINSTALL_USAGE.contains(expected),
                "usage should mention {expected:?}:\n{REINSTALL_USAGE}"
            );
        }
    }
}
