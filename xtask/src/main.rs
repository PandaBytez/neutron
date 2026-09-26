use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

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

/// The argument list for one sandboxed `podman run`.
///
/// Built in one place because the order carries meaning: everything up to and
/// including [`IMAGE_NAME`] is read by the container runtime, and anything after
/// it is the command inside the container. The masking flags belong to the former
/// -- appended after the image they are passed on to `cargo`, which is how
/// `cargo test` ended up failing with `Unrecognized option: 'tmpfs'`.
fn container_run_args(mount: &str, interactive: bool, command: &[String]) -> Vec<String> {
    let mut args: Vec<String> = ["run", "--rm"].into_iter().map(String::from).collect();
    if interactive {
        args.push("-it".into());
    }
    args.extend([
        "--privileged".to_string(),
        "-v".to_string(),
        mount.to_string(),
        "-w".to_string(),
        "/src".to_string(),
    ]);
    for path in SANDBOX_PRIVATE_PATHS {
        args.push("--tmpfs".into());
        args.push(path.into());
    }
    args.push(IMAGE_NAME.into());
    args.extend(command.iter().cloned());
    args
}

fn run_in_container(root: &Path, command_args: &[String]) -> i32 {
    let tool = match detect_container_tool() {
        Ok(t) => t,
        Err(err) => {
            eprintln!("Error: {err}");
            return 1;
        }
    };

    let mount = format!("{}:/src:z", root.display());
    let mut command = vec!["cargo".to_string()];
    command.extend(command_args.iter().cloned());
    let mut cmd = Command::new(tool);
    cmd.args(container_run_args(&mount, false, &command))
        .current_dir(root);

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
    cmd.args(container_run_args(&mount, true, command_args))
        .current_dir(root);

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

Restarted: the tray/lease daemon, if it was running. An install replaces the
binary underneath a running process, which would otherwise go on using the old
build until the next login. A running Neutron window is reported, not closed.

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
    let program = root_dir.join("bin/neutron");
    println!("Installed: {}", program.display());
    println!("Lockdown left alone: firewall rules, refresh helper, and polkit action unchanged.");
    match restart_daemon(Path::new("/proc"), &program) {
        Ok(Some(pid)) => println!("Daemon restarted on this build (pid {pid})."),
        Ok(None) => println!("No daemon was running, so none was started."),
        Err(reason) => eprintln!("Warning: the running daemon still has the old build -- {reason}"),
    }
    for (pid, argv0) in running_instances(&program).others {
        println!("Left running: pid {pid} ({argv0}) still has the build it started with.");
    }
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

/// The running Neutron processes, split by what this task may do to them.
struct Instances {
    /// The tray/lease daemons running `program` -- the ones to replace.
    daemons: Vec<u32>,
    /// Every other Neutron process as `(pid, argv[0])`: a window the developer
    /// is sitting in, or a daemon belonging to a different install. Reported,
    /// never touched.
    others: Vec<(u32, String)>,
}

/// Read `/proc` for the running Neutron processes.
///
/// Scoped to the binary that was just installed, deliberately: `cargo reinstall
/// -- --root DIR` writes somewhere else, and swapping the daemon of the install
/// the developer actually uses for that build would hand it the bus name and the
/// lease. Read out of `/proc` rather than off the bus because a build tool has
/// no use for a D-Bus dependency.
fn running_instances_in(proc: &Path, program: &Path) -> Instances {
    let mut found = Instances {
        daemons: Vec::new(),
        others: Vec::new(),
    };
    let Ok(entries) = std::fs::read_dir(proc) else {
        return found;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let dir = entry.path();
        if !std::fs::read_to_string(dir.join("comm")).is_ok_and(|c| c.trim() == "neutron") {
            continue;
        }
        // argv is NUL-terminated, so the split yields a trailing empty field.
        // A process with no argv at all is a zombie: it has exited and is only
        // waiting to be reaped, which is what a daemon killed under a TUI looks
        // like for as long as that TUI runs. Treating it as running would both
        // stall the restart and report a window that is not there.
        let args: Vec<String> = std::fs::read(dir.join("cmdline"))
            .map(|raw| {
                raw.split(|byte| *byte == 0)
                    .map(|arg| String::from_utf8_lossy(arg).into_owned())
                    .filter(|arg| !arg.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let Some(argv0) = args.first() else {
            continue;
        };
        // `daemon` is the alias the CLI accepts for the same subcommand.
        if Path::new(argv0) == program
            && matches!(
                args.get(1).map(String::as_str),
                Some("indicator" | "daemon")
            )
        {
            found.daemons.push(pid);
        } else {
            found.others.push((pid, argv0.clone()));
        }
    }
    found.daemons.sort_unstable();
    found.others.sort_unstable();
    found
}

fn running_instances(program: &Path) -> Instances {
    running_instances_in(Path::new("/proc"), program)
}

/// Stop the running daemon and start the freshly installed one, reporting the
/// pid it came back on. `Ok(None)` means there was no daemon to replace.
///
/// This has to happen here rather than being left to the next login: `cargo
/// install` replaces the binary by rename, so a running process keeps its old
/// inode and goes on renewing leases and pushing ports with pre-reinstall code,
/// silently. `Ok(Some(_))`/`Err` are about the daemon only -- the install itself
/// already succeeded, so a failure here is reported, not fatal.
fn restart_daemon(proc: &Path, program: &Path) -> Result<Option<u32>, String> {
    const EXIT_WAIT: Duration = Duration::from_secs(2);
    const START_WAIT: Duration = Duration::from_secs(2);

    let daemons = running_instances_in(proc, program).daemons;
    if daemons.is_empty() {
        return Ok(None);
    }
    for pid in &daemons {
        // `kill` rather than kill(2): no unsafe in a build tool, and it is
        // coreutils wherever NetworkManager runs.
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    }
    if !wait_until(EXIT_WAIT, || {
        running_instances_in(proc, program).daemons.is_empty()
    }) {
        // Starting a second daemon now would only have the two fight over the
        // bus name.
        return Err("it ignored SIGTERM; quit it and run `neutron indicator` yourself".into());
    }
    // `setsid` detaches the daemon from this task's session, or the terminal
    // that ran the build would take it down with SIGHUP on exit.
    Command::new("setsid")
        .arg(program)
        .arg("indicator")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("it could not be started: {e}"))?;
    if !wait_until(START_WAIT, || {
        !running_instances_in(proc, program).daemons.is_empty()
    }) {
        return Err(format!(
            "it did not come back up; start it with `{} indicator`",
            program.display()
        ));
    }
    Ok(running_instances_in(proc, program).daemons.first().copied())
}

fn wait_until(timeout: Duration, done: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
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

    /// A `/proc` entry as the scan sees it: a numeric directory with `comm` and
    /// NUL-separated `cmdline`.
    fn process(proc: &Path, pid: u32, comm: &str, argv: &[&str]) {
        let dir = proc.join(pid.to_string());
        std::fs::create_dir_all(&dir).expect("proc dir should be created");
        std::fs::write(dir.join("comm"), format!("{comm}\n")).expect("comm should be written");
        let raw: Vec<u8> = argv
            .iter()
            .flat_map(|a| a.as_bytes().iter().copied().chain(std::iter::once(0u8)))
            .collect();
        std::fs::write(dir.join("cmdline"), raw).expect("cmdline should be written");
    }

    #[test]
    fn the_daemon_is_told_apart_from_a_window_a_zombie_and_another_install() {
        // Every case here is one way a restart goes wrong: killing the window a
        // developer is working in, skipping the daemon that has to be replaced,
        // waiting on a zombie that will never be reaped, or handing a throwaway
        // `--root` build the real install's bus name.
        let proc = scratch("processes");
        let installed = Path::new("/home/u/.cargo/bin/neutron");
        process(
            &proc,
            100,
            "neutron",
            &["/home/u/.cargo/bin/neutron", "indicator"],
        );
        process(
            &proc,
            101,
            "neutron",
            &["/home/u/.cargo/bin/neutron", "daemon"],
        );
        process(&proc, 200, "neutron", &["/home/u/.cargo/bin/neutron"]);
        process(&proc, 300, "nmcli", &["nmcli", "monitor"]);
        process(&proc, 400, "neutron", &["/usr/bin/neutron", "indicator"]);
        // A daemon killed under a TUI lingers with an empty argv.
        process(&proc, 500, "neutron", &[]);

        let found = running_instances_in(&proc, installed);

        assert_eq!(
            found.daemons,
            vec![100, 101],
            "only this install's daemons, under either subcommand name"
        );
        assert_eq!(
            found.others,
            vec![
                (200, "/home/u/.cargo/bin/neutron".to_string()),
                (400, "/usr/bin/neutron".to_string()),
            ],
            "a window and another install's daemon are reported, not killed"
        );
        let _ = std::fs::remove_dir_all(&proc);
    }

    #[test]
    fn container_options_precede_the_image_and_the_command_follows_it() {
        // The regression: the masking flags were appended after the image, so
        // the runtime passed them to `cargo`, and the sandbox tier failed with
        // "Unrecognized option: 'tmpfs'" before running a single test.
        let command = vec!["cargo".to_string(), "test".to_string()];
        for interactive in [false, true] {
            let args = container_run_args("/src:/src:z", interactive, &command);
            let image = args
                .iter()
                .position(|arg| arg == IMAGE_NAME)
                .expect("the image name is in the argument list");

            for (index, arg) in args.iter().enumerate().skip(image + 1) {
                assert!(
                    !arg.starts_with('-'),
                    "runtime option {arg} must precede the image, not the command: {args:?}"
                );
            }
            assert_eq!(
                args.iter().filter(|arg| *arg == "--tmpfs").count(),
                SANDBOX_PRIVATE_PATHS.len(),
                "every masked path is still masked: {args:?}"
            );
            assert_eq!(
                &args[image + 1..],
                &command,
                "only the command may follow the image: {args:?}"
            );
            assert_eq!(args.contains(&"-it".to_string()), interactive);
        }
    }

    #[test]
    fn a_proc_root_that_cannot_be_read_reports_nothing_running() {
        let found = running_instances_in(&scratch("no-proc"), Path::new("/nope"));
        assert!(found.daemons.is_empty() && found.others.is_empty());
    }

    /// This text is the only discoverability a new contributor has, so the
    /// two things that surprise people -- what survives, and the stale helper
    /// -- have to be in it.
    #[test]
    fn the_usage_says_what_is_kept_and_what_is_not() {
        for expected in [
            "lockdown",
            "settings",
            "restored",
            "neutron lockdown enable",
            "cargo install",
            "daemon",
        ] {
            assert!(
                REINSTALL_USAGE.contains(expected),
                "usage should mention {expected:?}:\n{REINSTALL_USAGE}"
            );
        }
    }
}
