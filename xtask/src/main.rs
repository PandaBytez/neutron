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
        "Neutron VPN Custom Cargo Tasks (xtask)\n\n\
        USAGE:\n  \
          cargo xtask <TASK> [OPTIONS]\n  \
          cargo <ALIAS> [OPTIONS]\n\n\
        TASKS:\n  \
          test-all                    Run ALL tests: unit/integration + containerized system tests\n  \
          test-system, system-tests   Run destructive system tests inside a Podman container\n  \
          test-leaks, leak-tests      Run leak protection tests inside a Podman container\n  \
          container-shell, shell      Drop into an interactive shell inside the test container\n  \
          build-image                 Build/rebuild the neutron-sandbox container image\n  \
          lint                        Run cargo fmt and clippy with strict warnings\n\n\
        OPTIONS:\n  \
          --host-only                 Run only host tests (skip container)\n  \
          --nm                        Run only NetworkManager system tests\n  \
          --firewall                  Run only Firewall lockdown system tests\n  \
          --rebuild                   Force rebuild the container image before running\n  \
          --filter <pattern>          Run specific tests matching pattern\n\n\
        CARGO SHORTCUT ALIASES:\n  \
          cargo test-all              Execute entire test suite (host + container)\n  \
          cargo test-system           Run system tests in container\n  \
          cargo test-leaks            Run leak tests in container\n  \
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

    run_status(cmd.status())
}

fn run_host_tests(root: &Path) -> i32 {
    let status = Command::new("cargo")
        .args(["test", "--all-targets", "--features", "qbittorrent"])
        .current_dir(root)
        .status();
    run_status(status)
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
        .args([
            "clippy",
            "--all-targets",
            "--features",
            "qbittorrent",
            "--",
            "-D",
            "warnings",
        ])
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
