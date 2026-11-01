//! Subprocess plumbing shared by every module that shells out.
//!
//! This lives outside [`crate::nm`] because it is not NetworkManager-specific:
//! [`crate::firewall`] drives `firewall-cmd`/`pkexec` through the same helpers,
//! and having it reach into the NetworkManager module for them inverted the
//! module boundaries.

use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{AppError, AppResult};

/// Escape terminal controls in displayed data, without changing command arguments
/// or ordinary Unicode text. Also escape line separators and bidi controls.
pub fn terminal_safe(text: &str) -> String {
    let mut safe = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control()
            || matches!(ch, '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            safe.extend(ch.escape_default());
        } else {
            safe.push(ch);
        }
    }
    safe
}

/// Resolve the path or name of the currently running application binary,
/// accounting for `$APPIMAGE`, `current_exe()`, and fallback.
pub fn current_app_path() -> std::ffi::OsString {
    if let Ok(appimage) = std::env::var("APPIMAGE") {
        std::ffi::OsString::from(appimage)
    } else if let Ok(exe) = std::env::current_exe() {
        exe.into_os_string()
    } else {
        std::ffi::OsString::from("neutron")
    }
}

/// Render a failed command's exit status and stderr into one message. Falls back
/// to `prefix` when the process printed nothing to stderr.
pub fn format_command_error(
    prefix: &str,
    status: std::process::ExitStatus,
    stderr: &str,
) -> String {
    let stderr = stderr.trim();
    let code = status
        .code()
        .map(|code| code.to_string())
        .unwrap_or_else(|| "terminated by signal".to_string());
    if stderr.is_empty() {
        format!("{} (exit {code})", terminal_safe(prefix))
    } else {
        format!("{} (exit {code})", terminal_safe(stderr))
    }
}

/// Run `program` with `args`, returning its trimmed stdout, and killing it if it
/// outlives `timeout`.
pub fn run_with_timeout(program: &str, args: &[&str], timeout: Duration) -> AppResult<String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;

    // Drain stdout/stderr on separate threads so a large amount of output
    // cannot fill the pipe buffers and deadlock the child while we wait.
    let mut stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| AppError::CommandFailed(format!("{program} stdout unavailable")))?;
    let mut stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| AppError::CommandFailed(format!("{program} stderr unavailable")))?;

    let stdout_reader = thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buffer);
        buffer
    });
    let stderr_reader = thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buffer);
        buffer
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(AppError::CommandFailed(format!(
                "{program} {args:?} timed out after {}s",
                timeout.as_secs()
            )));
        }
        thread::sleep(Duration::from_millis(20));
    };

    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();

    if !status.success() {
        let stderr_str = String::from_utf8_lossy(&stderr);
        let prefix = format!("{program} {args:?} failed");
        return Err(AppError::CommandFailed(format_command_error(
            &prefix,
            status,
            &stderr_str,
        )));
    }

    Ok(String::from_utf8_lossy(&stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_terminal_controls_are_inert_and_unicode_is_preserved() {
        let hostile =
            "\u{6771}\u{4eac} caf\u{e9}\x1b]52;c;payload\x07\r\n\t\x7f\u{9b}\u{2028}\u{202e}";
        let safe = terminal_safe(hostile);
        assert!(safe.starts_with("\u{6771}\u{4eac} caf\u{e9}\\u{1b}]52;c;payload"));
        assert!(!safe.chars().any(char::is_control));
        assert!(!safe.contains('\u{2028}'));
        assert_eq!(terminal_safe(&safe), safe);
        let status = Command::new("false").status().unwrap();
        assert!(!format_command_error("failure", status, hostile).contains('\x1b'));
    }

    #[cfg(unix)]
    #[test]
    fn command_timeout_kills_long_running_process() {
        let start = Instant::now();
        let result = run_with_timeout("sleep", &["10"], Duration::from_millis(150));

        assert!(
            matches!(result, Err(AppError::CommandFailed(message)) if message.contains("timed out"))
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "timeout should return promptly instead of waiting for the process"
        );
    }

    #[cfg(unix)]
    #[test]
    fn command_success_returns_trimmed_stdout() {
        let result = run_with_timeout("printf", &["hello"], Duration::from_secs(5))
            .expect("printf should succeed");

        assert_eq!(result, "hello");
    }

    #[cfg(unix)]
    #[test]
    fn command_failure_includes_exit_code() {
        let result = run_with_timeout("false", &[], Duration::from_secs(5));

        assert!(matches!(
            result,
            Err(AppError::CommandFailed(message)) if message.contains("exit 1")
        ));
    }

    #[test]
    fn format_command_error_prefers_stderr_over_prefix() {
        let status = std::process::Command::new("false")
            .status()
            .expect("false should run");
        assert_eq!(
            format_command_error("prefix", status, "oops\n"),
            "oops (exit 1)"
        );

        let status = std::process::Command::new("true")
            .status()
            .expect("true should run");
        assert_eq!(
            format_command_error("prefix", status, ""),
            "prefix (exit 0)"
        );
        assert_eq!(
            format_command_error("prefix", status, "   \n"),
            "prefix (exit 0)"
        );
    }

    #[test]
    fn current_app_path_resolves_non_empty() {
        let path = current_app_path();
        assert!(!path.is_empty());
    }
}
