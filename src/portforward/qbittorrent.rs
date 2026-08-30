//! qBittorrent WebUI integration for dynamic NAT-PMP port forwarding.
//!
//! When connected to a VPN provider with NAT-PMP (such as Proton VPN), the
//! leased listening port changes per session. This module synchronizes the
//! dynamic port directly into a running qBittorrent instance (native, Flatpak,
//! or containerized) using its official Web API (v2).
//!
//! # Prerequisite
//! In qBittorrent:
//! 1. Open **Tools** -> **Options** -> **Web UI** (or **Preferences** -> **Web UI**).
//! 2. Enable **"Web User Interface (Remote control)"** (default port: `8080`).
//! 3. Check **"Bypass authentication for clients on localhost"** (recommended),
//!    or configure the matching username and password in Neutron.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::QBittorrentConfig;
use crate::error::{AppError, AppResult};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QBittorrentPreferences {
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default)]
    pub current_network_interface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QBittorrentSyncReport {
    pub previous_port: Option<u16>,
    pub new_port: u16,
    pub bound_interface: Option<String>,
    pub app_version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct QBittorrentClient {
    base_url: String,
    username: Option<String>,
    password: Option<String>,
    bind_interface: bool,
    cookie: Option<String>,
    timeout: Duration,
}

impl QBittorrentClient {
    pub fn new(config: &QBittorrentConfig) -> Self {
        let base_url = config.url.trim_end_matches('/').to_string();
        Self {
            base_url,
            username: config.username.clone().filter(|u| !u.trim().is_empty()),
            password: config.password.clone().filter(|p| !p.is_empty()),
            bind_interface: config.bind_interface,
            cookie: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Normalize API URL with endpoint path.
    pub fn endpoint_url(&self, path: &str) -> String {
        let clean_path = path.trim_start_matches('/');
        format!("{}/{}", self.base_url, clean_path)
    }

    /// Authenticate with the qBittorrent Web API if credentials are provided.
    pub fn login(&mut self) -> AppResult<()> {
        let (Some(username), Some(password)) = (self.username.as_deref(), self.password.as_deref())
        else {
            return Ok(());
        };

        let url = self.endpoint_url("api/v2/auth/login");
        let timeout_str = format_curl_timeout(self.timeout);
        let output = std::process::Command::new("curl")
            .args([
                "-s",
                "-i",
                "--max-time",
                &timeout_str,
                "-X",
                "POST",
                &url,
                "--data-urlencode",
                &format!("username={username}"),
                "--data-urlencode",
                &format!("password={password}"),
            ])
            .output()
            .map_err(|err| {
                AppError::QBittorrent(format!("failed to invoke curl for login: {err}"))
            })?;

        if !output.status.success() {
            return Err(AppError::QBittorrent(
                "qBittorrent WebUI is unreachable (curl connection failed)".to_string(),
            ));
        }

        let raw = String::from_utf8_lossy(&output.stdout);
        let resp = parse_http_response(&raw)?;

        if resp.status == 403 || resp.body.trim() == "Fails." {
            return Err(AppError::QBittorrent(
                "invalid qBittorrent WebUI credentials".to_string(),
            ));
        }

        if let Some(cookie) = extract_cookie(&resp.headers, "SID") {
            self.cookie = Some(cookie);
        }

        Ok(())
    }

    /// Query application version string (e.g. `v5.0.3`).
    pub fn app_version(&mut self) -> AppResult<String> {
        self.ensure_authenticated()?;
        let url = self.endpoint_url("api/v2/app/version");
        let resp = self.http_get(&url)?;

        if resp.status == 403 {
            // Cookie might have expired; retry once after re-authenticating
            self.cookie = None;
            self.login()?;
            let retry = self.http_get(&url)?;
            if retry.status != 200 {
                return Err(AppError::QBittorrent(format!(
                    "failed to query qBittorrent version (HTTP {})",
                    retry.status
                )));
            }
            return Ok(retry.body.trim().to_string());
        }

        if resp.status != 200 {
            return Err(AppError::QBittorrent(format!(
                "failed to query qBittorrent version (HTTP {})",
                resp.status
            )));
        }

        Ok(resp.body.trim().to_string())
    }

    /// Retrieve current preferences (such as `listen_port` and `current_network_interface`).
    pub fn get_preferences(&mut self) -> AppResult<QBittorrentPreferences> {
        self.ensure_authenticated()?;
        let url = self.endpoint_url("api/v2/app/preferences");
        let resp = self.http_get(&url)?;

        if resp.status != 200 {
            return Err(AppError::QBittorrent(format!(
                "failed to read qBittorrent preferences (HTTP {})",
                resp.status
            )));
        }

        let parsed: serde_json::Value = serde_json::from_str(&resp.body).map_err(|err| {
            AppError::QBittorrent(format!("invalid JSON from qBittorrent preferences: {err}"))
        })?;

        let listen_port = parsed
            .get("listen_port")
            .and_then(|v| v.as_u64())
            .map(|p| p as u16)
            .unwrap_or(0);

        let current_network_interface = parsed
            .get("current_network_interface")
            .and_then(|v| v.as_str())
            .map(String::from)
            .filter(|s| !s.is_empty());

        Ok(QBittorrentPreferences {
            listen_port,
            current_network_interface,
        })
    }

    /// Update listening port and optionally bind network interface.
    pub fn set_listen_port(&mut self, port: u16, interface_name: Option<&str>) -> AppResult<()> {
        self.ensure_authenticated()?;
        let url = self.endpoint_url("api/v2/app/setPreferences");

        let mut payload = serde_json::json!({
            "listen_port": port
        });

        if self.bind_interface
            && let Some(iface) = interface_name
        {
            payload["current_network_interface"] = serde_json::Value::String(iface.to_string());
        }

        let json_body = payload.to_string();
        let resp = self.http_post_urlencoded(&url, &[("json", &json_body)])?;

        if resp.status != 200 {
            return Err(AppError::QBittorrent(format!(
                "failed to update qBittorrent port to {port} (HTTP {})",
                resp.status
            )));
        }

        Ok(())
    }

    /// Synchronize port forward lease with qBittorrent.
    pub fn sync_port(
        &mut self,
        port: u16,
        interface_name: Option<&str>,
    ) -> AppResult<QBittorrentSyncReport> {
        let version = self.app_version().ok();
        let current_prefs = self.get_preferences().ok();
        let previous_port = current_prefs.as_ref().map(|p| p.listen_port);

        self.set_listen_port(port, interface_name)?;

        let bound_interface = if self.bind_interface {
            interface_name.map(String::from)
        } else {
            None
        };

        Ok(QBittorrentSyncReport {
            previous_port,
            new_port: port,
            bound_interface,
            app_version: version,
        })
    }

    fn ensure_authenticated(&mut self) -> AppResult<()> {
        if self.cookie.is_none() && self.username.is_some() {
            self.login()?;
        }
        Ok(())
    }

    fn http_get(&self, url: &str) -> AppResult<HttpResponse> {
        let args = build_get_args(self.timeout, url, self.cookie.as_deref());
        let output = std::process::Command::new("curl")
            .args(&args)
            .output()
            .map_err(|err| AppError::QBittorrent(format!("curl failed to query {url}: {err}")))?;

        if !output.status.success() {
            return Err(AppError::QBittorrent(format!(
                "qBittorrent WebUI unreachable at {}",
                self.base_url
            )));
        }

        parse_http_response(&String::from_utf8_lossy(&output.stdout))
    }

    fn http_post_urlencoded(
        &self,
        url: &str,
        form_data: &[(&str, &str)],
    ) -> AppResult<HttpResponse> {
        let args = build_post_args(self.timeout, url, form_data, self.cookie.as_deref());
        let output = std::process::Command::new("curl")
            .args(&args)
            .output()
            .map_err(|err| AppError::QBittorrent(format!("curl failed to post to {url}: {err}")))?;

        if !output.status.success() {
            return Err(AppError::QBittorrent(format!(
                "qBittorrent WebUI unreachable at {}",
                self.base_url
            )));
        }

        parse_http_response(&String::from_utf8_lossy(&output.stdout))
    }
}

pub(crate) fn build_get_args(timeout: Duration, url: &str, cookie: Option<&str>) -> Vec<String> {
    let timeout_str = format_curl_timeout(timeout);
    let mut args = vec![
        "-s".to_string(),
        "-i".to_string(),
        "--max-time".to_string(),
        timeout_str,
        url.to_string(),
    ];
    if let Some(cookie) = cookie {
        args.push("-H".to_string());
        args.push(format!("Cookie: SID={cookie}"));
    }
    args
}

pub(crate) fn build_post_args(
    timeout: Duration,
    url: &str,
    form_data: &[(&str, &str)],
    cookie: Option<&str>,
) -> Vec<String> {
    let timeout_str = format_curl_timeout(timeout);
    let mut args = vec![
        "-s".to_string(),
        "-i".to_string(),
        "--max-time".to_string(),
        timeout_str,
        "-X".to_string(),
        "POST".to_string(),
        url.to_string(),
    ];
    for (key, val) in form_data {
        args.push("--data-urlencode".to_string());
        args.push(format!("{key}={val}"));
    }
    if let Some(cookie) = cookie {
        args.push("-H".to_string());
        args.push(format!("Cookie: SID={cookie}"));
    }
    args
}

pub(crate) fn format_curl_timeout(timeout: Duration) -> String {
    let secs = timeout.as_secs_f64();
    if secs <= 0.0 {
        "0.001".to_string()
    } else if secs.fract() == 0.0 {
        format!("{:.0}", secs)
    } else {
        format!("{:.3}", secs)
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_string()
    }
}

/// Parse raw HTTP response headers, status code, and body from `curl -i` output.
pub fn parse_http_response(raw: &str) -> AppResult<HttpResponse> {
    if raw.is_empty() {
        return Err(AppError::QBittorrent(
            "empty response from WebUI".to_string(),
        ));
    }

    let delimiter = if raw.contains("\r\n\r\n") {
        "\r\n\r\n"
    } else {
        "\n\n"
    };

    let segments: Vec<&str> = raw.split(delimiter).collect();
    if segments.is_empty() {
        return Err(AppError::QBittorrent(
            "missing HTTP response content".to_string(),
        ));
    }

    // Find the last segment that starts with HTTP header (in case of 100 Continue)
    let mut header_idx = 0;
    for (i, seg) in segments.iter().enumerate() {
        if seg.starts_with("HTTP/1.") || seg.starts_with("HTTP/2") {
            header_idx = i;
        }
    }

    let header_section = segments[header_idx];
    let body = segments[header_idx + 1..].join(delimiter);

    let mut lines = header_section.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| AppError::QBittorrent("missing HTTP status line".to_string()))?;

    let status_code = parse_status_code(status_line)?;
    let mut headers = Vec::new();

    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_lowercase(), v.trim().to_string()));
        }
    }

    Ok(HttpResponse {
        status: status_code,
        headers,
        body,
    })
}

fn parse_status_code(status_line: &str) -> AppResult<u16> {
    let mut tokens = status_line.split_whitespace();
    let _http_version = tokens.next();
    let code_str = tokens
        .next()
        .ok_or_else(|| AppError::QBittorrent(format!("invalid status line: {status_line}")))?;

    code_str
        .parse::<u16>()
        .map_err(|_| AppError::QBittorrent(format!("invalid status code: {code_str}")))
}

fn extract_cookie(headers: &[(String, String)], cookie_name: &str) -> Option<String> {
    for (k, v) in headers {
        if k == "set-cookie" {
            for item in v.split(';') {
                let item = item.trim();
                if let Some(val) = item.strip_prefix(&format!("{cookie_name}=")) {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_curl_timeout_handles_subsecond_and_fractional_durations() {
        assert_eq!(format_curl_timeout(Duration::from_millis(500)), "0.5");
        assert_eq!(format_curl_timeout(Duration::from_millis(1500)), "1.5");
        assert_eq!(format_curl_timeout(Duration::from_secs(3)), "3");
        assert_eq!(format_curl_timeout(Duration::from_millis(0)), "0.001");
    }

    #[test]
    fn parses_http_response_with_crlf() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: SID=abc123xyz; Path=/\r\n\r\nOk.";
        let resp = parse_http_response(raw).expect("should parse");

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "Ok.");
        assert_eq!(
            extract_cookie(&resp.headers, "SID"),
            Some("abc123xyz".to_string())
        );
    }

    #[test]
    fn parses_http_response_with_lf_and_json() {
        let raw = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"listen_port\": 45678, \"current_network_interface\": \"wg0\"}";
        let resp = parse_http_response(raw).expect("should parse");

        assert_eq!(resp.status, 200);
        let parsed: QBittorrentPreferences = serde_json::from_str(&resp.body).expect("valid json");
        assert_eq!(parsed.listen_port, 45678);
        assert_eq!(parsed.current_network_interface.as_deref(), Some("wg0"));
    }

    #[test]
    fn parses_http_response_with_100_continue() {
        let raw = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOk.";
        let resp = parse_http_response(raw).expect("should parse");

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "Ok.");
    }

    #[test]
    fn parses_error_status_code() {
        let raw = "HTTP/1.1 403 Forbidden\r\n\r\nFails.";
        let resp = parse_http_response(raw).expect("should parse");

        assert_eq!(resp.status, 403);
        assert_eq!(resp.body, "Fails.");
    }

    #[test]
    fn client_url_formatting() {
        let cfg = QBittorrentConfig {
            enabled: true,
            url: "http://127.0.0.1:8080/".to_string(),
            username: None,
            password: None,
            bind_interface: false,
        };
        let client = QBittorrentClient::new(&cfg);
        assert_eq!(
            client.endpoint_url("api/v2/app/version"),
            "http://127.0.0.1:8080/api/v2/app/version"
        );
        assert_eq!(
            client.endpoint_url("/api/v2/app/preferences"),
            "http://127.0.0.1:8080/api/v2/app/preferences"
        );
    }

    #[test]
    fn build_get_args_formats_curl_command_with_and_without_cookie() {
        let args_no_cookie = build_get_args(
            Duration::from_secs(3),
            "http://127.0.0.1:8080/api/v2/app/version",
            None,
        );
        assert_eq!(
            args_no_cookie,
            vec![
                "-s",
                "-i",
                "--max-time",
                "3",
                "http://127.0.0.1:8080/api/v2/app/version"
            ]
        );

        let args_cookie = build_get_args(
            Duration::from_millis(1500),
            "http://127.0.0.1:8080/api/v2/app/version",
            Some("session123"),
        );
        assert_eq!(
            args_cookie,
            vec![
                "-s",
                "-i",
                "--max-time",
                "1.5",
                "http://127.0.0.1:8080/api/v2/app/version",
                "-H",
                "Cookie: SID=session123"
            ]
        );
    }

    #[test]
    fn build_post_args_formats_data_urlencoded_and_headers() {
        let form_data = [("username", "admin"), ("password", "secret&123=")];
        let args = build_post_args(
            Duration::from_secs(5),
            "http://127.0.0.1:8080/api/v2/auth/login",
            &form_data,
            Some("old_sid"),
        );

        assert_eq!(
            args,
            vec![
                "-s",
                "-i",
                "--max-time",
                "5",
                "-X",
                "POST",
                "http://127.0.0.1:8080/api/v2/auth/login",
                "--data-urlencode",
                "username=admin",
                "--data-urlencode",
                "password=secret&123=",
                "-H",
                "Cookie: SID=old_sid"
            ]
        );
    }

    #[test]
    fn mock_webui_server_login_and_sync_port() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();

        let done = Arc::new(AtomicBool::new(false));
        let done_clone = done.clone();

        let handle = thread::spawn(move || {
            while !done_clone.load(Ordering::Relaxed) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buffer = [0u8; 1024];
                    let n = stream.read(&mut buffer).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buffer[..n]);

                    if req.contains("/api/v2/auth/login") {
                        let resp = "HTTP/1.1 200 OK\r\nSet-Cookie: SID=mock_session_123; Path=/\r\nContent-Length: 3\r\n\r\nOk.";
                        let _ = stream.write_all(resp.as_bytes());
                    } else if req.contains("/api/v2/app/version") {
                        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\nv4.6.3";
                        let _ = stream.write_all(resp.as_bytes());
                    } else if req.contains("/api/v2/app/preferences") {
                        let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"listen_port\": 40000, \"current_network_interface\": \"\"}";
                        let _ = stream.write_all(resp.as_bytes());
                    } else if req.contains("/api/v2/app/setPreferences") {
                        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n";
                        let _ = stream.write_all(resp.as_bytes());
                    } else {
                        let resp = "HTTP/1.1 404 Not Found\r\n\r\n";
                        let _ = stream.write_all(resp.as_bytes());
                    }
                }
                thread::sleep(Duration::from_millis(10));
            }
        });

        let cfg = QBittorrentConfig {
            enabled: true,
            url: format!("http://127.0.0.1:{port}"),
            username: Some("admin".to_string()),
            password: Some("adminadmin".to_string()),
            bind_interface: true,
        };

        let mut client = QBittorrentClient::new(&cfg);
        client.login().expect("login should succeed");
        assert_eq!(client.cookie.as_deref(), Some("mock_session_123"));

        let version = client.app_version().expect("version should fetch");
        assert_eq!(version, "v4.6.3");

        let sync_res = client
            .sync_port(55432, Some("wg0"))
            .expect("sync should succeed");
        assert_eq!(sync_res.previous_port, Some(40000));
        assert_eq!(sync_res.new_port, 55432);
        assert_eq!(sync_res.bound_interface.as_deref(), Some("wg0"));

        done.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }
}
