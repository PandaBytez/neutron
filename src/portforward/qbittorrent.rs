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
            // A NAT-PMP port is only reachable through the tunnel, so a qBittorrent
            // on this machine has to listen on the tunnel's interface. Decided by
            // the URL unless the user spelled it out (see
            // `QBittorrentConfig::binds_tunnel_interface`).
            bind_interface: config.binds_tunnel_interface(),
            base_url,
            username: config.username.clone().filter(|u| !u.trim().is_empty()),
            password: config.password.clone().filter(|p| !p.is_empty()),
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
        let resp =
            self.http_post_urlencoded(&url, &[("username", username), ("password", password)])?;

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

    /// Whether the WebUI answered a version query.
    ///
    /// A precondition check, not a sync: `false` means the UI is off, the
    /// process is down, or credentials were rejected. Callers that only need
    /// a warning must not treat that as a failed port push.
    pub fn reachable(&mut self) -> bool {
        self.app_version().is_ok()
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

    /// Update the listening port, and with it the tunnel's interface when the
    /// WebUI is local and the interface is known.
    ///
    /// An unknown interface leaves qBittorrent's binding alone: the port still
    /// lands, and naming a device that does not exist would keep it from
    /// listening anywhere at all.
    pub fn set_listen_port(&mut self, port: u16, interface_name: Option<&str>) -> AppResult<()> {
        self.ensure_authenticated()?;
        let url = self.endpoint_url("api/v2/app/setPreferences");

        let mut payload = serde_json::json!({
            "listen_port": port
        });

        if let Some(iface) = self.bind_target(interface_name) {
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

        let bound_interface = self.bind_target(interface_name).map(String::from);

        Ok(QBittorrentSyncReport {
            previous_port,
            new_port: port,
            bound_interface,
            app_version: version,
        })
    }

    /// The interface qBittorrent should listen on: the tunnel's, but only for a
    /// WebUI on this machine and only when the tunnel actually named one.
    fn bind_target<'a>(&self, interface_name: Option<&'a str>) -> Option<&'a str> {
        if !self.bind_interface {
            return None;
        }
        interface_name
            .map(str::trim)
            .filter(|name| !name.is_empty())
    }

    fn ensure_authenticated(&mut self) -> AppResult<()> {
        if self.cookie.is_none() && self.username.is_some() {
            self.login()?;
        }
        Ok(())
    }

    fn http_get(&self, url: &str) -> AppResult<HttpResponse> {
        run_curl(&request_config(
            self.timeout,
            url,
            None,
            self.cookie.as_deref(),
        )?)
    }

    fn http_post_urlencoded(
        &self,
        url: &str,
        form_data: &[(&str, &str)],
    ) -> AppResult<HttpResponse> {
        run_curl(&request_config(
            self.timeout,
            url,
            Some(form_data),
            self.cookie.as_deref(),
        )?)
    }
}

fn request_config(
    timeout: Duration,
    url: &str,
    form_data: Option<&[(&str, &str)]>,
    cookie: Option<&str>,
) -> AppResult<String> {
    let mut config = format!(
        "silent\ninclude\nmax-time = {}\nurl = {}\n",
        format_curl_timeout(timeout),
        curl_quote(url)
    );
    if let Some(form_data) = form_data {
        config.push_str("request = POST\n");
        for (key, val) in form_data {
            config.push_str(&format!(
                "data-urlencode = {}\n",
                curl_quote(&format!("{key}={val}"))
            ));
        }
    }
    if let Some(cookie) = cookie {
        if cookie.chars().any(char::is_control) {
            return Err(AppError::QBittorrent("invalid session cookie".into()));
        }
        config.push_str(&format!(
            "header = {}\n",
            curl_quote(&format!("Cookie: SID={cookie}"))
        ));
    }
    Ok(config)
}

/// curl config uses quoted strings with C-style escapes, not shell quoting.
fn curl_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\r', "\\r")
            .replace('\n', "\\n")
            .replace('\t', "\\t")
            .replace('\u{b}', "\\v")
    )
}

fn curl_command() -> std::process::Command {
    let mut command = std::process::Command::new("curl");
    // -q must be first: a user's curlrc must not enable tracing of credentials.
    command.args(["-q", "--config", "-"]);
    command
}

fn run_curl(config: &str) -> AppResult<HttpResponse> {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = curl_command()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let write_result = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(config.as_bytes()),
        None => Err(std::io::Error::other("curl stdin unavailable")),
    };
    if let Err(error) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(AppError::QBittorrent(format!(
            "failed to send curl request: {error}"
        )));
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(AppError::QBittorrent(
            "qBittorrent WebUI request failed".into(),
        ));
    }
    parse_http_response(&String::from_utf8_lossy(&output.stdout))
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
    fn an_unreachable_webui_is_not_reachable() {
        use crate::testing::{curl_available, unreachable_qbittorrent_url};

        if !curl_available() {
            eprintln!("Skipping reachability test: 'curl' is not installed.");
            return;
        }

        let cfg = QBittorrentConfig {
            url: unreachable_qbittorrent_url(),
            ..Default::default()
        };
        let mut client = QBittorrentClient::new(&cfg).with_timeout(Duration::from_millis(200));
        assert!(
            !client.reachable(),
            "a refused connection must not look like a live WebUI"
        );
    }

    #[test]
    fn client_url_formatting() {
        let cfg = QBittorrentConfig {
            url: "http://127.0.0.1:8080/".to_string(),
            username: None,
            password: None,
            ..Default::default()
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
    fn credentials_only_enter_stdin_and_config_values_cannot_inject_options() {
        let config = request_config(
            Duration::from_millis(1500),
            "http://localhost/",
            Some(&[("password", "secret\"\\\noutput = /tmp/stolen")]),
            Some("sentinel_sid"),
        )
        .unwrap();
        assert!(config.contains("max-time = 1.5"));
        assert!(config.contains("sentinel_sid"));
        assert!(!config.lines().any(|line| line.starts_with("output")));
        let command = curl_command();
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args, ["-q", "--config", "-"]);
        assert!(
            request_config(
                DEFAULT_TIMEOUT,
                "http://localhost/",
                None,
                Some("bad\r\nheader")
            )
            .is_err()
        );
    }

    #[test]
    fn mock_webui_server_login_and_sync_port() {
        use crate::testing::{MockQBittorrentWebUi, curl_available};

        if !curl_available() {
            eprintln!("Skipping mock WebUI test: 'curl' is not installed in the environment.");
            return;
        }

        let server = MockQBittorrentWebUi::start();
        let base = |authenticated: bool| QBittorrentConfig {
            url: server.url(),
            username: authenticated.then(|| "admin".to_string()),
            password: authenticated.then(|| "adminadmin".to_string()),
            ..Default::default()
        };

        let mut client = QBittorrentClient::new(&base(true));
        client.login().expect("login should succeed");
        assert_eq!(
            client.cookie.as_deref(),
            Some(MockQBittorrentWebUi::SESSION_COOKIE),
            "the session cookie must be taken from Set-Cookie"
        );

        assert_eq!(
            client.app_version().expect("version should fetch"),
            "v5.0.3"
        );

        let synced = client
            .sync_port(55432, Some("wg0"))
            .expect("sync should succeed");
        assert_eq!(
            synced.previous_port,
            Some(MockQBittorrentWebUi::INITIAL_LISTEN_PORT)
        );
        assert_eq!(synced.new_port, 55432);
        assert_eq!(synced.bound_interface.as_deref(), Some("wg0"));
        assert!(
            server.last_set_preferences().contains("wg0"),
            "a local WebUI must be told to listen on the tunnel interface"
        );

        // A tunnel that named no interface: the port still lands and no device
        // that does not exist is bound, which is the half that used to fail the
        // whole push.
        for interface in [None, Some(""), Some(" ")] {
            let mut client = QBittorrentClient::new(&base(false));
            let report = client
                .sync_port(55433, interface)
                .expect("port-only sync should succeed");
            assert_eq!(report.bound_interface, None);
            let pushed = server.last_set_preferences();
            assert!(
                !pushed.contains("current_network_interface"),
                "a missing interface must not be bound as a device: {pushed}"
            );
            assert!(
                pushed.contains("listen_port"),
                "the port must be applied: {pushed}"
            );
        }

        // A WebUI on another host has no tunnel interface to bind, so the
        // interface is left out of the payload there. The override is what
        // covers a WebUI on this machine that the URL does not look local.
        let remote = QBittorrentClient::new(&QBittorrentConfig {
            url: "http://192.168.1.50:8080".to_string(),
            ..Default::default()
        });
        assert_eq!(remote.bind_target(Some("wg0")), None);
        let forced = QBittorrentClient::new(&QBittorrentConfig {
            url: "http://192.168.1.50:8080".to_string(),
            bind_interface: Some(true),
            ..Default::default()
        });
        assert_eq!(forced.bind_target(Some("wg0")), Some("wg0"));
    }
}
