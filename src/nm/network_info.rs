//! Public IP address discovery, bandwidth rate sampling, and latency telemetry.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIpInfo {
    pub ip: String,
    pub country: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
}

impl PublicIpInfo {
    /// Format public IP, location, and ISP into a clean single-line summary.
    pub fn format_display(&self) -> String {
        let mut location = Vec::new();
        if let Some(ref city) = self.city {
            location.push(city.as_str());
        }
        if let Some(ref country) = self.country {
            location.push(country.as_str());
        }
        let loc_str = location.join(", ");

        match (loc_str.is_empty(), self.isp.as_deref()) {
            (false, Some(isp)) => format!("{} ({} — {})", self.ip, loc_str, isp),
            (false, None) => format!("{} ({})", self.ip, loc_str),
            (true, Some(isp)) => format!("{} ({})", self.ip, isp),
            (true, None) => self.ip.clone(),
        }
    }
}

/// Fetch `url` with a short timeout and parse the body as JSON.
///
/// `curl` is shelled out to rather than pulling in an HTTP stack for three
/// optional telemetry lookups. Returns `None` for any failure -- a missing
/// public IP is cosmetic, never fatal.
fn curl_json(url: &str) -> Option<serde_json::Value> {
    let output = std::process::Command::new("curl")
        .args(["-s", "--max-time", CURL_TIMEOUT_SECS, url])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

const CURL_TIMEOUT_SECS: &str = "3";

/// Read a string field out of a JSON object, if present and non-empty.
fn json_str(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|field| field.as_str())
        .filter(|text| !text.is_empty())
        .map(String::from)
}

/// Fetch the current public IP address and geolocation information via lightweight HTTP APIs.
///
/// The providers are tried in order of how much they report; the first that
/// answers wins.
pub fn fetch_public_ip_info() -> Option<PublicIpInfo> {
    // ip-api.com: fast, unauthenticated, includes city/country/ISP.
    if let Some(value) = curl_json("http://ip-api.com/json/")
        && json_str(&value, "status").as_deref() == Some("success")
        && let Some(ip) = json_str(&value, "query")
    {
        return Some(PublicIpInfo {
            ip,
            country: json_str(&value, "country"),
            city: json_str(&value, "city"),
            isp: json_str(&value, "isp"),
        });
    }

    // ifconfig.co: no ISP, but still reports a location.
    if let Some(value) = curl_json("https://ifconfig.co/json")
        && let Some(ip) = json_str(&value, "ip")
    {
        return Some(PublicIpInfo {
            ip,
            country: json_str(&value, "country"),
            city: json_str(&value, "city"),
            isp: None,
        });
    }

    // icanhazip.com: bare address, plain text rather than JSON.
    let output = std::process::Command::new("curl")
        .args([
            "-s",
            "--max-time",
            CURL_TIMEOUT_SECS,
            "https://icanhazip.com",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!ip.is_empty()).then(|| PublicIpInfo {
        ip,
        ..PublicIpInfo::default()
    })
}

/// Read total bytes (rx, tx) from /proc/net/dev for given interface or WireGuard / active interfaces.
pub fn read_interface_bytes(iface_name: Option<&str>) -> (u64, u64) {
    let Ok(content) = std::fs::read_to_string("/proc/net/dev") else {
        return (0, 0);
    };
    parse_interface_bytes(&content, iface_name)
}

/// The receive counter of `iface_name`, or `None` when no such interface exists.
///
/// Distinct from [`read_interface_bytes`], which cannot tell "the interface is
/// absent" from "the interface has received nothing". Callers verifying a
/// freshly created tunnel need that distinction: absent means the counter is
/// about to start from zero, so any growth belongs to the new session.
pub fn interface_receive_bytes(iface_name: &str) -> Option<u64> {
    let content = std::fs::read_to_string("/proc/net/dev").ok()?;
    parse_interface_receive_bytes(&content, iface_name)
}

/// Pure parsing core of [`interface_receive_bytes`].
fn parse_interface_receive_bytes(content: &str, iface_name: &str) -> Option<u64> {
    for line in content.lines().skip(2) {
        // A line without a colon is not an interface row; skip it rather than
        // abandoning the search, or a malformed row would hide later ones.
        let Some((iface, stats)) = line.split_once(':') else {
            continue;
        };
        if iface.trim() != iface_name {
            continue;
        }
        return stats.split_whitespace().next()?.parse::<u64>().ok();
    }
    None
}

/// Pure parsing core of [`read_interface_bytes`], taking `/proc/net/dev`-shaped
/// content directly so it can be unit tested without a real `/proc` file.
fn parse_interface_bytes(content: &str, iface_name: Option<&str>) -> (u64, u64) {
    if let Some(target) = iface_name {
        for line in content.lines().skip(2) {
            let Some((iface, stats)) = line.split_once(':') else {
                continue;
            };
            let iface = iface.trim();
            if iface != target {
                continue;
            }
            let tokens: Vec<&str> = stats.split_whitespace().collect();
            if tokens.len() < 9 {
                return (0, 0);
            }
            let rx = tokens[0].parse::<u64>().unwrap_or(0);
            let tx = tokens[8].parse::<u64>().unwrap_or(0);
            return (rx, tx);
        }
        return (0, 0);
    }

    let mut total_rx = 0_u64;
    let mut total_tx = 0_u64;
    let mut found_wg = false;

    for line in content.lines().skip(2) {
        let Some((iface, stats)) = line.split_once(':') else {
            continue;
        };
        let iface = iface.trim();
        let tokens: Vec<&str> = stats.split_whitespace().collect();
        if tokens.len() < 9 {
            continue;
        }

        let rx = tokens[0].parse::<u64>().unwrap_or(0);
        let tx = tokens[8].parse::<u64>().unwrap_or(0);

        if iface.starts_with("wg") {
            total_rx += rx;
            total_tx += tx;
            found_wg = true;
        }
    }

    if found_wg {
        return (total_rx, total_tx);
    }

    // Fallback: sum all non-lo interfaces if no wg interfaces are up
    for line in content.lines().skip(2) {
        let Some((iface, stats)) = line.split_once(':') else {
            continue;
        };
        let iface = iface.trim();
        if iface == "lo" {
            continue;
        }
        let tokens: Vec<&str> = stats.split_whitespace().collect();
        if tokens.len() >= 9 {
            total_rx += tokens[0].parse::<u64>().unwrap_or(0);
            total_tx += tokens[8].parse::<u64>().unwrap_or(0);
        }
    }

    (total_rx, total_tx)
}

/// Format bytes per second to human readable transfer rate (e.g. "1.2 MB/s", "450 KB/s").
pub fn format_speed(bytes_per_sec: u64) -> String {
    if bytes_per_sec < 1024 {
        format!("{bytes_per_sec} B/s")
    } else if bytes_per_sec < 1024 * 1024 {
        format!("{:.1} KB/s", bytes_per_sec as f64 / 1024.0)
    } else {
        format!("{:.1} MB/s", bytes_per_sec as f64 / (1024.0 * 1024.0))
    }
}

/// Sample current network latency in milliseconds by pinging 1.1.1.1.
pub fn sample_latency() -> Option<u32> {
    let output = std::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", "1.1.1.1"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    parse_ping_latency(&String::from_utf8_lossy(&output.stdout))
}

/// Pure parsing core of [`sample_latency`]: extract the `time=<ms>` field from
/// `ping`'s stdout. Separated out so the parsing logic can be unit tested
/// without actually pinging a host.
fn parse_ping_latency(stdout: &str) -> Option<u32> {
    for part in stdout.split_whitespace() {
        if let Some(time_str) = part.strip_prefix("time=") {
            let val_str = time_str.trim_end_matches("ms");
            if let Ok(float_ms) = val_str.parse::<f64>() {
                return Some(float_ms.round() as u32);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_display_combines_all_fields() {
        let info = PublicIpInfo {
            ip: "185.159.157.1".to_string(),
            country: Some("Lithuania".to_string()),
            city: Some("Vilnius".to_string()),
            isp: Some("M247 Europe SRL".to_string()),
        };
        assert_eq!(
            info.format_display(),
            "185.159.157.1 (Vilnius, Lithuania — M247 Europe SRL)"
        );
    }

    #[test]
    fn format_display_with_ip_only() {
        let info = PublicIpInfo {
            ip: "1.1.1.1".to_string(),
            country: None,
            city: None,
            isp: None,
        };
        assert_eq!(info.format_display(), "1.1.1.1");
    }

    #[test]
    fn format_speed_units() {
        assert_eq!(format_speed(500), "500 B/s");
        assert_eq!(format_speed(1500), "1.5 KB/s");
        assert_eq!(format_speed(2_500_000), "2.4 MB/s");
    }

    #[test]
    fn interface_receive_bytes_distinguishes_absent_from_silent() {
        // A tunnel that has received nothing and a tunnel that does not exist
        // are different facts: the health check treats the first as a dead peer
        // and the second as "not ours to verify", so they must not collapse
        // into the same `0`.
        let sample = "Inter-|   Receive                                                |  Transmit\n\
                      face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                      wg0: 0             0    0    0    0     0          0         0        0        0    0    0    0     0       0          0\n\
                      wg1: 92            1    0    0    0     0          0         0      148        2    0    0    0     0       0          0\n";

        assert_eq!(parse_interface_receive_bytes(sample, "wg0"), Some(0));
        assert_eq!(parse_interface_receive_bytes(sample, "wg1"), Some(92));
        assert_eq!(parse_interface_receive_bytes(sample, "wg_absent"), None);
    }

    #[test]
    fn parse_interface_bytes_specific_target_matched() {
        let sample = "Inter-|   Receive                                                |  Transmit\n\
                      face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                      wg0: 1000       10    0    0    0     0          0         0     2000       20    0    0    0     0       0          0\n\
                      wg1: 5000       50    0    0    0     0          0         0     6000       60    0    0    0     0       0          0\n\
                      eth0: 99999    100    0    0    0     0          0         0    88888      100    0    0    0     0       0          0\n";
        assert_eq!(parse_interface_bytes(sample, Some("wg0")), (1000, 2000));
        assert_eq!(parse_interface_bytes(sample, Some("wg1")), (5000, 6000));
    }

    #[test]
    fn parse_interface_bytes_specific_target_missing_returns_zero() {
        let sample = "Inter-|   Receive                                                |  Transmit\n\
                      face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                      wg0: 1000       10    0    0    0     0          0         0     2000       20    0    0    0     0       0          0\n\
                      wg1: 5000       50    0    0    0     0          0         0     6000       60    0    0    0     0       0          0\n";
        assert_eq!(parse_interface_bytes(sample, Some("wg_missing")), (0, 0));
    }

    #[test]
    fn parse_interface_bytes_no_target_sums_wg_or_falls_back_to_non_lo() {
        let sample_wg = "Inter-|   Receive                                                |  Transmit\n\
                         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                         wg0: 1000       10    0    0    0     0          0         0     2000       20    0    0    0     0       0          0\n\
                         wg1: 5000       50    0    0    0     0          0         0     6000       60    0    0    0     0       0          0\n\
                         eth0: 99999    100    0    0    0     0          0         0    88888      100    0    0    0     0       0          0\n";
        assert_eq!(parse_interface_bytes(sample_wg, None), (6000, 8000));

        let sample_no_wg = "Inter-|   Receive                                                |  Transmit\n\
                            face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                            lo:   500        5    0    0    0     0          0         0      500        5    0    0    0     0       0          0\n\
                            eth0: 100        1    0    0    0     0          0         0      200        2    0    0    0     0       0          0\n";
        assert_eq!(parse_interface_bytes(sample_no_wg, None), (100, 200));
    }
}
