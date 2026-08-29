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

/// Fetch the current public IP address and geolocation information via lightweight HTTP APIs.
pub fn fetch_public_ip_info() -> Option<PublicIpInfo> {
    // 1. Try ip-api.com (fast, unauthenticated, includes city/country/ISP)
    if let Ok(output) = std::process::Command::new("curl")
        .args(["-s", "--max-time", "3", "http://ip-api.com/json/"])
        .output()
        && output.status.success()
        && let Ok(val) = serde_json::from_slice::<serde_json::Value>(&output.stdout)
        && val.get("status").and_then(|s| s.as_str()) == Some("success")
    {
        let ip = val.get("query").and_then(|v| v.as_str())?.to_string();
        let country = val
            .get("country")
            .and_then(|v| v.as_str())
            .map(String::from);
        let city = val.get("city").and_then(|v| v.as_str()).map(String::from);
        let isp = val.get("isp").and_then(|v| v.as_str()).map(String::from);
        return Some(PublicIpInfo {
            ip,
            country,
            city,
            isp,
        });
    }

    // 2. Fallback to ifconfig.co
    if let Ok(output) = std::process::Command::new("curl")
        .args(["-s", "--max-time", "3", "https://ifconfig.co/json"])
        .output()
        && output.status.success()
        && let Ok(val) = serde_json::from_slice::<serde_json::Value>(&output.stdout)
    {
        let ip = val.get("ip").and_then(|v| v.as_str())?.to_string();
        let country = val
            .get("country")
            .and_then(|v| v.as_str())
            .map(String::from);
        let city = val.get("city").and_then(|v| v.as_str()).map(String::from);
        return Some(PublicIpInfo {
            ip,
            country,
            city,
            isp: None,
        });
    }

    // 3. Fallback to icanhazip.com for bare IP
    if let Ok(output) = std::process::Command::new("curl")
        .args(["-s", "--max-time", "3", "https://icanhazip.com"])
        .output()
        && output.status.success()
    {
        let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !ip.is_empty() {
            return Some(PublicIpInfo {
                ip,
                country: None,
                city: None,
                isp: None,
            });
        }
    }

    None
}

/// Read total bytes (rx, tx) from /proc/net/dev for given interface or WireGuard / active interfaces.
pub fn read_interface_bytes(iface_name: Option<&str>) -> (u64, u64) {
    let Ok(content) = std::fs::read_to_string("/proc/net/dev") else {
        return (0, 0);
    };

    let mut total_rx = 0_u64;
    let mut total_tx = 0_u64;
    let mut found_specific = false;

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

        if let Some(target) = iface_name
            && iface == target
        {
            return (rx, tx);
        }

        if iface.starts_with("wg") {
            total_rx += rx;
            total_tx += tx;
            found_specific = true;
        }
    }

    if found_specific || iface_name.is_some() {
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

    let text = String::from_utf8_lossy(&output.stdout);
    for part in text.split_whitespace() {
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
}
