pub fn should_refresh_from_nm_monitor_line(line: &str) -> bool {
    let normalized = line.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }

    normalized.contains("connection")
        || normalized.contains("device")
        || normalized.contains("wireguard")
        || normalized.contains("vpn")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refreshes_for_connection_event_line() {
        assert!(should_refresh_from_nm_monitor_line(
            "connection profile added"
        ));
    }

    #[test]
    fn refreshes_for_device_event_line() {
        assert!(should_refresh_from_nm_monitor_line(
            "device wlan0 state changed"
        ));
    }

    #[test]
    fn ignores_unrelated_lines() {
        assert!(!should_refresh_from_nm_monitor_line("dns manager started"));
    }

    #[test]
    fn ignores_empty_line() {
        assert!(!should_refresh_from_nm_monitor_line("   "));
    }
}
