//! NetworkManager `connection.autoconnect` control for WireGuard profiles.
//!
//! The "random profile per boot" selector relies on NetworkManager *not*
//! activating WireGuard profiles on its own: it must start from a clean slate
//! and bring up exactly one. NetworkManager, however, defaults
//! `connection.autoconnect` to `yes`, so without intervention every profile is
//! auto-activated at boot (each WireGuard profile is its own interface, so they
//! do not compete and all come up at once). That defeats the selector entirely.
//!
//! Neutron therefore takes ownership of the flag and disables autoconnect on the
//! profiles it manages, leaving boot-time activation to the selector alone.

/// `nmcli` arguments that set `connection.autoconnect` on connection `uuid` to
/// `yes` (`enable`) or `no`.
pub fn set_args(uuid: &str, enable: bool) -> Vec<String> {
    vec![
        "connection".to_string(),
        "modify".to_string(),
        uuid.to_string(),
        "connection.autoconnect".to_string(),
        if enable { "yes" } else { "no" }.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_args_disable_targets_uuid_and_turns_autoconnect_off() {
        let args = set_args("uuid-1", false);

        assert_eq!(
            args,
            vec![
                "connection".to_string(),
                "modify".to_string(),
                "uuid-1".to_string(),
                "connection.autoconnect".to_string(),
                "no".to_string(),
            ]
        );
    }

    #[test]
    fn set_args_enable_turns_autoconnect_on() {
        let args = set_args("uuid-2", true);

        assert_eq!(args[2], "uuid-2");
        assert_eq!(args[3], "connection.autoconnect");
        assert_eq!(args[4], "yes");
    }
}
