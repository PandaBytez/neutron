use std::io;

use thiserror::Error;

use crate::process::terminal_safe;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Policy {
    Lockdown,
    KillSwitch,
    SplitTunnel,
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Lockdown => "lockdown",
            Self::KillSwitch => "kill switch",
            Self::SplitTunnel => "split tunneling",
        })
    }
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error(
        "{policy}: {outcome}; saved intent may differ from effective protection. Retry the policy action to reconcile: {source}"
    )]
    PolicyUpdate {
        policy: Policy,
        outcome: &'static str,
        #[source]
        source: Box<AppError>,
    },
    #[error("command failed: {}", terminal_safe(.0))]
    CommandFailed(String),
    #[error("firewall command failed: {}", terminal_safe(.0))]
    Firewall(String),
    #[error("failed to parse NetworkManager output: {}", terminal_safe(.0))]
    NmParseFailed(String),
    #[error("wireguard profile not found: {}", terminal_safe(.0))]
    ProfileNotFound(String),
    #[error("multiple wireguard profiles match name: {}; use a unique profile name", terminal_safe(.0))]
    AmbiguousProfileName(String),
    #[error("no active wireguard profile found")]
    NoActiveProfile,
    #[error("{}", terminal_safe(.0))]
    TunnelUnhealthy(String),
    #[error("no eligible profile found for random startup")]
    NoEligibleProfile,
    #[error("{}", terminal_safe(.0))]
    Uninstall(String),
    #[error("port forwarding failed: {}", terminal_safe(.0))]
    PortForward(String),
    #[error("qbittorrent error: {}", terminal_safe(.0))]
    QBittorrent(String),
    #[error("configuration error: {}", terminal_safe(.0))]
    Config(String),
    #[error("io error: {}", terminal_safe(&.0.to_string()))]
    Io(#[from] io::Error),
    #[error("json error: {}", terminal_safe(.0))]
    SerdeJson(String),
    #[error("toml deserialization error: {}", terminal_safe(.0))]
    TomlDe(String),
    #[error("toml serialization error: {}", terminal_safe(&.0.to_string()))]
    TomlSer(#[from] toml::ser::Error),
}

// Parser messages can contain values, keys, or entire credential-bearing lines.
// Retain only category/location, never the original error or its source chain.
impl From<serde_json::Error> for AppError {
    fn from(error: serde_json::Error) -> Self {
        let reason = match error.classify() {
            serde_json::error::Category::Io => "input/output failure",
            serde_json::error::Category::Syntax => "invalid JSON syntax",
            serde_json::error::Category::Data => "invalid field type or value",
            serde_json::error::Category::Eof => "unexpected end of input",
        };
        Self::SerdeJson(format!(
            "{reason} at line {}, column {}",
            error.line(),
            error.column()
        ))
    }
}

impl From<toml::de::Error> for AppError {
    fn from(error: toml::de::Error) -> Self {
        let location = error
            .span()
            .map(|span| format!(" at bytes {}..{}", span.start, span.end))
            .unwrap_or_default();
        Self::TomlDe(format!(
            "invalid TOML syntax, field type, or value{location}"
        ))
    }
}

pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policies_display_as_readable_names() {
        assert_eq!(Policy::Lockdown.to_string(), "lockdown");
        assert_eq!(Policy::KillSwitch.to_string(), "kill switch");
        assert_eq!(Policy::SplitTunnel.to_string(), "split tunneling");
    }
}
