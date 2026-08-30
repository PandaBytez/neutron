use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("command failed: {0}")]
    CommandFailed(String),
    #[error("firewall command failed: {0}")]
    Firewall(String),
    #[error("failed to parse NetworkManager output: {0}")]
    NmParseFailed(String),
    #[error("wireguard profile not found: {0}")]
    ProfileNotFound(String),
    #[error("multiple wireguard profiles match name: {0}; use a unique profile name")]
    AmbiguousProfileName(String),
    #[error("no active wireguard profile found")]
    NoActiveProfile,
    #[error("{0}")]
    TunnelUnhealthy(String),
    #[error("no eligible profile found for random startup")]
    NoEligibleProfile,
    #[error("port forwarding failed: {0}")]
    PortForward(String),
    #[error("qbittorrent error: {0}")]
    QBittorrent(String),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("json serialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("toml deserialization error: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("toml serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),
}

pub type AppResult<T> = Result<T, AppError>;
