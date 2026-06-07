use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("network manager command failed: {0}")]
    NmCommandFailed(String),
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
    #[error("no eligible profile found for random startup")]
    NoEligibleProfile,
    #[error("feature unavailable: {0}")]
    FeatureUnavailable(String),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type AppResult<T> = Result<T, AppError>;
