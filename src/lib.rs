pub const APP_ID: &str = "io.gitlab.neutron_vpn.neutron";
pub const APP_NAME: &str = "Neutron VPN";

pub mod app;
pub mod config;
pub mod error;
pub mod firewall;
pub mod gui;
pub mod nm;
pub mod portforward;
pub mod service;
pub mod testing;
