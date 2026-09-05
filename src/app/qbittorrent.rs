//! The one place a forwarded port is handed to qBittorrent.
//!
//! Three callers need this -- the TUI, the tray daemon's lease-renewal loop, and
//! the `neutron qbit sync` command -- and they differ only in where the config
//! comes from and how they report the outcome. The push itself lives here so
//! they cannot drift: when each kept its own copy, a fix to the interface
//! handling landed in one and left the other two binding qBittorrent's socket to
//! a device that does not exist.
//!
//! Reporting deliberately stays with the callers. A toast, a `tracing` record
//! and a line on stdout are not the same thing, and folding them together here
//! would mean inventing a sink abstraction to tell them apart again.

use crate::config::QBittorrentConfig;
use crate::error::AppResult;
use crate::nm::NmClient;
use crate::portforward::qbittorrent::{QBittorrentClient, QBittorrentSyncReport};

/// Push `port` into the qBittorrent instance described by `config`, binding it
/// to the interface of the tunnel `uuid` that leased the port.
///
/// The interface comes from [`NmClient::tunnel_interface`] rather than from the
/// profile diagnostics, because the latter substitutes the uuid when no
/// interface name is configured. Binding to that substitute would point
/// qBittorrent at a device that does not exist and silently drop every incoming
/// connection; `None` instead leaves it listening on any interface.
///
/// Whether the interface is applied at all is the user's call, via
/// [`QBittorrentConfig::bind_interface`].
pub fn sync_port<C: NmClient>(
    client: &C,
    config: &QBittorrentConfig,
    uuid: &str,
    port: u16,
) -> AppResult<QBittorrentSyncReport> {
    let interface = client.tunnel_interface(uuid);
    QBittorrentClient::new(config).sync_port(port, interface.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        MockNmClient, MockQBittorrentWebUi, curl_available, unreachable_qbittorrent_url,
    };

    fn config(url: String) -> QBittorrentConfig {
        QBittorrentConfig {
            enabled: true,
            url,
            username: None,
            password: None,
            bind_interface: true,
        }
    }

    #[test]
    fn an_unreachable_webui_is_an_error_rather_than_a_silent_no_op() {
        let client = MockNmClient::default();

        let result = sync_port(
            &client,
            &config(unreachable_qbittorrent_url()),
            "uuid-eu",
            51820,
        );

        assert!(
            result.is_err(),
            "an unreachable WebUI must not look like a successful push"
        );
    }

    #[test]
    fn the_tunnels_interface_is_bound_alongside_the_port() {
        if !curl_available() {
            return;
        }
        let server = MockQBittorrentWebUi::start();
        let client = MockNmClient::default();

        sync_port(&client, &config(server.url()), "uuid-eu", 51820).expect("push should succeed");

        let pushed = server.last_set_preferences();
        assert!(
            pushed.contains("wg0"),
            "the tunnel's interface must reach qBittorrent: {pushed}"
        );
    }

    #[test]
    fn a_tunnel_without_an_interface_binds_to_none() {
        // `get_profile_diagnostics` substitutes the uuid when NetworkManager
        // reports no interface name, because the details pane needs something to
        // print. Binding qBittorrent to that label would point its socket at a
        // device that does not exist and drop every incoming connection, so the
        // push must carry no interface at all instead.
        if !curl_available() {
            return;
        }
        let server = MockQBittorrentWebUi::start();
        let client = MockNmClient::default().without_tunnel_interface();

        sync_port(&client, &config(server.url()), "uuid-eu", 51820).expect("push should succeed");

        let pushed = server.last_set_preferences();
        assert!(
            !pushed.contains("current_network_interface"),
            "a missing interface must not be bound as a device: {pushed}"
        );
        assert!(
            pushed.contains("listen_port"),
            "the port itself must still be applied: {pushed}"
        );
    }
}
