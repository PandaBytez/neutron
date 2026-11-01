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
use crate::nm::{NmIntrospect, NmLifecycle};
use crate::portforward::qbittorrent::{QBittorrentClient, QBittorrentSyncReport};

/// Push `port` into the qBittorrent instance described by `config`, binding it
/// to the interface of the tunnel `uuid` that leased the port.
///
/// The interface comes from [`NmIntrospect::tunnel_interface`] rather than from the
/// profile diagnostics, because the latter substitutes the uuid when no
/// interface name is configured. Binding to that substitute would point
/// qBittorrent at a device that does not exist and silently drop every incoming
/// connection. A missing interface is not an error: the port is pushed and the
/// binding is left alone.
///
/// Whether the interface is applied at all follows from the WebUI URL: a local
/// qBittorrent listens on the tunnel, because a NAT-PMP port only arrives there
/// (see [`crate::config::webui_is_local`]).
pub fn sync_port<C: NmIntrospect + NmLifecycle>(
    client: &C,
    path: &std::path::Path,
    config: &QBittorrentConfig,
    uuid: &str,
    port: u16,
    expires_at: Option<u64>,
) -> AppResult<QBittorrentSyncReport> {
    crate::config::coordinate_policy(path, || {
        if !client
            .list_wireguard_profiles()?
            .iter()
            .any(|p| p.uuid == uuid && p.is_active())
        {
            return Err(crate::error::AppError::QBittorrent(
                "the leased tunnel is no longer active; sync refused".into(),
            ));
        }
        let interface = client.tunnel_interface(uuid);
        QBittorrentClient::new(config).sync_port(port, interface.as_deref(), expires_at)
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn queued_sync_refuses_a_tunnel_that_is_no_longer_active_without_contacting_the_webui() {
        let path = crate::testing::temp_config_path("qbit-stale-owner");
        let server = crate::testing::MockQBittorrentWebUi::start();
        let client = crate::testing::MockNmClient::new(vec![crate::testing::profile(
            "B",
            "B",
            crate::nm::ProfileState::Active,
        )]);
        let result = sync_port(&client, &path, &config(server.url()), "A", 51820, None);
        assert!(result.unwrap_err().to_string().contains("no longer active"));
        assert!(server.paths().is_empty());
        crate::testing::remove_temp_config(&path);
    }

    use super::*;
    use crate::testing::{
        MockNmClient, MockQBittorrentWebUi, curl_available, unreachable_qbittorrent_url,
    };

    fn config(url: String) -> QBittorrentConfig {
        QBittorrentConfig {
            url,
            username: None,
            password: None,
            ..Default::default()
        }
    }

    fn active_client() -> MockNmClient {
        MockNmClient::new(vec![crate::testing::profile(
            "wg-eu",
            "uuid-eu",
            crate::nm::ProfileState::Active,
        )])
    }

    #[test]
    fn an_unreachable_webui_is_an_error_rather_than_a_silent_no_op() {
        let client = active_client();
        let path = crate::testing::temp_config_path("qbit-unreachable");

        let result = sync_port(
            &client,
            &path,
            &config(unreachable_qbittorrent_url()),
            "uuid-eu",
            51820,
            None,
        );

        assert!(
            result.is_err(),
            "an unreachable WebUI must not look like a successful push"
        );
        crate::testing::remove_temp_config(&path);
    }

    #[test]
    fn the_tunnels_interface_is_bound_alongside_the_port() {
        if !curl_available() {
            return;
        }
        let server = MockQBittorrentWebUi::start();
        let client = active_client();
        let path = crate::testing::temp_config_path("qbit-bind");

        sync_port(
            &client,
            &path,
            &config(server.url()),
            "uuid-eu",
            51820,
            None,
        )
        .expect("push should succeed");

        let pushed = server.last_set_preferences();
        assert!(
            pushed.contains("wg0"),
            "the tunnel's interface must reach qBittorrent: {pushed}"
        );
        crate::testing::remove_temp_config(&path);
    }

    #[test]
    fn a_tunnel_without_an_interface_still_gets_the_port() {
        // `get_profile_diagnostics` substitutes the uuid when NetworkManager
        // reports no interface name, because the details pane needs something to
        // print. Binding qBittorrent to that label would point its socket at a
        // device that does not exist, so the push applies the port and leaves
        // the binding alone instead of naming a device.
        if !curl_available() {
            return;
        }
        let server = MockQBittorrentWebUi::start();
        let client = active_client().without_tunnel_interface();
        let path = crate::testing::temp_config_path("qbit-no-interface");

        sync_port(
            &client,
            &path,
            &config(server.url()),
            "uuid-eu",
            51820,
            None,
        )
        .expect("port sync should work");

        let pushed = server.last_set_preferences();
        assert!(
            !pushed.contains("current_network_interface"),
            "a missing interface must not be bound as a device: {pushed}"
        );
        assert!(
            pushed.contains("listen_port"),
            "the port itself must still be applied: {pushed}"
        );
        crate::testing::remove_temp_config(&path);
    }
}
