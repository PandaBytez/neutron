//! Pure Rust D-Bus StatusNotifierItem (AppIndicator) implementation using zbus.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::{debug, info, warn};
use zbus::interface;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};

use crate::error::AppResult;
use crate::nm::NmClient;

pub const INDICATOR_BUS_NAME: &str = "io.gitlab.neutron_vpn.indicator";

pub type ToolTipTuple = (String, Vec<(i32, i32, Vec<u8>)>, String, String);
pub type MenuLayoutResult<'a> = (u32, (i32, HashMap<String, Value<'a>>, Vec<Value<'a>>));

const CONNECTED_48_ARGB32: &[u8] = include_bytes!("../../resources/status/connected_48.argb32");
const CONNECTED_24_ARGB32: &[u8] = include_bytes!("../../resources/status/connected_24.argb32");
const DISCONNECTED_48_ARGB32: &[u8] =
    include_bytes!("../../resources/status/disconnected_48.argb32");
const DISCONNECTED_24_ARGB32: &[u8] =
    include_bytes!("../../resources/status/disconnected_24.argb32");

/// State shared between TUI/CLI and background StatusNotifierItem D-Bus service.
#[derive(Debug, Clone, Default)]
pub struct IndicatorSharedState {
    pub active_profile: Option<String>,
    pub forwarded_port: Option<u16>,
    pub menu_revision: u32,
}

pub fn install_status_icons() {
    let Some(data_dir) = dirs::data_dir() else {
        return;
    };

    let status_dir = data_dir.join("icons/hicolor/scalable/status");
    let _ = std::fs::create_dir_all(&status_dir);

    let conn_svg = include_bytes!("../../resources/status/neutron-vpn-connected.svg");
    let disconn_svg = include_bytes!("../../resources/status/neutron-vpn-disconnected.svg");

    let _ = std::fs::write(status_dir.join("neutron-vpn-connected.svg"), conn_svg);
    let _ = std::fs::write(status_dir.join("neutron-vpn-disconnected.svg"), disconn_svg);

    let dir_48 = data_dir.join("icons/hicolor/48x48/status");
    let _ = std::fs::create_dir_all(&dir_48);
    let _ = std::fs::write(
        dir_48.join("neutron-vpn-connected.png"),
        include_bytes!("../../resources/status/connected_48.png"),
    );
    let _ = std::fs::write(
        dir_48.join("neutron-vpn-disconnected.png"),
        include_bytes!("../../resources/status/disconnected_48.png"),
    );
}

fn icon_theme_path() -> String {
    dirs::data_dir()
        .map(|dir| dir.join("icons").to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Check if an indicator instance is already holding the well-known bus name.
pub fn is_indicator_running() -> bool {
    zbus::block_on(async {
        let Ok(conn) = zbus::Connection::session().await else {
            return false;
        };
        let Ok(dbus) = zbus::fdo::DBusProxy::new(&conn).await else {
            return false;
        };
        if let Ok(name) = zbus::names::WellKnownName::try_from(INDICATOR_BUS_NAME) {
            dbus.name_has_owner(zbus::names::BusName::WellKnown(name))
                .await
                .unwrap_or(false)
        } else {
            false
        }
    })
}

pub struct StatusNotifierItem {
    pub state: Arc<Mutex<IndicatorSharedState>>,
}

#[interface(name = "org.kde.StatusNotifierItem")]
impl StatusNotifierItem {
    #[zbus(property)]
    fn category(&self) -> &str {
        "ApplicationStatus"
    }

    #[zbus(property)]
    fn id(&self) -> &str {
        "neutron-vpn"
    }

    #[zbus(property)]
    fn title(&self) -> &str {
        "Neutron VPN"
    }

    #[zbus(property)]
    fn status(&self) -> &str {
        // Always advertise Active so panel hosts do not hide the disconnected icon
        "Active"
    }

    #[zbus(property)]
    fn icon_name(&self) -> &str {
        // Deliberately empty so host uses IconPixmap embedded bytes directly
        ""
    }

    #[zbus(property)]
    fn icon_pixmap(&self) -> Vec<(i32, i32, Vec<u8>)> {
        let is_conn = self
            .state
            .lock()
            .map(|st| st.active_profile.is_some())
            .unwrap_or(false);

        if is_conn {
            vec![
                (48, 48, CONNECTED_48_ARGB32.to_vec()),
                (24, 24, CONNECTED_24_ARGB32.to_vec()),
            ]
        } else {
            vec![
                (48, 48, DISCONNECTED_48_ARGB32.to_vec()),
                (24, 24, DISCONNECTED_24_ARGB32.to_vec()),
            ]
        }
    }

    #[zbus(property)]
    fn icon_theme_path(&self) -> String {
        icon_theme_path()
    }

    #[zbus(property)]
    fn menu(&self) -> OwnedObjectPath {
        ObjectPath::from_static_str("/MenuBar").unwrap().into()
    }

    #[zbus(property)]
    fn item_is_menu(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn tool_tip(&self) -> ToolTipTuple {
        let (title, desc) = if let Ok(st) = self.state.lock() {
            if let Some(ref name) = st.active_profile {
                let port_str = st
                    .forwarded_port
                    .map(|p| format!(" (Port: {p})"))
                    .unwrap_or_default();
                (
                    "Neutron VPN".to_string(),
                    format!("Connected: {name}{port_str}"),
                )
            } else {
                ("Neutron VPN".to_string(), "Disconnected".to_string())
            }
        } else {
            (
                "Neutron VPN".to_string(),
                "Neutron WireGuard Manager".to_string(),
            )
        };

        (String::new(), Vec::new(), title, desc)
    }

    fn activate(&self, _x: i32, _y: i32) {
        debug!("StatusNotifierItem: Activate triggered");
    }

    fn context_menu(&self, _x: i32, _y: i32) {
        debug!("StatusNotifierItem: ContextMenu triggered");
    }

    fn scroll(&self, _delta: i32, _orientation: &str) {
        debug!("StatusNotifierItem: Scroll triggered");
    }

    #[zbus(signal)]
    async fn new_icon(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn new_tool_tip(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn new_status(emitter: &SignalEmitter<'_>, status: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn new_title(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

pub struct DBusMenu<C> {
    pub client: C,
    pub state: Arc<Mutex<IndicatorSharedState>>,
}

#[interface(name = "com.canonical.dbusmenu")]
impl<C> DBusMenu<C>
where
    C: NmClient + Clone + Send + Sync + 'static,
{
    #[zbus(property)]
    fn version(&self) -> u32 {
        3
    }

    #[zbus(property)]
    fn status(&self) -> &str {
        "normal"
    }

    fn get_layout(
        &self,
        _parent_id: i32,
        _recursion_depth: i32,
        _property_names: Vec<String>,
    ) -> MenuLayoutResult<'_> {
        let (prof, port_opt, rev) = if let Ok(st) = self.state.lock() {
            (
                st.active_profile.clone(),
                st.forwarded_port,
                st.menu_revision,
            )
        } else {
            (None, None, 1)
        };

        let mut children = Vec::new();

        // 1. Toggle Connect / Disconnect
        let toggle_label = if let Some(ref name) = prof {
            format!("Disconnect ({name})")
        } else {
            "Quick Connect (Random Eligible)".to_string()
        };
        let mut toggle_props = HashMap::new();
        toggle_props.insert("label".to_string(), Value::from(toggle_label));
        toggle_props.insert("enabled".to_string(), Value::from(true));
        toggle_props.insert("visible".to_string(), Value::from(true));
        children.push(Value::from((2i32, toggle_props, Vec::<Value<'_>>::new())));

        // 2. Port Forwarding (Copy)
        if let Some(port) = port_opt {
            let mut port_props = HashMap::new();
            port_props.insert(
                "label".to_string(),
                Value::from(format!("Forwarded Port: {port} (Copy)")),
            );
            port_props.insert("enabled".to_string(), Value::from(true));
            port_props.insert("visible".to_string(), Value::from(true));
            children.push(Value::from((5i32, port_props, Vec::<Value<'_>>::new())));
        }

        // 3. Separator
        let mut sep_props = HashMap::new();
        sep_props.insert("type".to_string(), Value::from("separator"));
        sep_props.insert("visible".to_string(), Value::from(true));
        children.push(Value::from((3i32, sep_props, Vec::<Value<'_>>::new())));

        // 4. Quit
        let mut quit_props = HashMap::new();
        quit_props.insert("label".to_string(), Value::from("Quit Neutron"));
        quit_props.insert("enabled".to_string(), Value::from(true));
        quit_props.insert("visible".to_string(), Value::from(true));
        children.push(Value::from((4i32, quit_props, Vec::<Value<'_>>::new())));

        let mut root_props = HashMap::new();
        root_props.insert("children-display".to_string(), Value::from("submenu"));

        (rev, (0, root_props, children))
    }

    fn event(&self, id: i32, _event_id: &str, _data: Value<'_>, _timestamp: u32) {
        match id {
            2 => {
                let is_conn = self
                    .state
                    .lock()
                    .map(|st| st.active_profile.is_some())
                    .unwrap_or(false);
                let client = self.client.clone();
                if is_conn {
                    let _ = client.disconnect_active();
                } else {
                    let _ = crate::service::run_startup_random(&client);
                }
            }
            5 => {
                if let Ok(st) = self.state.lock()
                    && let Some(port) = st.forwarded_port
                {
                    copy_to_clipboard(&port.to_string());
                }
            }
            4 => {
                std::process::exit(0);
            }
            _ => {}
        }
    }

    fn about_to_show(&self, _id: i32) -> bool {
        false
    }

    #[zbus(signal)]
    async fn layout_updated(
        emitter: &SignalEmitter<'_>,
        revision: u32,
        parent: i32,
    ) -> zbus::Result<()>;
}

fn copy_to_clipboard(text: &str) {
    if std::process::Command::new("wl-copy")
        .arg(text)
        .status()
        .is_ok()
    {
        return;
    }
    use std::io::Write;
    if let Ok(mut child) = std::process::Command::new("xclip")
        .args(["-selection", "clipboard"])
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
        }
        let _ = child.wait();
    }
}

/// Spawn the background D-Bus StatusNotifierItem daemon thread.
pub fn spawn_indicator_service<C>(
    client: C,
    shared_state: Arc<Mutex<IndicatorSharedState>>,
) -> std::thread::JoinHandle<()>
where
    C: NmClient + Clone + Send + Sync + 'static,
{
    install_status_icons();

    std::thread::spawn(move || {
        zbus::block_on(async move {
            let conn = match zbus::Connection::session().await {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to connect to D-Bus session bus: {e}");
                    return;
                }
            };

            let Ok(dbus) = zbus::fdo::DBusProxy::new(&conn).await else {
                return;
            };

            let Ok(well_known) = zbus::names::WellKnownName::try_from(INDICATOR_BUS_NAME) else {
                return;
            };

            let reply = dbus
                .request_name(well_known, zbus::fdo::RequestNameFlags::DoNotQueue.into())
                .await;

            if !matches!(
                reply,
                Ok(zbus::fdo::RequestNameReply::PrimaryOwner)
                    | Ok(zbus::fdo::RequestNameReply::AlreadyOwner)
            ) {
                debug!("Indicator instance is already running, exiting duplicate.");
                return;
            }

            let sni = StatusNotifierItem {
                state: shared_state.clone(),
            };
            let menu = DBusMenu {
                client,
                state: shared_state.clone(),
            };

            let _ = conn.object_server().at("/StatusNotifierItem", sni).await;
            let _ = conn.object_server().at("/MenuBar", menu).await;

            // Register with both KDE and Freedesktop StatusNotifierWatchers
            for watcher_bus in [
                "org.kde.StatusNotifierWatcher",
                "org.freedesktop.StatusNotifierWatcher",
            ] {
                let _ = conn
                    .call_method(
                        Some(watcher_bus),
                        "/StatusNotifierWatcher",
                        Some(watcher_bus),
                        "RegisterStatusNotifierItem",
                        &("/StatusNotifierItem"),
                    )
                    .await;
            }

            // Monitor state changes and emit D-Bus signals so tray hosts immediately re-render!
            let mut last_profile: Option<String> = None;
            let mut last_port: Option<u16> = None;
            let mut last_rev: u32 = 0;

            loop {
                let (cur_profile, cur_port, cur_rev) = if let Ok(st) = shared_state.lock() {
                    (
                        st.active_profile.clone(),
                        st.forwarded_port,
                        st.menu_revision,
                    )
                } else {
                    (None, None, 0)
                };

                if cur_profile != last_profile || cur_port != last_port || cur_rev != last_rev {
                    last_profile = cur_profile;
                    last_port = cur_port;
                    last_rev = cur_rev;

                    // Emit signals to tray host
                    let _ = conn
                        .emit_signal(
                            Option::<&str>::None,
                            "/StatusNotifierItem",
                            "org.kde.StatusNotifierItem",
                            "NewIcon",
                            &(),
                        )
                        .await;
                    let _ = conn
                        .emit_signal(
                            Option::<&str>::None,
                            "/StatusNotifierItem",
                            "org.kde.StatusNotifierItem",
                            "NewToolTip",
                            &(),
                        )
                        .await;
                    let _ = conn
                        .emit_signal(
                            Option::<&str>::None,
                            "/StatusNotifierItem",
                            "org.kde.StatusNotifierItem",
                            "NewStatus",
                            &("Active"),
                        )
                        .await;
                    let _ = conn
                        .emit_signal(
                            Option::<&str>::None,
                            "/MenuBar",
                            "com.canonical.dbusmenu",
                            "LayoutUpdated",
                            &(cur_rev, 0i32),
                        )
                        .await;
                }

                std::thread::sleep(Duration::from_millis(200));
            }
        });
    })
}

/// Push a newly leased forwarded port to qBittorrent.
///
/// Gated behind the `qbittorrent` feature: the daemon calls this on every lease
/// renewal, so a broken integration would reach a third-party Web API
/// unattended. Compiled out unless the feature is enabled.
#[cfg(feature = "qbittorrent")]
fn sync_qbittorrent_port<C: NmClient>(client: &C, uuid: &str, port: u16) {
    let Ok(config) =
        crate::config::default_config_path().and_then(|path| crate::config::load(&path))
    else {
        return;
    };
    if !config.qbittorrent.enabled {
        return;
    }

    let interface = client
        .get_profile_diagnostics(uuid, true)
        .ok()
        .map(|diagnostics| diagnostics.interface_name);
    let mut qclient = crate::portforward::qbittorrent::QBittorrentClient::new(&config.qbittorrent);
    match qclient.sync_port(port, interface.as_deref()) {
        Ok(report) => info!(
            "qBittorrent port synced to {port} (interface: {:?})",
            report.bound_interface
        ),
        Err(error) => warn!("qBittorrent auto-sync failed: {error}"),
    }
}

/// No-op when the `qbittorrent` feature is disabled.
#[cfg(not(feature = "qbittorrent"))]
fn sync_qbittorrent_port<C: NmClient>(_: &C, _: &str, _: u16) {}

/// The currently active WireGuard profile, if any.
fn active_profile<C: NmClient>(client: &C) -> Option<crate::nm::WireguardProfile> {
    client
        .list_wireguard_profiles()
        .ok()?
        .into_iter()
        .find(|profile| profile.is_active())
}

/// How often the tray re-reads NetworkManager. Each poll spawns `nmcli`, so this
/// is deliberately slower than a UI refresh: the tray only has to notice a
/// connection change within a second or two.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Run standalone persistent indicator daemon in the foreground.
pub fn run_standalone_indicator<C>(client: C) -> AppResult<()>
where
    C: NmClient + Clone + Send + Sync + 'static,
{
    install_status_icons();

    if is_indicator_running() {
        debug!("Indicator daemon already active, exiting.");
        return Ok(());
    }

    info!("Starting Neutron persistent AppIndicator daemon...");

    let state = Arc::new(Mutex::new(IndicatorSharedState::default()));
    let _handle = spawn_indicator_service(client.clone(), state.clone());

    // The forwarded port is leased, not derived: it belongs to one tunnel and
    // expires on its own. So it is tracked alongside the profile that owns it,
    // and the lease clock advances only when a mapping actually succeeded --
    // otherwise a transient failure would wait a further `RENEW_INTERVAL` and
    // let the lease lapse, which is the very thing the interval exists to
    // prevent.
    let mut current: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut leased_at: Option<std::time::Instant> = None;

    loop {
        let active = active_profile(&client);
        let active_name = active.as_ref().map(|profile| profile.name.clone());

        if active_name != current {
            // A different tunnel (or none): the old lease is not ours anymore.
            current = active_name.clone();
            port = None;
            leased_at = None;
        }

        let port_forwarding_enabled = crate::config::default_config_path()
            .and_then(|path| crate::config::load(&path))
            .map(|cfg| cfg.port_forwarding.enabled)
            .unwrap_or(false);

        if !port_forwarding_enabled {
            port = None;
            leased_at = None;
        } else if let Some(profile) = active.as_ref()
            && leased_at.is_none_or(|at| at.elapsed() >= crate::portforward::RENEW_INTERVAL)
            && let Some(address) = client.tunnel_address(&profile.uuid)
        {
            leased_at = Some(std::time::Instant::now());
            if let Some(mapped) = crate::portforward::port_for_tunnel_address(&address) {
                let is_new_or_renewed_port = port != Some(mapped);
                port = Some(mapped);

                if is_new_or_renewed_port {
                    sync_qbittorrent_port(&client, &profile.uuid, mapped);
                }
            } else {
                port = None;
            }
        }

        if let Ok(mut st) = state.lock()
            && (st.active_profile != active_name || st.forwarded_port != port)
        {
            st.active_profile = active_name;
            st.forwarded_port = port;
            st.menu_revision += 1;
        }

        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nm::{ProfileState, WireguardProfile};
    use crate::testing::MockNmClient;

    fn make_sni(active_profile: Option<String>, port: Option<u16>) -> StatusNotifierItem {
        let state = Arc::new(Mutex::new(IndicatorSharedState {
            active_profile,
            forwarded_port: port,
            menu_revision: 1,
        }));
        StatusNotifierItem { state }
    }

    fn make_menu(active_profile: Option<String>, port: Option<u16>) -> DBusMenu<MockNmClient> {
        let state = Arc::new(Mutex::new(IndicatorSharedState {
            active_profile,
            forwarded_port: port,
            menu_revision: 1,
        }));
        let client = MockNmClient::default();
        DBusMenu { client, state }
    }

    #[test]
    fn icon_pixmap_returns_expected_resolutions_and_differs_by_state() {
        let sni_connected = make_sni(Some("wg-test".to_string()), None);
        let pix_connected = sni_connected.icon_pixmap();
        assert_eq!(pix_connected.len(), 2);
        assert_eq!(pix_connected[0].0, 48);
        assert_eq!(pix_connected[0].1, 48);
        assert_eq!(pix_connected[1].0, 24);
        assert_eq!(pix_connected[1].1, 24);

        let sni_disconnected = make_sni(None, None);
        let pix_disconnected = sni_disconnected.icon_pixmap();
        assert_eq!(pix_disconnected.len(), 2);
        assert_ne!(pix_connected[0].2, pix_disconnected[0].2);
    }

    #[test]
    fn tool_tip_formats_active_profile_and_port() {
        let sni = make_sni(Some("wg-fast".to_string()), Some(51820));
        let (_, _, title, desc) = sni.tool_tip();
        assert_eq!(title, "Neutron VPN");
        assert!(desc.contains("Connected: wg-fast"));
        assert!(desc.contains("Port: 51820"));

        let sni_disconnected = make_sni(None, None);
        let (_, _, title, desc) = sni_disconnected.tool_tip();
        assert_eq!(title, "Neutron VPN");
        assert_eq!(desc, "Disconnected");
    }

    #[test]
    fn get_layout_connected_includes_disconnect_and_port() {
        let menu = make_menu(Some("wg-fast".to_string()), Some(49152));
        let (rev, (root_id, _, children)) = menu.get_layout(0, 1, Vec::new());
        assert_eq!(rev, 1);
        assert_eq!(root_id, 0);

        // Children should contain: toggle (2), port (5), separator (3), quit (4)
        assert_eq!(children.len(), 4);
    }

    #[test]
    fn get_layout_disconnected_omits_port_and_shows_quick_connect() {
        let menu = make_menu(None, None);
        let (_, (_, _, children)) = menu.get_layout(0, 1, Vec::new());

        // Children should contain: toggle (2), separator (3), quit (4) (no port item)
        assert_eq!(children.len(), 3);
    }

    #[test]
    fn active_profile_extracts_active_profile_from_client() {
        let profiles = vec![
            WireguardProfile {
                name: "wg-1".to_string(),
                uuid: "uuid-1".to_string(),
                state: ProfileState::Inactive,
            },
            WireguardProfile {
                name: "wg-2".to_string(),
                uuid: "uuid-2".to_string(),
                state: ProfileState::Active,
            },
        ];
        let client = MockNmClient::new(profiles);
        let active = active_profile(&client);
        assert!(active.is_some());
        assert_eq!(active.unwrap().name, "wg-2");

        let client_none = MockNmClient::new(vec![WireguardProfile {
            name: "wg-1".to_string(),
            uuid: "uuid-1".to_string(),
            state: ProfileState::Inactive,
        }]);
        assert!(active_profile(&client_none).is_none());
    }
}
