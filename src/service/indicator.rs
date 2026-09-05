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
use crate::service::lease::QbitSyncStatus;

pub const INDICATOR_BUS_NAME: &str = "io.github.pandabytez.neutron.indicator";

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
    pub favorite_profiles: Vec<(String, String)>,
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

/// Ensure background indicator daemon is running (spawn once if not already active).
pub fn ensure_indicator_daemon_running() {
    if is_indicator_running() {
        return;
    }

    let program = crate::process::current_app_path();

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new(program);
        cmd.arg("indicator")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                unsafe extern "C" {
                    fn setsid() -> i32;
                }
                setsid();
                Ok(())
            });
        }
        let _ = cmd.spawn();
    }
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
        "neutron"
    }

    #[zbus(property)]
    fn title(&self) -> &str {
        "Neutron"
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
                    "Neutron".to_string(),
                    format!("Connected: {name}{port_str}"),
                )
            } else {
                ("Neutron".to_string(), "Disconnected".to_string())
            }
        } else {
            (
                "Neutron".to_string(),
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
        let (prof, port_opt, favorites, rev) = if let Ok(st) = self.state.lock() {
            (
                st.active_profile.clone(),
                st.forwarded_port,
                st.favorite_profiles.clone(),
                st.menu_revision,
            )
        } else {
            (None, None, Vec::new(), 1)
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

        // 2. Favorite Profiles Quick Actions
        if !favorites.is_empty() {
            let mut fav_sep = HashMap::new();
            fav_sep.insert("type".to_string(), Value::from("separator"));
            fav_sep.insert("visible".to_string(), Value::from(true));
            children.push(Value::from((10i32, fav_sep, Vec::<Value<'_>>::new())));

            for (idx, (_uuid, name)) in favorites.iter().enumerate() {
                let is_active = prof.as_deref() == Some(name.as_str());
                let label = if is_active {
                    format!("{name} (Active)")
                } else {
                    name.clone()
                };
                let mut fav_props = HashMap::new();
                fav_props.insert("label".to_string(), Value::from(label));
                fav_props.insert("enabled".to_string(), Value::from(true));
                fav_props.insert("visible".to_string(), Value::from(true));
                let item_id = 100 + idx as i32;
                children.push(Value::from((item_id, fav_props, Vec::<Value<'_>>::new())));
            }
        }

        // 3. Port Forwarding (Copy)
        if let Some(port) = port_opt {
            let mut port_sep = HashMap::new();
            port_sep.insert("type".to_string(), Value::from("separator"));
            port_sep.insert("visible".to_string(), Value::from(true));
            children.push(Value::from((11i32, port_sep, Vec::<Value<'_>>::new())));

            let mut port_props = HashMap::new();
            port_props.insert(
                "label".to_string(),
                Value::from(format!("Forwarded Port: {port} (Copy)")),
            );
            port_props.insert("enabled".to_string(), Value::from(true));
            port_props.insert("visible".to_string(), Value::from(true));
            children.push(Value::from((5i32, port_props, Vec::<Value<'_>>::new())));
        }

        // 4. Separator
        let mut sep_props = HashMap::new();
        sep_props.insert("type".to_string(), Value::from("separator"));
        sep_props.insert("visible".to_string(), Value::from(true));
        children.push(Value::from((3i32, sep_props, Vec::<Value<'_>>::new())));

        // 5. Quit
        let mut quit_props = HashMap::new();
        quit_props.insert("label".to_string(), Value::from("Quit Neutron"));
        quit_props.insert("enabled".to_string(), Value::from(true));
        quit_props.insert("visible".to_string(), Value::from(true));
        children.push(Value::from((4i32, quit_props, Vec::<Value<'_>>::new())));

        let mut root_props = HashMap::new();
        root_props.insert("children-display".to_string(), Value::from("submenu"));

        (rev, (0, root_props, children))
    }

    fn event(&self, id: i32, event_id: &str, _data: Value<'_>, _timestamp: u32) {
        if event_id != "clicked" {
            return;
        }

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
            item_id if item_id >= 100 => {
                let idx = (item_id - 100) as usize;
                if let Ok(st) = self.state.lock()
                    && let Some((uuid, _)) = st.favorite_profiles.get(idx)
                {
                    let _ = self.client.switch_to(uuid);
                }
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
    if let Ok(status) = std::process::Command::new("wl-copy").arg(text).status()
        && status.success()
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
        if let Ok(status) = child.wait()
            && status.success()
        {
            return;
        }
    }
    if let Ok(mut child) = std::process::Command::new("xsel")
        .args(["--clipboard", "--input"])
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

            // Monitor state changes on a background thread and emit D-Bus signals so tray hosts immediately re-render
            let conn_for_signals = conn.clone();
            std::thread::spawn(move || {
                let mut last_profile: Option<String> = None;
                let mut last_port: Option<u16> = None;
                let mut last_favs: Vec<(String, String)> = Vec::new();
                let mut last_rev: u32 = 0;

                loop {
                    let (cur_profile, cur_port, cur_favs, cur_rev) =
                        if let Ok(st) = shared_state.lock() {
                            (
                                st.active_profile.clone(),
                                st.forwarded_port,
                                st.favorite_profiles.clone(),
                                st.menu_revision,
                            )
                        } else {
                            (None, None, Vec::new(), 0)
                        };

                    if cur_profile != last_profile
                        || cur_port != last_port
                        || cur_favs != last_favs
                        || cur_rev != last_rev
                    {
                        last_profile = cur_profile;
                        last_port = cur_port;
                        last_favs = cur_favs;
                        last_rev = cur_rev;

                        // Emit signals to tray host
                        zbus::block_on(async {
                            let _ = conn_for_signals
                                .emit_signal(
                                    Option::<&str>::None,
                                    "/StatusNotifierItem",
                                    "org.kde.StatusNotifierItem",
                                    "NewIcon",
                                    &(),
                                )
                                .await;
                            let _ = conn_for_signals
                                .emit_signal(
                                    Option::<&str>::None,
                                    "/StatusNotifierItem",
                                    "org.kde.StatusNotifierItem",
                                    "NewToolTip",
                                    &(),
                                )
                                .await;
                            let _ = conn_for_signals
                                .emit_signal(
                                    Option::<&str>::None,
                                    "/StatusNotifierItem",
                                    "org.kde.StatusNotifierItem",
                                    "NewStatus",
                                    &("Active"),
                                )
                                .await;
                            let _ = conn_for_signals
                                .emit_signal(
                                    Option::<&str>::None,
                                    "/MenuBar",
                                    "com.canonical.dbusmenu",
                                    "LayoutUpdated",
                                    &(cur_rev, 0i32),
                                )
                                .await;
                        });
                    }

                    std::thread::sleep(Duration::from_millis(200));
                }
            });

            // Keep D-Bus connection processing all incoming requests with 0ms latency
            std::future::pending::<()>().await
        });
    })
}

/// Push a newly leased forwarded port to qBittorrent, reporting what came of it
/// so the daemon can publish the verdict for the TUI to render.
///
/// Gated behind the `qbittorrent` feature: the daemon calls this on every lease
/// renewal, so a broken integration would reach a third-party Web API
/// unattended. Compiled out unless the feature is enabled.
#[cfg(feature = "qbittorrent")]
fn sync_qbittorrent_port<C: NmClient>(client: &C, uuid: &str, port: u16) -> QbitSyncStatus {
    let Ok(config) =
        crate::config::default_config_path().and_then(|path| crate::config::load(&path))
    else {
        return QbitSyncStatus::Pending;
    };
    if !config.qbittorrent.enabled {
        return QbitSyncStatus::Pending;
    }

    match crate::app::qbittorrent::sync_port(client, &config.qbittorrent, uuid, port) {
        Ok(report) => {
            info!(
                "qBittorrent port synced to {port} (interface: {:?})",
                report.bound_interface
            );
            QbitSyncStatus::Synchronized
        }
        Err(error) => {
            warn!("qBittorrent auto-sync failed: {error}");
            QbitSyncStatus::Failed
        }
    }
}

/// No-op when the `qbittorrent` feature is disabled.
#[cfg(not(feature = "qbittorrent"))]
fn sync_qbittorrent_port<C: NmClient>(_: &C, _: &str, _: u16) -> QbitSyncStatus {
    QbitSyncStatus::Pending
}

/// The daemon's running record of the forwarded-port lease.
///
/// The port is leased, not derived: it belongs to one tunnel, expires on its
/// own, and has to be renewed before it lapses. Those rules were previously
/// inlined in the poll loop, where two of them were wrong and neither could be
/// tested; they live here so each one can be stated and checked on its own.
#[derive(Debug, Default)]
struct LeaseTracker {
    /// The tunnel the lease belongs to, by uuid.
    tunnel_uuid: Option<String>,
    /// The port the gateway mapped.
    port: Option<u16>,
    /// When the mapping last succeeded. Advanced only on success, so a transient
    /// failure retries on the next poll rather than waiting out another
    /// [`crate::portforward::RENEW_INTERVAL`] and letting the lease lapse.
    leased_at: Option<std::time::Instant>,
    /// What became of the last push to qBittorrent.
    qbit_sync: QbitSyncStatus,
}

impl LeaseTracker {
    /// Drop the lease unless it still belongs to `active_uuid`.
    ///
    /// Compared by uuid rather than by name because NetworkManager allows two
    /// profiles to share a name. Keyed by name, a switch between two such
    /// profiles reads as no change at all, and the lease obtained for one goes on
    /// being published against the other -- which is how a port ends up bound to
    /// the wrong interface.
    fn follow_tunnel(&mut self, active_uuid: &Option<String>) {
        if self.tunnel_uuid != *active_uuid {
            self.tunnel_uuid = active_uuid.clone();
            self.release();
        }
    }

    /// Give up the lease and everything said about it.
    fn release(&mut self) {
        self.port = None;
        self.leased_at = None;
        self.qbit_sync = QbitSyncStatus::Pending;
    }

    /// Whether the mapping should be renewed on this poll.
    fn is_due(&self) -> bool {
        self.leased_at
            .is_none_or(|at| at.elapsed() >= crate::portforward::RENEW_INTERVAL)
    }

    /// Record the outcome of a renewal, reporting whether qBittorrent should now
    /// be told about the port.
    ///
    /// A renewal normally returns the same port, so a push gated only on the port
    /// *changing* would never retry: qBittorrent started after a failed first
    /// attempt would stay unsynced for the life of the tunnel, showing a failure
    /// the user has no way to clear. A previous failure is therefore retried on
    /// every renewal.
    fn record(&mut self, mapped: Option<u16>) -> bool {
        self.leased_at = Some(std::time::Instant::now());

        let Some(mapped) = mapped else {
            self.release();
            return false;
        };

        let changed = self.port != Some(mapped);
        self.port = Some(mapped);
        changed || self.qbit_sync == QbitSyncStatus::Failed
    }

    /// The lease as published for the TUI.
    fn publication(&self, profile_uuid: Option<String>) -> crate::service::lease::LeaseState {
        crate::service::lease::LeaseState {
            port: self.port,
            profile_uuid,
            qbit_sync: self.qbit_sync,
            // Stamped on publication; the caller has no business inventing a time.
            ..Default::default()
        }
    }
}

/// The currently active WireGuard profile, if any.
#[cfg(test)]
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
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

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

    // The check above asks the session bus, so it cannot answer when there is no
    // session bus -- and that is exactly when a second daemon gets spawned. The
    // published lease carries its author's pid, which settles ownership without
    // needing a bus at all. Without this, every launch would add another NAT-PMP
    // renewer on one lease and another writer against one qBittorrent.
    if let Some(owner) = crate::service::lease::live_owner()
        && owner != std::process::id()
    {
        debug!("Neutron daemon {owner} already holds the port lease, exiting.");
        return Ok(());
    }

    info!("Starting Neutron persistent AppIndicator daemon...");

    let state = Arc::new(Mutex::new(IndicatorSharedState::default()));
    let _handle = spawn_indicator_service(client.clone(), state.clone());

    let mut lease = LeaseTracker::default();

    loop {
        let profiles = client.list_wireguard_profiles().unwrap_or_default();
        let active = profiles.iter().find(|p| p.is_active());
        let active_name = active.map(|profile| profile.name.clone());
        let active_uuid = active.map(|profile| profile.uuid.clone());

        let app_cfg = crate::config::default_config_path()
            .ok()
            .and_then(|path| crate::config::load(&path).ok())
            .unwrap_or_default();

        let favorites: Vec<(String, String)> = profiles
            .iter()
            .filter(|p| app_cfg.favorite_profile_ids.contains(&p.uuid))
            .map(|p| (p.uuid.clone(), p.name.clone()))
            .collect();

        lease.follow_tunnel(&active_uuid);

        if !app_cfg.port_forwarding.enabled {
            lease.release();
        } else if let Some(profile) = active
            && lease.is_due()
            && let Some(address) = client.tunnel_address(&profile.uuid)
        {
            let mapped = crate::portforward::port_for_tunnel_address(&address);
            if lease.record(mapped) {
                lease.qbit_sync =
                    sync_qbittorrent_port(&client, &profile.uuid, lease.port.unwrap_or_default());
            }
        }

        // Republished every poll even when nothing changed: the timestamp is how
        // a reader tells a held lease from one left behind by a dead daemon.
        crate::service::lease::publish(&lease.publication(active_uuid.clone()));

        if let Ok(mut st) = state.lock()
            && (st.active_profile != active_name
                || st.forwarded_port != lease.port
                || st.favorite_profiles != favorites)
        {
            st.active_profile = active_name;
            st.forwarded_port = lease.port;
            st.favorite_profiles = favorites;
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
            favorite_profiles: Vec::new(),
            menu_revision: 1,
        }));
        StatusNotifierItem { state }
    }

    fn make_menu(active_profile: Option<String>, port: Option<u16>) -> DBusMenu<MockNmClient> {
        let state = Arc::new(Mutex::new(IndicatorSharedState {
            active_profile,
            forwarded_port: port,
            favorite_profiles: Vec::new(),
            menu_revision: 1,
        }));
        let client = MockNmClient::default();
        DBusMenu { client, state }
    }

    #[test]
    fn a_lease_survives_a_poll_that_finds_the_same_tunnel() {
        let mut lease = LeaseTracker::default();
        let eu = Some("uuid-eu".to_string());

        lease.follow_tunnel(&eu);
        lease.record(Some(51820));
        lease.follow_tunnel(&eu);

        assert_eq!(lease.port, Some(51820));
    }

    #[test]
    fn a_lease_is_dropped_when_the_tunnel_changes() {
        let mut lease = LeaseTracker::default();

        lease.follow_tunnel(&Some("uuid-eu".to_string()));
        lease.record(Some(51820));
        lease.follow_tunnel(&Some("uuid-us".to_string()));

        assert_eq!(lease.port, None, "the new tunnel has no lease yet");
        assert_eq!(lease.qbit_sync, QbitSyncStatus::Pending);
    }

    #[test]
    fn two_profiles_sharing_a_name_are_still_different_tunnels() {
        // NetworkManager allows duplicate connection names. Keyed by name, this
        // switch reads as no change, and the lease obtained for the first
        // profile goes on being published against the second -- handing
        // qBittorrent one profile's port bound to the other's interface.
        let mut lease = LeaseTracker::default();

        lease.follow_tunnel(&Some("uuid-first".to_string()));
        lease.record(Some(51820));
        lease.follow_tunnel(&Some("uuid-second".to_string()));

        assert_eq!(lease.port, None);
    }

    #[test]
    fn a_renewal_returning_the_same_port_does_not_re_push() {
        let mut lease = LeaseTracker::default();
        lease.follow_tunnel(&Some("uuid-eu".to_string()));

        assert!(
            lease.record(Some(51820)),
            "the first mapping must be pushed"
        );
        assert!(
            !lease.record(Some(51820)),
            "an unchanged port needs no second push"
        );
    }

    #[test]
    fn a_renewal_returning_a_different_port_is_pushed() {
        let mut lease = LeaseTracker::default();
        lease.follow_tunnel(&Some("uuid-eu".to_string()));
        lease.record(Some(51820));

        assert!(lease.record(Some(40000)));
    }

    #[test]
    fn a_failed_push_is_retried_on_the_next_renewal() {
        // Otherwise qBittorrent started after the first attempt stays unsynced
        // for the life of the tunnel, showing a failure the user cannot clear:
        // the port is stable, so "push only when it changes" means never again.
        let mut lease = LeaseTracker::default();
        lease.follow_tunnel(&Some("uuid-eu".to_string()));
        lease.record(Some(51820));
        lease.qbit_sync = QbitSyncStatus::Failed;

        assert!(
            lease.record(Some(51820)),
            "a failure must be retried even though the port is unchanged"
        );
    }

    #[test]
    fn a_successful_push_is_not_retried_forever() {
        let mut lease = LeaseTracker::default();
        lease.follow_tunnel(&Some("uuid-eu".to_string()));
        lease.record(Some(51820));
        lease.qbit_sync = QbitSyncStatus::Synchronized;

        assert!(!lease.record(Some(51820)));
    }

    #[test]
    fn a_renewal_that_maps_nothing_gives_up_the_lease() {
        let mut lease = LeaseTracker::default();
        lease.follow_tunnel(&Some("uuid-eu".to_string()));
        lease.record(Some(51820));

        assert!(!lease.record(None), "there is no port to push");
        assert_eq!(lease.port, None);
        assert_eq!(lease.qbit_sync, QbitSyncStatus::Pending);
    }

    #[test]
    fn a_fresh_lease_is_not_due_for_renewal_but_an_unheld_one_is() {
        let mut lease = LeaseTracker::default();
        assert!(lease.is_due(), "with no lease there is nothing to wait for");

        lease.record(Some(51820));
        assert!(
            !lease.is_due(),
            "a just-renewed lease must not be re-requested"
        );
    }

    #[test]
    fn get_layout_with_favorites_includes_quick_actions() {
        let state = Arc::new(Mutex::new(IndicatorSharedState {
            active_profile: Some("wg-fast".to_string()),
            forwarded_port: None,
            favorite_profiles: vec![
                ("uuid-fast".to_string(), "wg-fast".to_string()),
                ("uuid-backup".to_string(), "wg-backup".to_string()),
            ],
            menu_revision: 1,
        }));
        let client = MockNmClient::default();
        let menu = DBusMenu { client, state };

        let (_, (_, _, children)) = menu.get_layout(0, 1, Vec::new());
        // Children should contain: toggle (2), separator (10), fav 1 (100), fav 2 (101), separator (3), quit (4)
        assert_eq!(children.len(), 6);
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
        assert_eq!(title, "Neutron");
        assert!(desc.contains("Connected: wg-fast"));
        assert!(desc.contains("Port: 51820"));

        let sni_disconnected = make_sni(None, None);
        let (_, _, title, desc) = sni_disconnected.tool_tip();
        assert_eq!(title, "Neutron");
        assert_eq!(desc, "Disconnected");
    }

    #[test]
    fn get_layout_connected_includes_disconnect_and_port() {
        let menu = make_menu(Some("wg-fast".to_string()), Some(49152));
        let (rev, (root_id, _, children)) = menu.get_layout(0, 1, Vec::new());
        assert_eq!(rev, 1);
        assert_eq!(root_id, 0);

        // Children should contain: toggle (2), port separator (11), port (5), separator (3), quit (4)
        assert_eq!(children.len(), 5);
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
