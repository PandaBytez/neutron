use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use adw::prelude::*;
use gtk::gdk;
use gtk::gio;
use gtk::gio::glib::{self, Variant, VariantTy};
use tracing::{debug, error, info, warn};

use crate::nm::NmClient;
use crate::{APP_ID, APP_NAME};

pub const ICON_CONNECTED: &str = "neutron-vpn-connected";
pub const ICON_DISCONNECTED: &str = "neutron-vpn-disconnected";

const SNI_PATH: &str = "/StatusNotifierItem";
const SNI_INTERFACE: &str = "org.kde.StatusNotifierItem";
const MENU_PATH: &str = "/MenuBar";
const MENU_INTERFACE: &str = "com.canonical.dbusmenu";
const PORTAL_DESKTOP_DEST: &str = "org.freedesktop.portal.Desktop";
const PORTAL_DESKTOP_PATH: &str = "/org/freedesktop/portal/desktop";
const PORTAL_BACKGROUND_IFACE: &str = "org.freedesktop.portal.Background";
const PORTAL_REGISTRY_IFACE: &str = "org.freedesktop.host.portal.Registry";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum MenuItem {
    Root = 0,
    Show = 1,
    ToggleConnect = 2,
    Separator = 3,
    Quit = 4,
    PortForwarding = 5,
}

impl MenuItem {
    pub const ORDER: [MenuItem; 5] = [
        MenuItem::Show,
        MenuItem::PortForwarding,
        MenuItem::ToggleConnect,
        MenuItem::Separator,
        MenuItem::Quit,
    ];

    pub fn from_i32(id: i32) -> Option<Self> {
        match id {
            0 => Some(MenuItem::Root),
            1 => Some(MenuItem::Show),
            2 => Some(MenuItem::ToggleConnect),
            3 => Some(MenuItem::Separator),
            4 => Some(MenuItem::Quit),
            5 => Some(MenuItem::PortForwarding),
            _ => None,
        }
    }

    pub fn id(self) -> i32 {
        self as i32
    }
}

/// Icon theme base directory advertised to the tray host, i.e. the directory
/// `install_status_icons` writes into (`~/.local/share/icons`).
///
/// `IconName` is resolved by the *host* (GNOME Shell), not by this process, and
/// the host loaded its icon theme long before this app first ran. Leaving this
/// empty left the host resolving `neutron-vpn-connected` against whatever it
/// happened to already know about, which is why the tray fell back to a
/// placeholder even though the files were installed and resolvable here.
///
/// Returns an empty string when the data directory cannot be determined; the
/// property is optional, and hosts fall back to `IconPixmap`.
fn icon_theme_path() -> String {
    dirs::data_dir()
        .map(|dir| dir.join("icons").to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Artwork for the tray shields, embedded so the pixmap never depends on what
/// is installed on disk.
const CONNECTED_PNG: &[u8] = include_bytes!("../../resources/status/connected_48.png");
const DISCONNECTED_PNG: &[u8] = include_bytes!("../../resources/status/disconnected_48.png");

/// Convert GDK's premultiplied BGRA bytes into the ARGB32 layout that
/// StatusNotifierItem specifies (network byte order, so `A R G B` per pixel).
///
/// Alpha is un-premultiplied on the way out: the shields are a solid fill with
/// an antialiased rim, and leaving the edge pixels premultiplied against black
/// would draw a dark halo around them on light panels.
fn argb32_from_premultiplied_bgra(bgra: &[u8]) -> Vec<u8> {
    // `as_chunks` yields `&[u8; 4]`, so the per-pixel channels destructure
    // directly instead of going through fallible indexing. A trailing partial
    // pixel (`.1`) is discarded, matching `chunks_exact`.
    bgra.as_chunks::<4>()
        .0
        .iter()
        .flat_map(|&[b, g, r, a]| {
            let straight = |channel: u8| match a {
                0 => 0,
                _ => ((channel as u32 * 255) / a as u32).min(255) as u8,
            };
            [a, straight(r), straight(g), straight(b)]
        })
        .collect()
}

/// Decode one embedded shield into `(width, height, ARGB32 bytes)`.
///
/// GDK decodes PNG itself, so this needs no gdk-pixbuf or glycin loader to be
/// present on the host -- which matters for an AppImage.
fn decode_pixmap(png: &'static [u8]) -> Option<(i32, i32, Vec<u8>)> {
    let texture = gdk::Texture::from_bytes(&glib::Bytes::from_static(png)).ok()?;
    let (width, height) = (texture.width(), texture.height());
    let stride = width as usize * 4;
    let mut bgra = vec![0u8; stride * height as usize];
    texture.download(&mut bgra, stride);
    Some((width, height, argb32_from_premultiplied_bgra(&bgra)))
}

/// The `a(iiay)` pixmap the tray falls back to when it cannot resolve
/// [`status_icon`] from its icon theme.
///
/// Supplying this is what makes the indicator independent of icon-theme state:
/// the host renders these bytes directly. Decoded once per state and cached,
/// since the property is re-read on every icon change.
fn icon_pixmap(connected: bool) -> Variant {
    static CONNECTED: OnceLock<Option<(i32, i32, Vec<u8>)>> = OnceLock::new();
    static DISCONNECTED: OnceLock<Option<(i32, i32, Vec<u8>)>> = OnceLock::new();

    let cached = if connected {
        CONNECTED.get_or_init(|| decode_pixmap(CONNECTED_PNG))
    } else {
        DISCONNECTED.get_or_init(|| decode_pixmap(DISCONNECTED_PNG))
    };

    match cached {
        Some((width, height, data)) => vec![(*width, *height, data.clone())].to_variant(),
        None => Vec::<(i32, i32, Vec<u8>)>::new().to_variant(),
    }
}

const SNI_XML: &str = r#"
<node>
  <interface name="org.kde.StatusNotifierItem">
    <property name="Category" type="s" access="read"/>
    <property name="Id" type="s" access="read"/>
    <property name="Title" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="WindowId" type="i" access="read"/>
    <property name="IconThemePath" type="s" access="read"/>
    <property name="ItemIsMenu" type="b" access="read"/>
    <property name="Menu" type="o" access="read"/>
    <property name="IconName" type="s" access="read"/>
    <property name="IconPixmap" type="a(iiay)" access="read"/>
    <property name="OverlayIconName" type="s" access="read"/>
    <property name="OverlayIconPixmap" type="a(iiay)" access="read"/>
    <property name="AttentionIconName" type="s" access="read"/>
    <property name="AttentionIconPixmap" type="a(iiay)" access="read"/>
    <property name="AttentionMovieName" type="s" access="read"/>
    <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
    <method name="ContextMenu">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="Activate">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="SecondaryActivate">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="Scroll">
      <arg name="delta" type="i" direction="in"/>
      <arg name="orientation" type="s" direction="in"/>
    </method>
    <signal name="NewTitle"/>
    <signal name="NewIcon"/>
    <signal name="NewAttentionIcon"/>
    <signal name="NewOverlayIcon"/>
    <signal name="NewToolTip"/>
    <signal name="NewStatus">
      <arg name="status" type="s"/>
    </signal>
    <signal name="NewMenu"/>
  </interface>
</node>
"#;

const DBUSMENU_XML: &str = r#"
<node>
  <interface name="com.canonical.dbusmenu">
    <property name="Version" type="u" access="read"/>
    <property name="Status" type="s" access="read"/>
    <method name="GetLayout">
      <arg name="parentId" type="i" direction="in"/>
      <arg name="recursionDepth" type="i" direction="in"/>
      <arg name="propertyNames" type="as" direction="in"/>
      <arg name="revision" type="u" direction="out"/>
      <arg name="layout" type="(ia{sv}av)" direction="out"/>
    </method>
    <method name="GetGroupProperties">
      <arg name="ids" type="ai" direction="in"/>
      <arg name="propertyNames" type="as" direction="in"/>
      <arg name="properties" type="a(ia{sv})" direction="out"/>
    </method>
    <method name="GetProperty">
      <arg name="id" type="i" direction="in"/>
      <arg name="name" type="s" direction="in"/>
      <arg name="value" type="v" direction="out"/>
    </method>
    <method name="Event">
      <arg name="id" type="i" direction="in"/>
      <arg name="eventId" type="s" direction="in"/>
      <arg name="data" type="v" direction="in"/>
      <arg name="timestamp" type="u" direction="in"/>
    </method>
    <method name="AboutToShow">
      <arg name="id" type="i" direction="in"/>
      <arg name="needUpdate" type="b" direction="out"/>
    </method>
    <signal name="LayoutUpdated">
      <arg name="revision" type="u"/>
      <arg name="parent" type="i"/>
    </signal>
    <signal name="ItemPropertiesUpdated">
      <arg name="updatedProps" type="a(ia{sv})"/>
      <arg name="removedProps" type="a(ias)"/>
    </signal>
  </interface>
</node>
"#;

/// Assemble one dbusmenu `(ia{sv}av)` layout node.
///
/// The tuple is built through [`Variant::tuple_from_iter`] rather than
/// `(..).to_variant()` on a Rust tuple: the latter routes the already-typed
/// `a{sv}` properties through `ToVariant for Variant`, which boxes them into a
/// `v` and makes GNOME Shell reject the reply.
fn menu_item(id: i32, props: Variant, children: Vec<Variant>) -> Variant {
    Variant::tuple_from_iter([
        id.to_variant(),
        props,
        Variant::array_from_iter::<Variant>(children),
    ])
}

fn menu_object_path_variant() -> Variant {
    static PATH: OnceLock<Variant> = OnceLock::new();
    PATH.get_or_init(|| {
        Variant::parse(None, &format!("objectpath '{MENU_PATH}'")).expect("valid object path")
    })
    .clone()
}

/// Build the `a{sv}` property dictionary for one dbusmenu item.
///
/// The DBusMenu spec types item properties as `a{sv}`, so the dictionary is
/// finished with [`glib::VariantDict::end`]. Using `to_variant()` here would
/// instead yield a boxed `v`, which makes GNOME Shell reject the whole
/// `GetLayout` reply ("Type of return value is incorrect") and render an empty
/// menu.
fn get_item_dict(
    item: MenuItem,
    is_conn: bool,
    prof: Option<&str>,
    port: Option<u16>,
) -> Option<Variant> {
    let dict = glib::VariantDict::new(None);
    match item {
        MenuItem::Root => {
            dict.insert("children-display", "submenu");
            Some(dict.end())
        }
        MenuItem::Show => {
            let label = format!("Show {APP_NAME}");
            dict.insert("label", label.as_str());
            dict.insert("enabled", true);
            dict.insert("visible", true);
            Some(dict.end())
        }
        MenuItem::ToggleConnect => {
            let label = if is_conn {
                if let Some(name) = prof {
                    format!("Disconnect ({name})")
                } else {
                    "Disconnect".to_string()
                }
            } else {
                "Connect".to_string()
            };
            dict.insert("label", label.as_str());
            dict.insert("enabled", true);
            dict.insert("visible", true);
            Some(dict.end())
        }
        MenuItem::Separator => {
            dict.insert("type", "separator");
            dict.insert("visible", true);
            Some(dict.end())
        }
        MenuItem::Quit => {
            dict.insert("label", "Quit");
            dict.insert("enabled", true);
            dict.insert("visible", true);
            Some(dict.end())
        }
        MenuItem::PortForwarding => {
            if let Some(p) = port {
                let label = format!("Port Forwarding: {p} (Copy)");
                dict.insert("label", label.as_str());
                dict.insert("enabled", true);
                dict.insert("visible", true);
                Some(dict.end())
            } else {
                None
            }
        }
    }
}

fn build_tooltip_variant(
    is_conn: bool,
    profile_name: Option<String>,
    port_opt: Option<u16>,
) -> Variant {
    let sub = if is_conn {
        let name = profile_name.as_deref().unwrap_or("Connected");
        match port_opt {
            Some(port) => {
                format!("Connected: {name}\nForwarded port: {port}")
            }
            None => format!("Connected: {name}"),
        }
    } else {
        "Disconnected".to_string()
    };
    let empty_pixmap = Vec::<(i32, i32, Vec<u8>)>::new();
    ("", empty_pixmap, APP_NAME, sub.as_str()).to_variant()
}

#[derive(Clone)]
struct IndicatorState {
    connected: Arc<AtomicBool>,
    active_profile: Arc<Mutex<Option<String>>>,
    active_port: Arc<Mutex<Option<u16>>>,
    menu_revision: Arc<AtomicU32>,
}

fn register_sni_object(
    conn: &gio::DBusConnection,
    window_weak: glib::WeakRef<adw::ApplicationWindow>,
    state: &IndicatorState,
) {
    if let Ok(node_info) = gio::DBusNodeInfo::for_xml(SNI_XML)
        && let Some(iface_info) = node_info.lookup_interface(SNI_INTERFACE)
    {
        let win_for_activate = window_weak;
        let connected = state.connected.clone();
        let active_profile = state.active_profile.clone();
        let active_port = state.active_port.clone();

        let reg_res = conn
            .register_object(SNI_PATH, &iface_info)
            .method_call(
                move |_conn, _sender, _path, _iface, method, _params, invocation| match method {
                    "Activate" | "SecondaryActivate" | "ContextMenu" => {
                        if let Some(win) = win_for_activate.upgrade() {
                            win.set_visible(true);
                            win.present();
                        }
                        invocation.return_value(None);
                    }
                    "Scroll" => {
                        invocation.return_value(None);
                    }
                    _ => {
                        invocation.return_error(gio::DBusError::UnknownMethod, "Unknown method");
                    }
                },
            )
            .property(move |_conn, _sender, _path, _iface, property| {
                let is_conn = connected.load(Ordering::Relaxed);
                let profile_name = active_profile.lock().unwrap().clone();
                let port_opt = *active_port.lock().unwrap();
                match property {
                    "Category" => "ApplicationStatus".to_variant(),
                    "Id" => "neutron-vpn".to_variant(),
                    "Title" => APP_NAME.to_variant(),
                    "Status" => "Active".to_variant(),
                    "WindowId" => 0i32.to_variant(),
                    "IconThemePath" => icon_theme_path().to_variant(),
                    "ItemIsMenu" => false.to_variant(),
                    "Menu" => menu_object_path_variant(),
                    "IconName" => "".to_variant(),
                    "IconPixmap" => icon_pixmap(is_conn),
                    "OverlayIconName" => "".to_variant(),
                    "OverlayIconPixmap" => Vec::<(i32, i32, Vec<u8>)>::new().to_variant(),
                    "AttentionIconName" => "".to_variant(),
                    "AttentionIconPixmap" => Vec::<(i32, i32, Vec<u8>)>::new().to_variant(),
                    "AttentionMovieName" => "".to_variant(),
                    "ToolTip" => build_tooltip_variant(is_conn, profile_name, port_opt),
                    _ => "".to_variant(),
                }
            })
            .build();

        if let Err(err) = reg_res {
            error!("Failed to register StatusNotifierItem object: {err}");
        }
    }
}

fn register_dbusmenu_object<C>(
    conn: &gio::DBusConnection,
    window_weak: glib::WeakRef<adw::ApplicationWindow>,
    app_weak: glib::WeakRef<adw::Application>,
    client: C,
    state: &IndicatorState,
) where
    C: NmClient + Clone + Send + 'static,
{
    if let Ok(node_info) = gio::DBusNodeInfo::for_xml(DBUSMENU_XML)
        && let Some(iface_info) = node_info.lookup_interface(MENU_INTERFACE)
    {
        let connected = state.connected.clone();
        let active_profile = state.active_profile.clone();
        let active_port = state.active_port.clone();
        let menu_revision = state.menu_revision.clone();

        let reg_res = conn
            .register_object(MENU_PATH, &iface_info)
            .method_call(
                move |_conn, _sender, _path, _iface, method, params, invocation| {
                    let is_conn = connected.load(Ordering::Relaxed);
                    let prof = active_profile.lock().unwrap().clone();
                    let port_opt = *active_port.lock().unwrap();
                    let rev = menu_revision.load(Ordering::Relaxed);

                    match method {
                        "GetLayout" => {
                            let mut children = Vec::new();
                            for item in MenuItem::ORDER {
                                let Some(props) =
                                    get_item_dict(item, is_conn, prof.as_deref(), port_opt)
                                else {
                                    continue;
                                };
                                let node = menu_item(item.id(), props, Vec::new());
                                children.push(Variant::from_variant(&node));
                            }

                            let root_props =
                                get_item_dict(MenuItem::Root, is_conn, prof.as_deref(), port_opt)
                                    .expect("root menu item is always present");
                            let root = menu_item(MenuItem::Root.id(), root_props, children);

                            let reply = Variant::tuple_from_iter([rev.to_variant(), root]);
                            invocation.return_value(Some(&reply));
                        }
                        "GetGroupProperties" => {
                            let ids_var = params.child_value(0);
                            let ids_to_fetch: Vec<i32> = match ids_var.get::<Vec<i32>>() {
                                Some(ids) if !ids.is_empty() => ids,
                                _ => vec![0, 1, 5, 2, 3, 4],
                            };

                            let mut group_props = Vec::new();
                            for id in ids_to_fetch {
                                if let Some(item) = MenuItem::from_i32(id)
                                    && let Some(props) =
                                        get_item_dict(item, is_conn, prof.as_deref(), port_opt)
                                {
                                    group_props
                                        .push(Variant::tuple_from_iter([id.to_variant(), props]));
                                }
                            }
                            let array = Variant::array_from_iter_with_type(
                                VariantTy::new("(ia{sv})").expect("valid signature"),
                                group_props,
                            );
                            let reply = Variant::tuple_from_iter([array]);
                            invocation.return_value(Some(&reply));
                        }
                        "GetProperty" => {
                            invocation.return_value(None);
                        }
                        "Event" => {
                            let id_var = params.child_value(0);
                            if let Some(id) = id_var.get::<i32>()
                                && let Some(item) = MenuItem::from_i32(id)
                            {
                                match item {
                                    MenuItem::Show => {
                                        if let Some(win) = window_weak.upgrade() {
                                            win.set_visible(true);
                                            win.present();
                                        }
                                    }
                                    MenuItem::ToggleConnect => {
                                        let client_task = client.clone();
                                        gio::spawn_blocking(move || {
                                            if is_conn {
                                                let _ = client_task.disconnect_active();
                                            } else {
                                                let _ = crate::service::run_startup_random(
                                                    &client_task,
                                                );
                                            }
                                        });
                                    }
                                    MenuItem::Quit => {
                                        if let Some(win) = window_weak.upgrade() {
                                            win.destroy();
                                        }
                                        if let Some(app) = app_weak.upgrade() {
                                            app.quit();
                                        }
                                    }
                                    MenuItem::PortForwarding => {
                                        if let Some(port) = port_opt
                                            && let Some(display) = gdk::Display::default()
                                        {
                                            display.clipboard().set_text(&port.to_string());
                                        }
                                    }
                                    MenuItem::Root | MenuItem::Separator => {}
                                }
                            }
                            invocation.return_value(None);
                        }
                        "AboutToShow" => {
                            invocation.return_value(Some(&(false,).to_variant()));
                        }
                        _ => {
                            invocation
                                .return_error(gio::DBusError::UnknownMethod, "Unknown method");
                        }
                    }
                },
            )
            .property(
                move |_conn, _sender, _path, _iface, property| match property {
                    "Version" => 3u32.to_variant(),
                    "Status" => "normal".to_variant(),
                    _ => "".to_variant(),
                },
            )
            .build();

        if let Err(err) = reg_res {
            error!("Failed to register DBusMenu object: {err}");
        }
    }
}

fn register_with_watchers(conn: &gio::DBusConnection) {
    for watcher_bus in [
        "org.kde.StatusNotifierWatcher",
        "org.freedesktop.StatusNotifierWatcher",
    ] {
        let conn_watcher = conn.clone();
        let item_path = SNI_PATH.to_string();
        conn_watcher.call(
            Some(watcher_bus),
            "/StatusNotifierWatcher",
            watcher_bus,
            "RegisterStatusNotifierItem",
            Some(&(item_path,).to_variant()),
            None,
            gio::DBusCallFlags::NONE,
            -1,
            gio::Cancellable::NONE,
            move |res| {
                if let Err(e) = res {
                    debug!("Could not register with {watcher_bus}: {e}");
                } else {
                    info!("Successfully registered AppIndicator with {watcher_bus}");
                }
            },
        );
    }
}

#[derive(Clone)]
pub struct AppIndicator {
    connection: Option<gio::DBusConnection>,
    state: IndicatorState,
}

impl AppIndicator {
    pub fn new<C>(app: &adw::Application, window: &adw::ApplicationWindow, client: C) -> Self
    where
        C: NmClient + Clone + Send + 'static,
    {
        let state = IndicatorState {
            connected: Arc::new(AtomicBool::new(false)),
            active_profile: Arc::new(Mutex::new(None)),
            active_port: Arc::new(Mutex::new(None)),
            menu_revision: Arc::new(AtomicU32::new(1)),
        };

        let connection = match gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE) {
            Ok(conn) => Some(conn),
            Err(err) => {
                warn!("Could not connect to D-Bus session bus for AppIndicator: {err}");
                None
            }
        };

        let indicator = Self {
            connection: connection.clone(),
            state: state.clone(),
        };

        if let Some(conn) = connection {
            let window_weak = window.downgrade();
            let app_weak = app.downgrade();

            register_sni_object(&conn, window_weak.clone(), &state);
            register_dbusmenu_object(&conn, window_weak, app_weak, client, &state);
            register_with_watchers(&conn);
            init_background_portal(&conn);
        }

        indicator
    }

    pub fn update_status(
        &self,
        connected: bool,
        active_profile: Option<&str>,
        forwarded_port: Option<u16>,
    ) {
        self.state.connected.store(connected, Ordering::Relaxed);
        *self.state.active_profile.lock().unwrap() = active_profile.map(|s| s.to_string());
        *self.state.active_port.lock().unwrap() = forwarded_port;
        self.state.menu_revision.fetch_add(1, Ordering::Relaxed);

        if let Some(conn) = &self.connection {
            let _ = conn.emit_signal(None, SNI_PATH, SNI_INTERFACE, "NewIcon", None);
            let _ = conn.emit_signal(None, SNI_PATH, SNI_INTERFACE, "NewToolTip", None);
            // Always advertise "Active" status so the indicator remains visible
            // in the panel (with the red disconnected shield) even when disconnected,
            // rather than being hidden by the tray host.
            let status = "Active";
            let _ = conn.emit_signal(
                None,
                SNI_PATH,
                SNI_INTERFACE,
                "NewStatus",
                Some(&(status,).to_variant()),
            );
            let _ = conn.emit_signal(
                None,
                MENU_PATH,
                MENU_INTERFACE,
                "LayoutUpdated",
                Some(&(self.state.menu_revision.load(Ordering::Relaxed), 0i32).to_variant()),
            );

            // Update status message in GNOME Background Apps Quick Settings
            let bg_message = if connected {
                let name = active_profile.unwrap_or("Connected");
                match forwarded_port {
                    Some(port) => format!("Connected: {name} (Port: {port})"),
                    None => format!("Connected: {name}"),
                }
            } else {
                "Disconnected".to_string()
            };
            set_background_portal_status(conn, &bg_message);
        }
    }
}

pub fn portal_registry_params() -> Variant {
    let reg_options = glib::VariantDict::new(None);
    Variant::tuple_from_iter([APP_ID.to_variant(), reg_options.end()])
}

pub fn portal_request_background_params() -> Variant {
    let options = glib::VariantDict::new(None);
    options.insert("reason", "Manage WireGuard VPN connections");
    options.insert("autostart", false);
    options.insert("dbus-activatable", false);
    Variant::tuple_from_iter(["".to_variant(), options.end()])
}

pub fn portal_set_status_params(message: &str) -> Variant {
    let options = glib::VariantDict::new(None);
    options.insert("message", message);
    Variant::tuple_from_iter([options.end()])
}

/// Request background status from XDG Desktop Portal for GNOME Quick Settings Background Apps.
fn init_background_portal(conn: &gio::DBusConnection) {
    let conn_for_req = conn.clone();
    let reg_params = portal_registry_params();

    conn.call(
        Some(PORTAL_DESKTOP_DEST),
        PORTAL_DESKTOP_PATH,
        PORTAL_REGISTRY_IFACE,
        "Register",
        Some(&reg_params),
        None,
        gio::DBusCallFlags::NONE,
        -1,
        gio::Cancellable::NONE,
        move |res| {
            if let Err(e) = res {
                debug!("Host portal Registry.Register: {e}");
            } else {
                info!("Registered app_id with host portal Registry");
            }

            let req_params = portal_request_background_params();
            let conn_for_status = conn_for_req.clone();
            conn_for_req.call(
                Some(PORTAL_DESKTOP_DEST),
                PORTAL_DESKTOP_PATH,
                PORTAL_BACKGROUND_IFACE,
                "RequestBackground",
                Some(&req_params),
                None,
                gio::DBusCallFlags::NONE,
                -1,
                gio::Cancellable::NONE,
                move |res| {
                    if let Err(e) = res {
                        debug!("RequestBackground portal call: {e}");
                    } else {
                        info!("Successfully registered background portal status");
                    }
                    set_background_portal_status(&conn_for_status, "Disconnected");
                },
            );
        },
    );
}

/// Set live status text in GNOME Quick Settings Background Apps section.
fn set_background_portal_status(conn: &gio::DBusConnection, message: &str) {
    let params = portal_set_status_params(message);

    conn.call(
        Some(PORTAL_DESKTOP_DEST),
        PORTAL_DESKTOP_PATH,
        PORTAL_BACKGROUND_IFACE,
        "SetStatus",
        Some(&params),
        None,
        gio::DBusCallFlags::NONE,
        -1,
        gio::Cancellable::NONE,
        |res| {
            if let Err(e) = res {
                debug!("SetStatus background portal call: {e}");
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_theme_path_points_at_the_directory_the_icons_are_installed_into() {
        // Must match `install_status_icons`, which writes into
        // `<data_dir>/icons/hicolor/...`. A mismatch here leaves the tray host
        // unable to resolve the icon name and falling back to a placeholder.
        let path = icon_theme_path();

        assert!(path.ends_with("icons"), "{path}");
        assert!(
            !path.is_empty(),
            "a data directory should be available in tests"
        );
    }

    #[test]
    fn converts_bgra_to_network_order_argb() {
        // One opaque pixel: GDK hands over B,G,R,A and the wire wants A,R,G,B.
        let bgra = [0x10, 0x20, 0x30, 0xff];

        assert_eq!(
            argb32_from_premultiplied_bgra(&bgra),
            vec![0xff, 0x30, 0x20, 0x10]
        );
    }

    #[test]
    fn un_premultiplies_partially_transparent_pixels() {
        // A 50%-alpha white pixel arrives premultiplied (0x80), and must be
        // restored to full-intensity white so the antialiased rim of the shield
        // does not render as a dark halo.
        let bgra = [0x80, 0x80, 0x80, 0x80];

        assert_eq!(
            argb32_from_premultiplied_bgra(&bgra),
            vec![0x80, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn leaves_fully_transparent_pixels_black() {
        // Dividing by a zero alpha must not panic or produce garbage colour.
        let bgra = [0x00, 0x00, 0x00, 0x00];

        assert_eq!(argb32_from_premultiplied_bgra(&bgra), vec![0, 0, 0, 0]);
    }

    #[test]
    fn emits_four_bytes_for_every_pixel() {
        let bgra = [0u8; 4 * 7];

        assert_eq!(argb32_from_premultiplied_bgra(&bgra).len(), 4 * 7);
    }

    #[test]
    fn menu_item_id_conversion_and_order() {
        for id in 0..=5 {
            let item = MenuItem::from_i32(id).expect("valid MenuItem ID");
            assert_eq!(item.id(), id);
        }
        assert_eq!(MenuItem::from_i32(6), None);
        assert_eq!(MenuItem::from_i32(-1), None);
        assert_eq!(MenuItem::ORDER.len(), 5);
    }

    #[test]
    fn menu_object_path_returns_valid_variant() {
        let path_var = menu_object_path_variant();
        assert_eq!(path_var.type_().as_str(), "o");
    }

    #[test]
    fn portal_params_generation() {
        let reg = portal_registry_params();
        assert_eq!(reg.type_().as_str(), "(sa{sv})");

        let req = portal_request_background_params();
        assert_eq!(req.type_().as_str(), "(sa{sv})");

        let status = portal_set_status_params("Connected: test");
        assert_eq!(status.type_().as_str(), "(a{sv})");
    }
}
