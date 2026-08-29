use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use adw::prelude::*;
use gtk::gdk;
use gtk::gio;
use gtk::gio::glib::{self, Variant, VariantTy};
use tracing::{debug, error, info, warn};

use crate::nm::NmClient;

/// Tray icon shown while a tunnel is up, and its counterpart while none is.
///
/// These are shipped by the app rather than taken from the icon theme: the
/// point is the green/red state colour, and a `-symbolic` theme icon would be
/// recoloured to the panel foreground and lose exactly that signal. They are
/// installed into the user icon theme at startup (`install_status_icons`) so
/// the names resolve for anything that reads the theme. The tray itself sends
/// the artwork as a pixmap instead -- see `IconName` in the property handler.
pub const ICON_CONNECTED: &str = "neutron-vpn-connected";
pub const ICON_DISCONNECTED: &str = "neutron-vpn-disconnected";

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
    bgra.chunks_exact(4)
        .flat_map(|pixel| {
            let (b, g, r, a) = (pixel[0], pixel[1], pixel[2], pixel[3]);
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

/// Build the `a{sv}` property dictionary for one dbusmenu item id.
///
/// The DBusMenu spec types item properties as `a{sv}`, so the dictionary is
/// finished with [`glib::VariantDict::end`]. Using `to_variant()` here would
/// instead yield a boxed `v`, which makes GNOME Shell reject the whole
/// `GetLayout` reply ("Type of return value is incorrect") and render an empty
/// menu.
fn get_item_dict(id: i32, is_conn: bool, prof: Option<&str>, port: Option<u16>) -> Option<Variant> {
    let dict = glib::VariantDict::new(None);
    match id {
        0 => {
            dict.insert("children-display", "submenu");
            Some(dict.end())
        }
        1 => {
            dict.insert("label", "Show Neutron VPN");
            dict.insert("enabled", true);
            dict.insert("visible", true);
            Some(dict.end())
        }
        2 => {
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
        3 => {
            dict.insert("type", "separator");
            dict.insert("visible", true);
            Some(dict.end())
        }
        4 => {
            dict.insert("label", "Quit");
            dict.insert("enabled", true);
            dict.insert("visible", true);
            Some(dict.end())
        }
        5 => {
            if let Some(p) = port {
                dict.insert("label", format!("Port Forwarding: {p} (Copy)"));
                dict.insert("enabled", true);
                dict.insert("visible", true);
                Some(dict.end())
            } else {
                None
            }
        }
        _ => None,
    }
}

#[derive(Clone)]
pub struct AppIndicator {
    connection: Option<gio::DBusConnection>,
    connected: Arc<AtomicBool>,
    active_profile: Arc<Mutex<Option<String>>>,
    active_port: Arc<Mutex<Option<u16>>>,
    menu_revision: Arc<AtomicU32>,
}

impl AppIndicator {
    pub fn new<C>(app: &adw::Application, window: &adw::ApplicationWindow, client: C) -> Self
    where
        C: NmClient + Clone + Send + 'static,
    {
        let connected = Arc::new(AtomicBool::new(false));
        let active_profile = Arc::new(Mutex::new(None));
        let active_port = Arc::new(Mutex::new(None));
        let menu_revision = Arc::new(AtomicU32::new(1));

        let connection = match gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE) {
            Ok(conn) => Some(conn),
            Err(err) => {
                warn!("Could not connect to D-Bus session bus for AppIndicator: {err}");
                None
            }
        };

        let indicator = Self {
            connection: connection.clone(),
            connected: connected.clone(),
            active_profile: active_profile.clone(),
            active_port: active_port.clone(),
            menu_revision: menu_revision.clone(),
        };

        if let Some(conn) = connection {
            let window_weak = window.downgrade();
            let app_weak = app.downgrade();
            let client_clone = client.clone();
            let connected_for_sni = connected.clone();
            let active_for_sni = active_profile.clone();
            let port_for_sni = active_port.clone();

            // 1. Register org.kde.StatusNotifierItem using standard Adwaita icons
            if let Ok(node_info) = gio::DBusNodeInfo::for_xml(SNI_XML)
                && let Some(iface_info) = node_info.lookup_interface("org.kde.StatusNotifierItem")
            {
                let win_for_activate = window_weak.clone();

                let reg_res = conn
                    .register_object("/StatusNotifierItem", &iface_info)
                    .method_call(
                        move |_conn, _sender, _path, _iface, method, _params, invocation| {
                            match method {
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
                                    invocation.return_error(
                                        gio::DBusError::UnknownMethod,
                                        "Unknown method",
                                    );
                                }
                            }
                        },
                    )
                    .property(move |_conn, _sender, _path, _iface, property| {
                        let is_conn = connected_for_sni.load(Ordering::Relaxed);
                        let profile_name = active_for_sni.lock().unwrap().clone();
                        let port_opt = *port_for_sni.lock().unwrap();
                        match property {
                            "Category" => "ApplicationStatus".to_variant(),
                            "Id" => "neutron-vpn".to_variant(),
                            "Title" => "Neutron VPN".to_variant(),
                            "Status" => "Active".to_variant(),
                            "WindowId" => 0i32.to_variant(),
                            "IconThemePath" => icon_theme_path().to_variant(),
                            "ItemIsMenu" => false.to_variant(),
                            "Menu" => Variant::parse(None, "objectpath '/MenuBar'").unwrap(),
                            // Deliberately empty so the host uses `IconPixmap`.
                            // A non-empty `IconName` takes precedence per the
                            // spec, and GNOME's appindicator support failed to
                            // resolve ours -- showing a placeholder rather than
                            // falling back -- even with `IconThemePath` set and
                            // the icons installed and resolvable by GTK. The
                            // pixmap is embedded in the binary, so it renders
                            // without depending on the host's icon theme at all.
                            "IconName" => "".to_variant(),
                            "IconPixmap" => icon_pixmap(is_conn),
                            "OverlayIconName" => "".to_variant(),
                            "OverlayIconPixmap" => Vec::<(i32, i32, Vec<u8>)>::new().to_variant(),
                            "AttentionIconName" => "".to_variant(),
                            "AttentionIconPixmap" => Vec::<(i32, i32, Vec<u8>)>::new().to_variant(),
                            "AttentionMovieName" => "".to_variant(),
                            "ToolTip" => {
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
                                // Icon name left empty here for the same reason
                                // as `IconName` above; the tooltip title and
                                // body carry the state.
                                ("", empty_pixmap, "Neutron VPN", sub.as_str()).to_variant()
                            }
                            _ => "".to_variant(),
                        }
                    })
                    .build();

                if let Err(err) = reg_res {
                    error!("Failed to register StatusNotifierItem object: {err}");
                }
            }

            // 2. Register com.canonical.dbusmenu
            if let Ok(node_info) = gio::DBusNodeInfo::for_xml(DBUSMENU_XML)
                && let Some(iface_info) = node_info.lookup_interface("com.canonical.dbusmenu")
            {
                let win_for_menu = window_weak.clone();
                let app_for_menu = app_weak.clone();
                let client_for_menu = client_clone.clone();
                let connected_for_menu = connected.clone();
                let active_for_menu = active_profile.clone();
                let port_for_menu = active_port.clone();
                let rev_for_menu = menu_revision.clone();

                let reg_res = conn
                    .register_object("/MenuBar", &iface_info)
                    .method_call(
                        move |_conn, _sender, _path, _iface, method, params, invocation| {
                            let is_conn = connected_for_menu.load(Ordering::Relaxed);
                            let prof = active_for_menu.lock().unwrap().clone();
                            let port_opt = *port_for_menu.lock().unwrap();
                            let rev = rev_for_menu.load(Ordering::Relaxed);

                            match method {
                                "GetLayout" => {
                                    // Menu ids rendered in display order. Item 5
                                    // (port forwarding) only exists while a port
                                    // is known, so it is filtered out otherwise.
                                    let mut children = Vec::new();
                                    for id in [1i32, 5, 2, 3, 4] {
                                        let Some(props) =
                                            get_item_dict(id, is_conn, prof.as_deref(), port_opt)
                                        else {
                                            continue;
                                        };
                                        let item = menu_item(id, props, Vec::new());
                                        children.push(Variant::from_variant(&item));
                                    }

                                    let root_props =
                                        get_item_dict(0, is_conn, prof.as_deref(), port_opt)
                                            .expect("root menu item is always present");
                                    let root = menu_item(0, root_props, children);

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
                                        if let Some(props) =
                                            get_item_dict(id, is_conn, prof.as_deref(), port_opt)
                                        {
                                            group_props.push(Variant::tuple_from_iter([
                                                id.to_variant(),
                                                props,
                                            ]));
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
                                    if let Some(id) = id_var.get::<i32>() {
                                        match id {
                                            1 => {
                                                if let Some(win) = win_for_menu.upgrade() {
                                                    win.set_visible(true);
                                                    win.present();
                                                }
                                            }
                                            2 => {
                                                let client_task = client_for_menu.clone();
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
                                            4 => {
                                                if let Some(win) = win_for_menu.upgrade() {
                                                    win.destroy();
                                                }
                                                if let Some(app) = app_for_menu.upgrade() {
                                                    app.quit();
                                                }
                                            }
                                            5 => {
                                                if let Some(port) = port_opt
                                                    && let Some(display) = gdk::Display::default()
                                                {
                                                    display.clipboard().set_text(&port.to_string());
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                    invocation.return_value(None);
                                }
                                "AboutToShow" => {
                                    invocation.return_value(Some(&(false,).to_variant()));
                                }
                                _ => {
                                    invocation.return_error(
                                        gio::DBusError::UnknownMethod,
                                        "Unknown method",
                                    );
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

            // 3. Register with StatusNotifierWatcher (org.kde and org.freedesktop)
            for watcher_bus in [
                "org.kde.StatusNotifierWatcher",
                "org.freedesktop.StatusNotifierWatcher",
            ] {
                let conn_watcher = conn.clone();
                let item_path = "/StatusNotifierItem".to_string();
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

            // 4. Register with GNOME Background Apps portal (org.freedesktop.portal.Background)
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
        self.connected.store(connected, Ordering::Relaxed);
        *self.active_profile.lock().unwrap() = active_profile.map(|s| s.to_string());
        *self.active_port.lock().unwrap() = forwarded_port;
        self.menu_revision.fetch_add(1, Ordering::Relaxed);

        if let Some(conn) = &self.connection {
            let _ = conn.emit_signal(
                None,
                "/StatusNotifierItem",
                "org.kde.StatusNotifierItem",
                "NewIcon",
                None,
            );
            let _ = conn.emit_signal(
                None,
                "/StatusNotifierItem",
                "org.kde.StatusNotifierItem",
                "NewToolTip",
                None,
            );
            // Always advertise "Active" status so the indicator remains visible
            // in the panel (with the red disconnected shield) even when disconnected,
            // rather than being hidden by the tray host.
            let status = "Active";
            let _ = conn.emit_signal(
                None,
                "/StatusNotifierItem",
                "org.kde.StatusNotifierItem",
                "NewStatus",
                Some(&(status,).to_variant()),
            );
            let _ = conn.emit_signal(
                None,
                "/MenuBar",
                "com.canonical.dbusmenu",
                "LayoutUpdated",
                Some(&(self.menu_revision.load(Ordering::Relaxed), 0i32).to_variant()),
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

/// Request background status from XDG Desktop Portal for GNOME Quick Settings Background Apps.
fn init_background_portal(conn: &gio::DBusConnection) {
    let reg_options = glib::VariantDict::new(None);
    let conn_for_req = conn.clone();

    // 1. Register app_id with host portal registry so non-sandboxed / AppImage apps
    // are recognized by xdg-desktop-portal and permitted to use the Background portal.
    let reg_params = Variant::tuple_from_iter([
        "io.gitlab.neutron_vpn.neutron".to_variant(),
        reg_options.end(),
    ]);

    conn.call(
        Some("org.freedesktop.portal.Desktop"),
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.host.portal.Registry",
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

            // 2. Request background running permission from the portal
            let options = glib::VariantDict::new(None);
            options.insert("reason", "Manage WireGuard VPN connections");
            options.insert("autostart", false);
            options.insert("dbus-activatable", false);

            let req_params = Variant::tuple_from_iter(["".to_variant(), options.end()]);

            let conn_for_status = conn_for_req.clone();
            conn_for_req.call(
                Some("org.freedesktop.portal.Desktop"),
                "/org/freedesktop/portal/desktop",
                "org.freedesktop.portal.Background",
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
    let options = glib::VariantDict::new(None);
    options.insert("message", message);
    let params = Variant::tuple_from_iter([options.end()]);

    conn.call(
        Some("org.freedesktop.portal.Desktop"),
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.Background",
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
    fn test_portal_registration_and_background_apps() {
        let Ok(conn) = gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE) else {
            eprintln!("No session bus, skipping");
            return;
        };

        let reg_options = glib::VariantDict::new(None);
        let reg_params = Variant::tuple_from_iter([
            "io.gitlab.neutron_vpn.neutron".to_variant(),
            reg_options.end(),
        ]);

        let reg_res = conn.call_sync(
            Some("org.freedesktop.portal.Desktop"),
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.host.portal.Registry",
            "Register",
            Some(&reg_params),
            None,
            gio::DBusCallFlags::NONE,
            -1,
            gio::Cancellable::NONE,
        );
        eprintln!("Register res: {:?}", reg_res);

        let options = glib::VariantDict::new(None);
        options.insert("reason", "Manage WireGuard VPN connections");
        options.insert("autostart", false);
        options.insert("dbus-activatable", false);

        let req_params = Variant::tuple_from_iter(["".to_variant(), options.end()]);

        let req_res = conn.call_sync(
            Some("org.freedesktop.portal.Desktop"),
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.Background",
            "RequestBackground",
            Some(&req_params),
            None,
            gio::DBusCallFlags::NONE,
            -1,
            gio::Cancellable::NONE,
        );
        eprintln!("RequestBackground res: {:?}", req_res);

        let status_options = glib::VariantDict::new(None);
        status_options.insert("message", "Connected: wg-us");
        let status_params = Variant::tuple_from_iter([status_options.end()]);

        let status_res = conn.call_sync(
            Some("org.freedesktop.portal.Desktop"),
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.Background",
            "SetStatus",
            Some(&status_params),
            None,
            gio::DBusCallFlags::NONE,
            -1,
            gio::Cancellable::NONE,
        );
        eprintln!("SetStatus res: {:?}", status_res);

        let bg_apps_res = conn.call_sync(
            Some("org.freedesktop.background.Monitor"),
            "/org/freedesktop/background/monitor",
            "org.freedesktop.DBus.Properties",
            "Get",
            Some(&("org.freedesktop.background.Monitor", "BackgroundApps").to_variant()),
            None,
            gio::DBusCallFlags::NONE,
            -1,
            gio::Cancellable::NONE,
        );
        eprintln!("BackgroundApps in Monitor: {:?}", bg_apps_res);
    }
}
