#[cfg(feature = "gui")]
mod indicator;

#[cfg(feature = "gui")]
mod enabled {
    use std::cell::{Cell, RefCell};
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Stdio};
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    use adw::prelude::*;
    use adw::{Application, ApplicationWindow, HeaderBar};
    use gtk::Orientation;
    use gtk::gdk;
    use gtk::gio;
    use gtk::glib;
    use tracing::debug;

    use super::indicator::{AppIndicator, ICON_CONNECTED, ICON_DISCONNECTED};

    use crate::app::eligibility;
    use crate::app::profile_list;
    use crate::app::refresh_sync;
    use crate::config;
    use crate::error::{AppError, AppResult};
    use crate::firewall::FirewallClient;
    use crate::nm::NmClient;
    use crate::portforward;
    use crate::service;

    #[derive(Clone)]
    struct StatusIndicators {
        /// Owning application, kept so background refreshes can raise desktop
        /// notifications without every caller having to thread it through.
        app: Application,
        log: gtk::Label,
        vpn_icon: gtk::Image,
        vpn_label: gtk::Label,
        port_box: gtk::Box,
        port_label: gtk::Label,
        port_copy_button: gtk::Button,
        /// Name of the profile currently up, or `None` while disconnected.
        active_profile: Rc<RefCell<Option<String>>>,
        /// Forwarded port most recently granted by the tunnel gateway.
        active_port: Rc<RefCell<Option<u16>>>,
        /// UUID the current [`Self::active_port`] belongs to, so a switch to a
        /// different profile discards the previous profile's port instead of
        /// showing it against the new tunnel.
        port_profile: Rc<RefCell<Option<String>>>,
        /// Collapsible "Eligible Profiles" row in the Settings group. Its
        /// child switches choose which profiles join the boot-time random pool,
        /// keeping that configuration concern out of the operational rows.
        eligibility: adw::ExpanderRow,
        /// The eligibility switches currently shown inside `eligibility`, tracked
        /// so they can be cleared and rebuilt when the profile set changes
        /// (`adw::ExpanderRow` offers no clear-all). Shared, so toggle handlers
        /// can recompute the summary subtitle.
        eligibility_rows: Rc<RefCell<Vec<adw::SwitchRow>>>,
        /// Background system tray / AppIndicator status handler.
        indicator: Rc<RefCell<Option<AppIndicator>>>,
    }

    pub fn run<C>(client: C, hidden: bool) -> AppResult<()>
    where
        C: NmClient + FirewallClient + Clone + Send + 'static,
    {
        // NetworkManager must never activate a profile on its own -- the app is
        // the only authority on which tunnel is up. An autostarted launch (the
        // `--hidden` entry written by the autoconnect toggle) additionally
        // connects one random eligible profile, which is the whole auto-connect
        // mechanism. A manual launch deliberately does not: reconnecting a
        // tunnel the user just disconnected, merely because they opened the
        // window, would be surprising.
        //
        // Off the main thread: this shells out to `nmcli` once per profile and
        // may wait on a handshake, neither of which may block the first frame.
        let startup_client = client.clone();
        thread::spawn(move || {
            if hidden {
                startup_connect_logged(&startup_client);
            } else {
                service::disable_nm_autoconnect(&startup_client);
            }
        });

        let app = Application::builder()
            .application_id("io.gitlab.neutron_vpn.neutron")
            .build();

        app.connect_activate(move |app| build_ui(app, client.clone(), hidden));

        // Launch GTK with only the program name. Forwarding the CLI subcommand
        // (e.g. `gui`) would make GApplication treat it as a file argument and
        // refuse to start with "This application can not open files".
        let program = std::env::args().next().unwrap_or_default();
        app.run_with_args(&[program]);
        Ok(())
    }

    /// Re-apply state that depends on which profiles exist, after the set
    /// changed. Logs rather than propagating: it is incidental to the
    /// import/delete the user actually asked for.
    fn profile_set_changed<C>(client: &C)
    where
        C: NmClient + FirewallClient,
    {
        let outcome = config::default_config_path()
            .and_then(|path| crate::app::rebuild_lockdown_if_enabled(client, &path));
        if let Err(error) = outcome {
            tracing::warn!("failed to rebuild the lockdown allow-list: {error}");
        }
    }

    /// Connect one random eligible profile at an autostarted launch, logging
    /// rather than propagating.
    ///
    /// Best-effort by design: nothing is waiting on the result, and a failure
    /// to auto-connect must not stop the app from starting.
    fn startup_connect_logged<C: NmClient>(client: &C) {
        let outcome =
            config::default_config_path().and_then(|path| service::startup_connect(client, &path));
        match outcome {
            Ok(Some(name)) => tracing::info!("auto-connected '{name}' at startup"),
            Ok(None) => tracing::info!("nothing to auto-connect at startup"),
            Err(error) => tracing::warn!("failed to auto-connect at startup: {error}"),
        }
    }

    /// Install the icon and desktop entry into the user's data directory so the
    /// GNOME Shell dock can resolve an icon for the running window.
    ///
    /// On Wayland the shell matches a window to a `.desktop` file by its
    /// `app_id` (which GTK takes from the program name) and by `StartupWMClass`,
    /// then takes the icon from *that* entry. A window with no matching entry —
    /// or one matching an entry whose `Icon=` cannot be loaded — renders as a
    /// blank placeholder even when the app grid shows the icon correctly.
    fn ensure_desktop_integration() {
        let Some(data_dir) = dirs::data_dir() else {
            return;
        };

        install_theme_icons(&data_dir);

        let apps_dir = data_dir.join("applications");
        let _ = std::fs::create_dir_all(&apps_dir);

        let exec_cmd = if let Ok(appimage) = std::env::var("APPIMAGE") {
            format!("\"{appimage}\" gui")
        } else if let Ok(exe) = std::env::current_exe() {
            format!("\"{}\" gui", exe.display())
        } else {
            "neutron-vpn gui".to_string()
        };
        let desktop_content = format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Neutron VPN\n\
             Comment=Manage VPN connections with NetworkManager\n\
             Exec={exec_cmd}\n\
             Icon={APP_ID}\n\
             Terminal=false\n\
             Categories=Network;\n\
             StartupNotify=true\n\
             StartupWMClass={APP_ID}\n\
             Keywords=vpn;wireguard;network;neutron;\n"
        );
        let _ = std::fs::write(apps_dir.join(format!("{APP_ID}.desktop")), &desktop_content);
        // Older builds also wrote a duplicate entry under the binary name. Two
        // entries claiming the same StartupWMClass make the shell's match
        // ambiguous, so drop the stale one.
        let _ = std::fs::remove_file(apps_dir.join("neutron-vpn.desktop"));

        repair_competing_desktop_entries(&apps_dir);
        refresh_desktop_caches(&data_dir, &apps_dir);
    }

    /// Write the app icon into the user icon theme at every size the shell asks
    /// for. The scalable SVG alone is not always enough: some shell and dock
    /// code paths only look for rasterised sizes.
    fn install_theme_icons(data_dir: &std::path::Path) {
        let svg = include_str!("../../resources/io.gitlab.neutron_vpn.neutron.svg");
        let scalable = data_dir.join("icons/hicolor/scalable/apps");
        if std::fs::create_dir_all(&scalable).is_ok() {
            let _ = std::fs::write(scalable.join(format!("{APP_ID}.svg")), svg);
        }

        const PNGS: [(&str, &[u8]); 8] = [
            ("16x16", include_bytes!("../../resources/icons/16x16.png")),
            ("24x24", include_bytes!("../../resources/icons/24x24.png")),
            ("32x32", include_bytes!("../../resources/icons/32x32.png")),
            ("48x48", include_bytes!("../../resources/icons/48x48.png")),
            ("64x64", include_bytes!("../../resources/icons/64x64.png")),
            (
                "128x128",
                include_bytes!("../../resources/icons/128x128.png"),
            ),
            (
                "256x256",
                include_bytes!("../../resources/icons/256x256.png"),
            ),
            (
                "512x512",
                include_bytes!("../../resources/icons/512x512.png"),
            ),
        ];
        for (size, bytes) in PNGS {
            let dir = data_dir.join(format!("icons/hicolor/{size}/apps"));
            if std::fs::create_dir_all(&dir).is_ok() {
                let _ = std::fs::write(dir.join(format!("{APP_ID}.png")), bytes);
            }
        }

        install_status_icons(data_dir);
    }

    /// One tray status icon: the theme name the indicator reports, plus the
    /// artwork to install under it.
    struct StatusIcon {
        name: &'static str,
        svg: &'static str,
        pngs: [(&'static str, &'static [u8]); 4],
    }

    /// Install the green/red shield the tray indicator switches between.
    ///
    /// The StatusNotifierItem spec only carries an icon *name*, which the shell
    /// resolves against its own icon theme, so these have to exist on disk
    /// before the indicator can reference them.
    fn install_status_icons(data_dir: &std::path::Path) {
        const STATUS_ICONS: [StatusIcon; 2] = [
            StatusIcon {
                name: ICON_CONNECTED,
                svg: include_str!("../../resources/status/neutron-vpn-connected.svg"),
                pngs: [
                    (
                        "16x16",
                        include_bytes!("../../resources/status/connected_16.png"),
                    ),
                    (
                        "24x24",
                        include_bytes!("../../resources/status/connected_24.png"),
                    ),
                    (
                        "32x32",
                        include_bytes!("../../resources/status/connected_32.png"),
                    ),
                    (
                        "48x48",
                        include_bytes!("../../resources/status/connected_48.png"),
                    ),
                ],
            },
            StatusIcon {
                name: ICON_DISCONNECTED,
                svg: include_str!("../../resources/status/neutron-vpn-disconnected.svg"),
                pngs: [
                    (
                        "16x16",
                        include_bytes!("../../resources/status/disconnected_16.png"),
                    ),
                    (
                        "24x24",
                        include_bytes!("../../resources/status/disconnected_24.png"),
                    ),
                    (
                        "32x32",
                        include_bytes!("../../resources/status/disconnected_32.png"),
                    ),
                    (
                        "48x48",
                        include_bytes!("../../resources/status/disconnected_48.png"),
                    ),
                ],
            },
        ];

        for icon in STATUS_ICONS {
            let scalable = data_dir.join("icons/hicolor/scalable/apps");
            if std::fs::create_dir_all(&scalable).is_ok() {
                let _ = std::fs::write(scalable.join(format!("{}.svg", icon.name)), icon.svg);
            }
            for (size, bytes) in icon.pngs {
                let dir = data_dir.join(format!("icons/hicolor/{size}/apps"));
                if std::fs::create_dir_all(&dir).is_ok() {
                    let _ = std::fs::write(dir.join(format!("{}.png", icon.name)), bytes);
                }
            }
        }
    }

    /// Point any *other* desktop entry that claims this app's window class at
    /// the themed icon.
    ///
    /// AppImage integrators (Gearlever, appimaged, …) generate their own entry
    /// for the same binary, copying our `StartupWMClass` but pointing `Icon=` at
    /// an extension-less file they extracted. When the shell picks that entry
    /// for the window, the icon fails to load. Rewriting just the `Icon=` line
    /// makes every candidate resolve to the same working icon, whichever one
    /// wins the match.
    fn repair_competing_desktop_entries(apps_dir: &std::path::Path) {
        let ours = format!("{APP_ID}.desktop");
        let Ok(entries) = std::fs::read_dir(apps_dir) else {
            return;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("desktop")
                || path.file_name().and_then(|n| n.to_str()) == Some(ours.as_str())
            {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            if !content.contains(&format!("StartupWMClass={APP_ID}")) {
                continue;
            }

            let repaired: String = content
                .lines()
                .map(|line| {
                    if line.starts_with("Icon=") {
                        format!("Icon={APP_ID}")
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            let repaired = format!("{repaired}\n");

            if repaired != content {
                let _ = std::fs::write(&path, repaired);
            }
        }
    }

    /// Nudge the icon and desktop-entry caches so the shell notices the files we
    /// just wrote instead of serving a stale lookup. All best-effort: the
    /// helpers are optional and a failure only delays the icon by one login.
    /// Make sure the shell picks up the entries we just wrote.
    ///
    /// The icon cache is deliberately *removed* rather than rebuilt. Once
    /// `icon-theme.cache` exists, GTK trusts it exclusively for that theme
    /// directory -- and this process loads the icon theme during GTK init,
    /// before [`ensure_desktop_integration`] has written anything. A cache
    /// generated on a previous run therefore hides icons added on this one,
    /// which is exactly how the tray shields ended up rendering as the
    /// missing-icon placeholder. With no cache present GTK stats the
    /// directories and always sees current files.
    fn refresh_desktop_caches(data_dir: &std::path::Path, apps_dir: &std::path::Path) {
        let _ = std::fs::remove_file(data_dir.join("icons/hicolor/icon-theme.cache"));
        let _ = std::process::Command::new("update-desktop-database")
            .arg(apps_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    fn build_ui<C>(app: &Application, client: C, hidden: bool)
    where
        C: NmClient + FirewallClient + Clone + Send + 'static,
    {
        ensure_desktop_integration();

        if let Some(display) = gdk::Display::default() {
            let icon_theme = gtk::IconTheme::for_display(&display);
            if let Some(data_dir) = dirs::data_dir() {
                icon_theme.add_search_path(data_dir.join("icons"));
            }
            if let Ok(appdir) = std::env::var("APPDIR") {
                icon_theme.add_search_path(format!("{appdir}/usr/share/icons"));
                icon_theme.add_search_path(format!("{appdir}/usr/share"));
            }
            icon_theme.add_search_path("/app/share/icons");
            icon_theme.add_search_path("resources");
        }
        gtk::Window::set_default_icon_name(APP_ID);

        let header = HeaderBar::builder()
            .title_widget(&gtk::Label::new(Some("Neutron VPN")))
            .build();

        let menu = gio::Menu::new();
        menu.append(Some("Quit Neutron VPN"), Some("app.quit"));
        let menu_button = gtk::MenuButton::builder()
            .icon_name("open-menu-symbolic")
            .menu_model(&menu)
            .tooltip_text("Main Menu")
            .build();
        header.pack_end(&menu_button);

        let status = gtk::Label::new(None);
        status.set_wrap(true);
        status.set_xalign(0.0);

        let list = gtk::ListBox::new();
        list.add_css_class("boxed-list");

        list.connect_row_activated(move |_, row_widget| {
            let Some(container) = row_widget.child().and_downcast::<gtk::Box>() else {
                return;
            };
            let Some(info_box) = container.first_child().and_then(|h| h.next_sibling()) else {
                return;
            };
            info_box.set_visible(!info_box.is_visible());
        });

        let vpn_status_box = gtk::Box::new(Orientation::Horizontal, 8);
        vpn_status_box.set_halign(gtk::Align::Center);
        vpn_status_box.set_margin_bottom(8);

        let vpn_status_icon = gtk::Image::builder().pixel_size(20).build();
        let vpn_status_label = gtk::Label::builder().use_markup(true).build();
        update_vpn_status_widget(false, &vpn_status_icon, &vpn_status_label);

        vpn_status_box.append(&vpn_status_icon);
        vpn_status_box.append(&vpn_status_label);

        let port_box = gtk::Box::new(Orientation::Horizontal, 6);
        port_box.set_halign(gtk::Align::Center);
        port_box.set_margin_bottom(16);

        let port_icon = gtk::Image::builder()
            .icon_name("network-wired-symbolic")
            .pixel_size(16)
            .build();
        let port_label = gtk::Label::builder().use_markup(true).build();
        let port_copy_button = gtk::Button::builder()
            .icon_name("edit-copy-symbolic")
            .css_classes(vec!["flat".to_string()])
            .valign(gtk::Align::Center)
            .tooltip_text("Copy port to clipboard")
            .build();

        let active_port_cell: Rc<RefCell<Option<u16>>> = Rc::new(RefCell::new(None));
        {
            let port_cell = active_port_cell.clone();
            let status_log = status.clone();
            port_copy_button.connect_clicked(move |btn| {
                if let Some(port) = *port_cell.borrow()
                    && let Some(display) = gdk::Display::default()
                {
                    display.clipboard().set_text(&port.to_string());
                    status_log.set_label(&format!("Copied port {port} to clipboard."));
                    btn.set_tooltip_text(Some("Copied!"));
                }
            });
        }

        port_box.append(&port_icon);
        port_box.append(&port_label);
        port_box.append(&port_copy_button);
        port_box.set_visible(false);

        let eligibility_expander = adw::ExpanderRow::builder()
            .title("Eligible Profiles")
            .subtitle("Choose profiles eligible for random selection at login")
            .build();

        let indicators = StatusIndicators {
            app: app.clone(),
            log: status.clone(),
            vpn_icon: vpn_status_icon.clone(),
            vpn_label: vpn_status_label.clone(),
            port_box: port_box.clone(),
            port_label: port_label.clone(),
            port_copy_button: port_copy_button.clone(),
            active_profile: Rc::new(RefCell::new(None)),
            active_port: active_port_cell,
            port_profile: Rc::new(RefCell::new(None)),
            eligibility: eligibility_expander.clone(),
            eligibility_rows: Rc::new(RefCell::new(Vec::new())),
            indicator: Rc::new(RefCell::new(None)),
        };

        let refresh = gtk::Button::with_label("Refresh");
        // Size the button to its label instead of stretching across the full
        // window width (a vertical box would otherwise fill the cross axis).
        refresh.set_halign(gtk::Align::Start);
        {
            let client = client.clone();
            let list = list.clone();
            let indicators = indicators.clone();
            refresh.connect_clicked(move |_| {
                refresh_profile_list(&client, &list, &indicators);
            });
        }

        // Watch NetworkManager for state changes so the list stays current
        // without the user pressing Refresh. The child is tracked so it can be
        // terminated when the window closes instead of being orphaned.
        let monitor_events = Arc::new(AtomicU64::new(0));
        let monitor_child: Rc<RefCell<Option<Child>>> = Rc::new(RefCell::new(None));
        match start_nm_monitor(monitor_events.clone()) {
            Ok(child) => {
                *monitor_child.borrow_mut() = Some(child);
            }
            Err(error) => {
                status.set_label(&format!(
                    "Profile monitor unavailable ({error}). Use Refresh for manual updates."
                ));
            }
        }

        {
            let client = client.clone();
            let list = list.clone();
            let indicators = indicators.clone();
            let mut last_seen_event = 0_u64;
            glib::timeout_add_seconds_local(1, move || {
                let current = monitor_events.load(Ordering::Relaxed);
                if current != last_seen_event {
                    last_seen_event = current;
                    refresh_profile_list(&client, &list, &indicators);
                }
                glib::ControlFlow::Continue
            });
        }

        refresh_profile_list(&client, &list, &indicators);

        let kill_switch_row = build_kill_switch_row(app, &client, &status);
        let lockdown_row = build_lockdown_row(app, &client, &status);
        let autoconnect_row = build_autoconnect_row(&client, &status, &indicators);
        let split_tunnel_row = build_split_tunnel_row(&client, &status);
        let import = build_import_button(&client, &list, &indicators);

        let container = gtk::Box::new(Orientation::Vertical, 12);
        container.set_margin_top(24);
        container.set_margin_bottom(24);
        container.set_margin_start(24);
        container.set_margin_end(24);

        let logo = build_logo();
        container.append(&logo);
        container.append(&vpn_status_box);
        container.append(&port_box);

        // Settings Section
        let settings_group = adw::PreferencesGroup::builder().title("Settings").build();
        settings_group.add(&autoconnect_row);
        settings_group.add(&eligibility_expander);
        settings_group.add(&kill_switch_row);
        settings_group.add(&lockdown_row);
        settings_group.add(&split_tunnel_row);

        container.append(&settings_group);

        // Profiles Section
        let profiles_title = gtk::Label::new(None);
        profiles_title.set_markup("<b>Profiles</b>");
        profiles_title.set_xalign(0.0);
        profiles_title.set_hexpand(true);

        let profiles_header = gtk::Box::new(Orientation::Horizontal, 12);
        profiles_header.set_margin_top(12);
        profiles_header.set_margin_bottom(4);
        profiles_header.append(&profiles_title);
        profiles_header.append(&import);
        profiles_header.append(&refresh);

        container.append(&profiles_header);
        container.append(&status);
        container.append(&list);

        let clamp = adw::Clamp::builder()
            .maximum_size(500)
            .child(&container)
            .build();

        // Wrap the main content clamp in a ScrolledWindow so that all elements
        // (logo, settings expander, profiles) scroll smoothly and naturally when
        // window dimensions or contents exceed available vertical space.
        let main_scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vscrollbar_policy(gtk::PolicyType::Automatic)
            .vexpand(true)
            .hexpand(true)
            .child(&clamp)
            .build();

        let (width, height) = load_window_size();
        let window = build_main_window(
            &header,
            &main_scroller.upcast::<gtk::Widget>(),
            width,
            height,
        );
        window.set_application(Some(app));

        // Initialize background AppIndicator / StatusNotifierItem
        let indicator = AppIndicator::new(app, &window, client.clone());
        *indicators.indicator.borrow_mut() = Some(indicator);

        let quit_action = gio::SimpleAction::new("quit", None);
        let monitor_child_quit = monitor_child.clone();
        let app_weak = app.downgrade();
        quit_action.connect_activate(move |_, _| {
            if let Some(mut child) = monitor_child_quit.borrow_mut().take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            if let Some(app) = app_weak.upgrade() {
                app.quit();
            }
            std::process::exit(0);
        });
        app.add_action(&quit_action);
        app.set_accels_for_action("app.quit", &["<Control>q"]);

        let monitor_child_for_shutdown = monitor_child.clone();
        app.connect_shutdown(move |_| {
            if let Some(mut child) = monitor_child_for_shutdown.borrow_mut().take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        });

        window.connect_close_request(move |window| {
            // Remember the user's last window size for the next launch.
            save_window_size(window);
            // Hide window instead of exiting so Neutron VPN stays accessible via the AppIndicator in background.
            window.set_visible(false);
            glib::Propagation::Stop
        });

        // An autostarted launch exists to re-arm the next boot's profile, so it
        // stays in the tray rather than stealing focus at login. The window is
        // fully built either way: the tray menu can raise it on demand, exactly
        // as it does after the user closes it.
        if !hidden {
            window.present();
        }
    }

    /// Build the main application window.
    ///
    /// `AdwApplicationWindow` aborts if a titlebar is installed via
    /// `gtk_window_set_titlebar()`. The header bar must therefore live *inside*
    /// the window content, stacked above the body by an `AdwToolbarView`, which
    /// is then set as the window content.
    ///
    /// The caller associates the window with its [`Application`] (after startup)
    /// so this stays a pure chrome builder that is cheap to unit test. The
    /// initial size is supplied by the caller (restored from config) so the
    /// window reopens at the size the user last left it.
    fn build_main_window(
        header: &HeaderBar,
        body: &gtk::Widget,
        width: i32,
        height: i32,
    ) -> ApplicationWindow {
        let toolbar_view = adw::ToolbarView::new();
        toolbar_view.add_top_bar(header);
        toolbar_view.set_content(Some(body));

        ApplicationWindow::builder()
            .title("Neutron VPN")
            .icon_name("io.gitlab.neutron_vpn.neutron")
            .default_width(width)
            .default_height(height)
            .content(&toolbar_view)
            .build()
    }

    /// Width used the first time the app runs, before a size is remembered.
    const DEFAULT_WINDOW_WIDTH: i32 = 720;
    /// Height used the first time the app runs, before a size is remembered.
    const DEFAULT_WINDOW_HEIGHT: i32 = 420;

    /// Load the remembered window size from config, falling back to defaults.
    fn load_window_size() -> (i32, i32) {
        config::default_config_path()
            .and_then(|path| config::load(&path))
            .map(|app_cfg| {
                (
                    app_cfg.window_width.unwrap_or(DEFAULT_WINDOW_WIDTH),
                    app_cfg.window_height.unwrap_or(DEFAULT_WINDOW_HEIGHT),
                )
            })
            .unwrap_or((DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT))
    }

    /// Persist the current window size so it is restored on the next launch.
    ///
    /// In GTK4 the `default-width`/`default-height` properties track the live
    /// window size while it is not maximized, so they are the correct values to
    /// remember here. A best-effort save: a config error must not block closing.
    fn save_window_size(window: &ApplicationWindow) {
        let width = window.default_width();
        let height = window.default_height();
        if width <= 0 || height <= 0 {
            return;
        }
        let Ok(path) = config::default_config_path() else {
            return;
        };
        let Ok(mut app_cfg) = config::load(&path) else {
            return;
        };
        app_cfg.window_width = Some(width);
        app_cfg.window_height = Some(height);
        let _ = config::save(&path, &app_cfg);
    }

    fn start_nm_monitor(events: Arc<AtomicU64>) -> Result<Child, String> {
        let mut child = crate::nm::host_command("nmcli")
            .arg("monitor")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| error.to_string())?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "nmcli monitor stdout unavailable".to_string())?;

        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let Ok(line) = line else {
                    break;
                };
                if refresh_sync::should_refresh_from_nm_monitor_line(&line) {
                    events.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        Ok(child)
    }

    const APP_ID: &str = "io.gitlab.neutron_vpn.neutron";

    fn build_logo() -> gtk::Image {
        let icon = format!("{APP_ID}.svg");
        let mut candidates = Vec::new();
        if let Ok(appdir) = std::env::var("APPDIR") {
            candidates.push(format!(
                "{appdir}/usr/share/icons/hicolor/scalable/apps/{icon}"
            ));
            candidates.push(format!("{appdir}/{icon}"));
        }
        candidates.push(format!("/app/share/icons/hicolor/scalable/apps/{icon}"));
        candidates.push(format!("resources/{icon}"));

        let logo = candidates
            .iter()
            .find(|path| std::path::Path::new(path).exists())
            .map(gtk::Image::from_file)
            .unwrap_or_else(|| gtk::Image::from_icon_name(APP_ID));
        logo.set_pixel_size(96);
        logo.set_halign(gtk::Align::Center);
        logo.set_margin_bottom(12);
        logo
    }

    /// Run `work` on the Gio pool, folding a task panic into the same error
    /// channel as the work's own failure.
    async fn spawn_blocking_flat<T, E, F>(work: F) -> Result<T, String>
    where
        F: FnOnce() -> Result<T, E> + Send + 'static,
        T: Send + 'static,
        E: std::fmt::Display + Send + 'static,
    {
        gio::spawn_blocking(move || work().map_err(|e| e.to_string()))
            .await
            .unwrap_or_else(|_| Err("background task panicked".to_string()))
    }

    fn build_toggle_row<F, N>(
        status: &gtk::Label,
        title: &str,
        subtitle: &str,
        error_prefix: &'static str,
        initial: bool,
        apply: F,
        on_changed: N,
    ) -> adw::ActionRow
    where
        F: Fn(bool) -> Result<(), String> + Clone + Send + 'static,
        N: Fn(bool) + Clone + 'static,
    {
        let toggle = gtk::Switch::new();
        toggle.set_valign(gtk::Align::Center);
        toggle.set_active(initial);

        let guard = Rc::new(Cell::new(false));
        {
            let status = status.clone();
            toggle.connect_state_set(move |toggle, requested| {
                if guard.get() {
                    return glib::Propagation::Proceed;
                }
                toggle.set_sensitive(false);

                let status = status.clone();
                let toggle = toggle.clone();
                let guard = guard.clone();
                let apply = apply.clone();
                let on_changed = on_changed.clone();

                glib::spawn_future_local(async move {
                    let outcome = spawn_blocking_flat(move || apply(requested)).await;
                    toggle.set_sensitive(true);
                    match outcome {
                        Ok(()) => {
                            on_changed(requested);
                        }
                        Err(error) => {
                            status.set_label(&format!("{error_prefix}: {error}"));
                            revert_switch(&toggle, &guard, !requested);
                        }
                    }
                });

                glib::Propagation::Proceed
            });
        }

        let row = adw::ActionRow::builder()
            .title(title)
            .subtitle(subtitle)
            .build();
        row.add_suffix(&toggle);
        row.set_activatable_widget(Some(&toggle));
        row
    }

    /// Read a boolean setting, falling back to [`config::AppConfig::default`]
    /// when the config cannot be read.
    ///
    /// Falling back to the struct default rather than a hardcoded `false`
    /// matters for settings that default to *on*: a corrupt config would
    /// otherwise render their switch off and misreport the real state.
    fn load_flag(pick: impl Fn(&config::AppConfig) -> bool) -> bool {
        let app_cfg = config::default_config_path()
            .and_then(|path| config::load(&path))
            .unwrap_or_default();
        pick(&app_cfg)
    }

    fn notify(app: &Application, id: &str, title: &str, body: &str) {
        let notification = gio::Notification::new(title);
        notification.set_body(Some(body));
        app.send_notification(Some(id), &notification);
    }

    /// Warn the user when the tunnel goes down, describing what that leaves
    /// their traffic protected by.
    ///
    /// Neither protection can report the moment it actually drops a packet: the
    /// kill switch is kernel policy routing and lockdown is a firewalld REJECT
    /// rule, and both discard silently with no signal to observe. The tunnel
    /// going down is the observable event that changes protection, so that is
    /// what is reported -- and it is the state the user needs to act on:
    ///
    /// * lockdown on -> everything is blocked until the VPN is back;
    /// * kill switch only -> nothing is blocked any more, because it protects
    ///   traffic solely while a tunnel is up.
    fn notify_tunnel_dropped(indicators: &StatusIndicators) {
        let lockdown = load_flag(|cfg| cfg.lockdown_enabled);
        let kill_switch = load_flag(|cfg| cfg.kill_switch_enabled);

        let (title, body) = if lockdown {
            (
                "Lockdown is blocking traffic",
                "The VPN disconnected. Lockdown is blocking all non-VPN traffic until you reconnect.",
            )
        } else if kill_switch {
            (
                "VPN disconnected — traffic is exposed",
                "The kill switch only protects traffic while a tunnel is up. Reconnect, or enable Lockdown to block traffic while disconnected.",
            )
        } else {
            return;
        };

        indicators.log.set_label(body);
        notify(&indicators.app, "neutron-protection", title, body);
    }

    /// Build the global kill-switch row: a single switch that applies (or
    /// removes) the NetworkManager kill-switch routing policy across *every*
    /// WireGuard profile at once.
    fn build_kill_switch_row<C>(
        app: &Application,
        client: &C,
        status: &gtk::Label,
    ) -> adw::ActionRow
    where
        C: NmClient + Clone + Send + 'static,
    {
        let client = client.clone();
        let app = app.clone();
        build_toggle_row(
            status,
            "Kill Switch",
            "Drop all traffic if any WireGuard profile fails to connect",
            "Failed to update kill switch",
            load_flag(|c| c.kill_switch_enabled),
            move |enable| apply_global_kill_switch(&client, enable),
            move |enabled| {
                if enabled {
                    notify(
                        &app,
                        "neutron-kill-switch",
                        "Kill switch enabled",
                        "All WireGuard profiles now drop traffic if the tunnel fails. Applies on next connect.",
                    );
                }
            },
        )
    }

    /// Build the connect-at-boot row: a switch that arms one random eligible
    /// profile at login, by installing the autostart entry whose hidden launch
    /// performs the connection.
    fn build_autoconnect_row<C>(
        client: &C,
        status: &gtk::Label,
        indicators: &StatusIndicators,
    ) -> adw::ActionRow
    where
        C: NmClient + Clone + Send + 'static,
    {
        let client = client.clone();
        let indicators = indicators.clone();
        let autoconnect_initial = load_flag(|c| c.autoconnect_at_boot);

        indicators.eligibility.set_sensitive(autoconnect_initial);
        indicators
            .eligibility
            .set_enable_expansion(autoconnect_initial);
        if !autoconnect_initial {
            indicators.eligibility.set_expanded(false);
        }

        build_toggle_row(
            status,
            "Auto-Connect at Login",
            "Connect a random eligible profile when you log in",
            "Failed to update auto-connect",
            autoconnect_initial,
            move |enable| apply_autoconnect_at_login(&client, enable),
            move |enable| {
                let has_rows = !indicators.eligibility_rows.borrow().is_empty();
                indicators.eligibility.set_sensitive(enable);
                indicators
                    .eligibility
                    .set_enable_expansion(enable && has_rows);
                if !enable {
                    indicators.eligibility.set_expanded(false);
                }
                update_eligibility_subtitle(&indicators);
            },
        )
    }

    /// Toggle login-time auto-connect and persist the new state to config.
    fn apply_autoconnect_at_login<C: NmClient>(client: &C, enable: bool) -> Result<(), String> {
        let path = config::default_config_path().map_err(|error| error.to_string())?;
        service::set_autoconnect_at_login(client, &path, enable).map_err(|error| error.to_string())
    }

    /// Restore a switch to `active` without re-triggering its async handler.
    fn revert_switch(toggle: &gtk::Switch, guard: &Rc<Cell<bool>>, active: bool) {
        guard.set(true);
        toggle.set_active(active);
        guard.set(false);
    }

    /// Apply the global kill switch to every WireGuard profile and persist the
    /// new state to config.
    fn apply_global_kill_switch<C: NmClient>(client: &C, enable: bool) -> Result<(), String> {
        let path = config::default_config_path().map_err(|error| error.to_string())?;
        crate::app::set_global_kill_switch(client, &path, enable).map_err(|error| error.to_string())
    }

    /// Build the global lockdown row: a switch that installs (or removes) the
    /// always-on firewall blocking every non-VPN packet.
    fn build_lockdown_row<C>(app: &Application, client: &C, status: &gtk::Label) -> adw::ActionRow
    where
        C: NmClient + FirewallClient + Clone + Send + 'static,
    {
        let client = client.clone();
        let app = app.clone();
        build_toggle_row(
            status,
            "Lockdown Mode",
            "Strictly block non-VPN packets via system firewall (requires root)",
            "Failed to update lockdown",
            load_flag(|c| c.lockdown_enabled),
            move |enable| apply_global_lockdown(&client, enable),
            move |enabled| {
                if enabled {
                    notify(
                        &app,
                        "neutron-lockdown",
                        "Lockdown enabled",
                        "All non-VPN traffic is blocked until lockdown is disabled in settings.",
                    );
                }
            },
        )
    }

    /// Apply the always-on lockdown firewall and persist the new state to config.
    fn apply_global_lockdown<C: NmClient + FirewallClient>(
        client: &C,
        enable: bool,
    ) -> Result<(), String> {
        let path = config::default_config_path().map_err(|error| error.to_string())?;
        crate::app::set_global_lockdown(client, &path, enable).map_err(|error| error.to_string())
    }

    /// Build the global split-tunneling settings row.
    fn build_split_tunnel_row<C>(client: &C, status: &gtk::Label) -> adw::ActionRow
    where
        C: NmClient + Clone + Send + 'static,
    {
        let app_cfg = config::default_config_path()
            .and_then(|p| config::load(&p))
            .unwrap_or_default();
        let subtitle =
            crate::app::split_tunnel::format_summary_subtitle(&app_cfg.global_split_tunnel);

        let row = adw::ActionRow::builder()
            .title("Split Tunneling")
            .subtitle(subtitle)
            .activatable(true)
            .build();
        row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));

        let client = client.clone();
        let status = status.clone();
        let row_weak = row.downgrade();

        row.connect_activated(move |row| {
            let parent = row.root().and_downcast::<gtk::Window>();
            let row_for_cb = row_weak.clone();
            let status_for_cb = status.clone();
            show_global_split_tunnel_dialog(parent.as_ref(), &client, move |new_cfg| {
                if let Some(row) = row_for_cb.upgrade() {
                    let sub = crate::app::split_tunnel::format_summary_subtitle(new_cfg);
                    row.set_subtitle(&sub);
                }
                status_for_cb.set_label(&format!(
                    "Updated global split tunneling ({}).",
                    new_cfg.mode
                ));
            });
        });

        row
    }

    /// Build the "Import" button: opens a file chooser and imports the chosen
    /// WireGuard `.conf` as a new NetworkManager profile. The blocking `nmcli`
    /// import runs off the GTK main thread; the profile list refreshes on
    /// success so the new profile appears without a manual Refresh.
    fn build_import_button<C>(
        client: &C,
        list: &gtk::ListBox,
        indicators: &StatusIndicators,
    ) -> gtk::Button
    where
        C: NmClient + FirewallClient + Clone + Send + 'static,
    {
        let button = gtk::Button::with_label("Import");
        button.set_halign(gtk::Align::Start);

        let client = client.clone();
        let list = list.clone();
        let indicators = indicators.clone();
        button.connect_clicked(move |button| {
            // The button is realized by click time, so its root is the window;
            // parent the chooser on it so it centers correctly.
            let parent = button.root().and_downcast::<gtk::Window>();
            show_provider_chooser(parent.as_ref(), &client, &list, &indicators);
        });

        button
    }

    /// Offer the import sources as a GNOME "Add VPN"-style chooser: each source
    /// is a row in a boxed list that opens its guided flow, plus a manual
    /// file-import row.
    fn show_provider_chooser<C>(
        parent: Option<&gtk::Window>,
        client: &C,
        list: &gtk::ListBox,
        indicators: &StatusIndicators,
    ) where
        C: NmClient + FirewallClient + Clone + Send + 'static,
    {
        let window = adw::Window::builder()
            .modal(true)
            .title("Import VPN profile")
            .default_width(400)
            .build();
        if let Some(parent) = parent {
            window.set_transient_for(Some(parent));
        }

        let header = HeaderBar::new();
        let cancel = gtk::Button::with_label("Cancel");
        {
            let window = window.downgrade();
            cancel.connect_clicked(move |_| {
                if let Some(window) = window.upgrade() {
                    window.close();
                }
            });
        }
        header.pack_start(&cancel);

        let providers = gtk::ListBox::new();
        providers.set_selection_mode(gtk::SelectionMode::None);
        providers.add_css_class("boxed-list");

        type ImportAction = Box<dyn Fn(Option<&gtk::Window>)>;
        let entries: [(&str, &str, ImportAction); 3] = [
            (
                "ProtonVPN",
                "Download configurations from your Proton account",
                {
                    let client = client.clone();
                    let list = list.clone();
                    let indicators = indicators.clone();
                    Box::new(move |parent| {
                        show_guided_import_dialog(
                            parent,
                            "Import from ProtonVPN",
                            PROTON_IMPORT_STEPS,
                            &client,
                            &list,
                            &indicators,
                        );
                    })
                },
            ),
            (
                "MullvadVPN",
                "Download configurations from your Mullvad account",
                {
                    let client = client.clone();
                    let list = list.clone();
                    let indicators = indicators.clone();
                    Box::new(move |parent| {
                        show_guided_import_dialog(
                            parent,
                            "Import from MullvadVPN",
                            MULLVAD_IMPORT_STEPS,
                            &client,
                            &list,
                            &indicators,
                        );
                    })
                },
            ),
            ("Manual import", "Import a WireGuard .conf file", {
                let client = client.clone();
                let list = list.clone();
                let indicators = indicators.clone();
                Box::new(move |parent| {
                    open_manual_import(parent, &client, &list, &indicators);
                })
            }),
        ];

        for (title, subtitle, action) in entries {
            let row = provider_chooser_row(title, subtitle, true);
            let window = window.downgrade();
            let parent = parent.cloned();
            row.connect_activated(move |_| {
                if let Some(w) = window.upgrade() {
                    w.close();
                }
                action(parent.as_ref());
            });
            providers.append(&row);
        }

        let content = gtk::Box::new(Orientation::Vertical, 0);
        content.set_margin_top(12);
        content.set_margin_bottom(12);
        content.set_margin_start(12);
        content.set_margin_end(12);
        content.append(&providers);

        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&header);
        toolbar.set_content(Some(&content));
        window.set_content(Some(&toolbar));
        window.present();
    }

    /// Build one row for the provider chooser: a leading VPN icon, a
    /// title/subtitle, and—when actionable—a trailing arrow hinting at a flow.
    fn provider_chooser_row(title: &str, subtitle: &str, activatable: bool) -> adw::ActionRow {
        let row = adw::ActionRow::builder()
            .title(title)
            .subtitle(subtitle)
            .activatable(activatable)
            .build();
        row.add_prefix(&gtk::Image::from_icon_name("network-vpn-symbolic"));
        if activatable {
            row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
        }
        row
    }

    /// ProtonVPN guided-import steps (Pango markup; links open via the portal):
    /// the account downloads generator and the support guide for per-server
    /// configs.
    const PROTON_IMPORT_STEPS: &str = "To add a ProtonVPN profile:\n\n\
        1. Open the WireGuard downloads page and sign in. \
        <a href=\"https://account.protonvpn.com/downloads#wireguard-configuration\">Downloads page</a>\n\n\
        2. Create and download a configuration for each server you want. \
        <a href=\"https://protonvpn.com/support/wireguard-configurations\">Configuration guide</a>\n\n\
        3. Choose the downloaded <tt>.conf</tt> file(s) below to import them.";

    /// Mullvad guided-import steps. Links: the account configuration generator
    /// and the WireGuard help index. The wg-quick-specific guide is avoided
    /// since this app drives connections through NetworkManager, not wg-quick.
    const MULLVAD_IMPORT_STEPS: &str = "To add a Mullvad VPN profile:\n\n\
        1. Open the WireGuard configuration page and log in with your account number. \
        <a href=\"https://mullvad.net/en/account/wireguard-config\">Configuration page</a>\n\n\
        2. Generate a key, choose your servers, and download the configuration. \
        Extract the <tt>.zip</tt> if it contains several files. \
        <a href=\"https://mullvad.net/en/help?Protocol=wireguard\">Mullvad help center</a>\n\n\
        3. Choose the downloaded <tt>.conf</tt> file(s) below to import them.";

    /// Guided provider import: show provider-specific `instructions` (Pango
    /// markup, with links routed through the desktop portal), then a "Choose
    /// files…" action that hands off to the manual file importer. Shared by the
    /// ProtonVPN and Mullvad flows.
    fn show_guided_import_dialog<C>(
        parent: Option<&gtk::Window>,
        heading: &str,
        instructions: &str,
        client: &C,
        list: &gtk::ListBox,
        indicators: &StatusIndicators,
    ) where
        C: NmClient + FirewallClient + Clone + Send + 'static,
    {
        let dialog = adw::MessageDialog::new(parent, Some(heading), None);

        let body = gtk::Label::builder()
            .use_markup(true)
            .wrap(true)
            .xalign(0.0)
            .width_request(440)
            .max_width_chars(60)
            .label(instructions)
            .build();
        // Route link clicks through gtk::UriLauncher so the URL opens via the
        // desktop portal inside the Flatpak sandbox.
        {
            let parent = parent.cloned();
            body.connect_activate_link(move |_, uri| {
                let launcher = gtk::UriLauncher::new(uri);
                launcher.launch(parent.as_ref(), gio::Cancellable::NONE, |_| {});
                glib::Propagation::Stop
            });
        }
        dialog.set_extra_child(Some(&body));

        dialog.add_response("cancel", "_Cancel");
        dialog.add_response("choose", "_Choose files\u{2026}");
        dialog.set_response_appearance("choose", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("choose"));
        dialog.set_close_response("cancel");

        let parent = parent.cloned();
        let client = client.clone();
        let list = list.clone();
        let indicators = indicators.clone();
        dialog.connect_response(None, move |_, response| {
            if response == "choose" {
                open_manual_import(parent.as_ref(), &client, &list, &indicators);
            }
        });
        dialog.present();
    }

    /// Open a modal settings dialog to configure Global Split Tunneling rules.
    fn show_global_split_tunnel_dialog<C, F>(parent: Option<&gtk::Window>, client: &C, on_saved: F)
    where
        C: NmClient + Clone + Send + 'static,
        F: Fn(&crate::config::SplitTunnelConfig) + Clone + 'static,
    {
        let window = adw::Window::builder()
            .modal(true)
            .title("Global Split Tunneling")
            .default_width(480)
            .default_height(560)
            .build();
        if let Some(parent) = parent {
            window.set_transient_for(Some(parent));
        }

        let header = HeaderBar::new();
        let cancel = gtk::Button::with_label("Cancel");
        {
            let window = window.downgrade();
            cancel.connect_clicked(move |_| {
                if let Some(w) = window.upgrade() {
                    w.close();
                }
            });
        }
        header.pack_start(&cancel);

        let app_cfg = config::default_config_path()
            .and_then(|p| config::load(&p))
            .unwrap_or_default();
        let initial_st = app_cfg.global_split_tunnel;

        let current_mode = Rc::new(Cell::new(initial_st.mode));
        let current_cidrs = Rc::new(RefCell::new(initial_st.cidrs));
        let current_domains = Rc::new(RefCell::new(initial_st.domains));

        let save_button = gtk::Button::builder()
            .label("Save")
            .css_classes(vec!["suggested-action".to_string()])
            .build();

        {
            let client = client.clone();
            let on_saved = on_saved.clone();
            let current_mode = current_mode.clone();
            let current_cidrs = current_cidrs.clone();
            let current_domains = current_domains.clone();
            let window_weak = window.downgrade();

            save_button.connect_clicked(move |btn| {
                btn.set_sensitive(false);
                let client = client.clone();
                let on_saved = on_saved.clone();
                let window_weak = window_weak.clone();
                let st_cfg = crate::config::SplitTunnelConfig {
                    mode: current_mode.get(),
                    cidrs: current_cidrs.borrow().clone(),
                    domains: current_domains.borrow().clone(),
                };

                glib::spawn_future_local(async move {
                    let task_client = client.clone();
                    let task_st = st_cfg.clone();
                    let outcome = spawn_blocking_flat(move || {
                        let path = config::default_config_path()?;
                        crate::app::split_tunnel::apply_and_persist_global_split_tunnel(
                            &task_client,
                            &path,
                            &task_st,
                        )
                    })
                    .await;

                    if let Some(window) = window_weak.upgrade() {
                        match outcome {
                            Ok(()) => {
                                on_saved(&st_cfg);
                                window.close();
                            }
                            Err(error) => {
                                let parent = window.transient_for();
                                show_error_dialog(
                                    parent.as_ref(),
                                    &format!("Failed to save split tunneling: {error}"),
                                );
                            }
                        }
                    }
                });
            });
        }
        header.pack_end(&save_button);

        let content = gtk::Box::new(Orientation::Vertical, 16);
        content.set_margin_top(16);
        content.set_margin_bottom(16);
        content.set_margin_start(16);
        content.set_margin_end(16);

        // Mode selector
        let mode_group = adw::PreferencesGroup::builder()
            .title("Routing Mode")
            .description("Choose how traffic routes through this VPN tunnel")
            .build();

        let mode_model = gtk::StringList::new(&["Disabled", "Include", "Exclude"]);
        let mode_row = adw::ComboRow::builder()
            .title("Mode")
            .model(&mode_model)
            .build();

        let initial_selected = match initial_st.mode {
            config::SplitTunnelMode::Disabled => 0,
            config::SplitTunnelMode::Include => 1,
            config::SplitTunnelMode::Exclude => 2,
        };
        mode_row.set_selected(initial_selected);

        {
            let current_mode = current_mode.clone();
            mode_row.connect_selected_notify(move |row| {
                let mode = match row.selected() {
                    1 => config::SplitTunnelMode::Include,
                    2 => config::SplitTunnelMode::Exclude,
                    _ => config::SplitTunnelMode::Disabled,
                };
                current_mode.set(mode);
            });
        }
        mode_group.add(&mode_row);
        content.append(&mode_group);

        // CIDRs Group
        let cidr_group = adw::PreferencesGroup::builder()
            .title("Subnets & IP Addresses")
            .description("Specific CIDRs or IPs (e.g. 10.0.0.0/8, 192.168.1.50/32)")
            .build();

        let cidr_list = gtk::ListBox::new();
        cidr_list.add_css_class("boxed-list");
        cidr_list.set_selection_mode(gtk::SelectionMode::None);

        let cidr_entry = adw::EntryRow::builder().title("Add CIDR / IP").build();
        let cidr_add_btn = gtk::Button::builder()
            .icon_name("list-add-symbolic")
            .css_classes(vec!["flat".to_string()])
            .valign(gtk::Align::Center)
            .tooltip_text("Add CIDR")
            .build();
        cidr_entry.add_suffix(&cidr_add_btn);

        type ListRefreshCallback = Rc<RefCell<Option<Box<dyn Fn()>>>>;
        let refresh_cidr_list: ListRefreshCallback = Rc::new(RefCell::new(None));
        {
            let cidr_list = cidr_list.clone();
            let current_cidrs = current_cidrs.clone();
            let refresh_slot = refresh_cidr_list.clone();
            *refresh_cidr_list.borrow_mut() = Some(Box::new(move || {
                while let Some(child) = cidr_list.first_child() {
                    cidr_list.remove(&child);
                }
                let items = current_cidrs.borrow().clone();
                for item in items {
                    let row = adw::ActionRow::builder().title(&item).build();
                    let del_btn = gtk::Button::builder()
                        .icon_name("user-trash-symbolic")
                        .css_classes(vec!["flat".to_string()])
                        .valign(gtk::Align::Center)
                        .tooltip_text("Remove route")
                        .build();

                    let current_cidrs = current_cidrs.clone();
                    let refresh_slot = refresh_slot.clone();
                    let item_clone = item.clone();
                    del_btn.connect_clicked(move |_| {
                        current_cidrs.borrow_mut().retain(|x| x != &item_clone);
                        if let Some(ref cb) = *refresh_slot.borrow() {
                            cb();
                        }
                    });
                    row.add_suffix(&del_btn);
                    cidr_list.append(&row);
                }
            }));
        }

        if let Some(ref cb) = *refresh_cidr_list.borrow() {
            cb();
        }

        {
            let current_cidrs = current_cidrs.clone();
            let refresh_cidr_list = refresh_cidr_list.clone();
            let entry_for_add = cidr_entry.clone();
            let on_add = move || {
                let text = entry_for_add.text().to_string();
                if let Ok((normalized, _)) =
                    crate::nm::split_tunnel::parse_and_normalize_cidr(&text)
                {
                    let mut list = current_cidrs.borrow_mut();
                    if !list.contains(&normalized) {
                        list.push(normalized);
                    }
                    drop(list);
                    entry_for_add.set_text("");
                    if let Some(ref cb) = *refresh_cidr_list.borrow() {
                        cb();
                    }
                }
            };

            let on_add_rc = Rc::new(on_add);
            let on_add_btn = on_add_rc.clone();
            cidr_add_btn.connect_clicked(move |_| {
                on_add_btn();
            });
            let on_add_entry = on_add_rc.clone();
            cidr_entry.connect_entry_activated(move |_| {
                on_add_entry();
            });
        }

        cidr_group.add(&cidr_entry);
        cidr_group.add(&cidr_list);
        content.append(&cidr_group);

        // Domains Group
        let domain_group = adw::PreferencesGroup::builder()
            .title("Domain Names")
            .description("Resolved to IP addresses when connecting (e.g. internal.corp)")
            .build();

        let domain_list = gtk::ListBox::new();
        domain_list.add_css_class("boxed-list");
        domain_list.set_selection_mode(gtk::SelectionMode::None);

        let domain_entry = adw::EntryRow::builder().title("Add Domain").build();
        let domain_add_btn = gtk::Button::builder()
            .icon_name("list-add-symbolic")
            .css_classes(vec!["flat".to_string()])
            .valign(gtk::Align::Center)
            .tooltip_text("Add Domain")
            .build();
        domain_entry.add_suffix(&domain_add_btn);

        let refresh_domain_list: ListRefreshCallback = Rc::new(RefCell::new(None));
        {
            let domain_list = domain_list.clone();
            let current_domains = current_domains.clone();
            let refresh_slot = refresh_domain_list.clone();
            *refresh_domain_list.borrow_mut() = Some(Box::new(move || {
                while let Some(child) = domain_list.first_child() {
                    domain_list.remove(&child);
                }
                let items = current_domains.borrow().clone();
                for item in items {
                    let row = adw::ActionRow::builder().title(&item).build();
                    let del_btn = gtk::Button::builder()
                        .icon_name("user-trash-symbolic")
                        .css_classes(vec!["flat".to_string()])
                        .valign(gtk::Align::Center)
                        .tooltip_text("Remove domain")
                        .build();

                    let current_domains = current_domains.clone();
                    let refresh_slot = refresh_slot.clone();
                    let item_clone = item.clone();
                    del_btn.connect_clicked(move |_| {
                        current_domains.borrow_mut().retain(|x| x != &item_clone);
                        if let Some(ref cb) = *refresh_slot.borrow() {
                            cb();
                        }
                    });
                    row.add_suffix(&del_btn);
                    domain_list.append(&row);
                }
            }));
        }

        if let Some(ref cb) = *refresh_domain_list.borrow() {
            cb();
        }

        {
            let current_domains = current_domains.clone();
            let refresh_domain_list = refresh_domain_list.clone();
            let entry_for_add = domain_entry.clone();
            let on_add = move || {
                let text = entry_for_add.text().trim().to_lowercase();
                if !text.is_empty() {
                    let mut list = current_domains.borrow_mut();
                    if !list.contains(&text) {
                        list.push(text);
                    }
                    drop(list);
                    entry_for_add.set_text("");
                    if let Some(ref cb) = *refresh_domain_list.borrow() {
                        cb();
                    }
                }
            };

            let on_add_rc = Rc::new(on_add);
            let on_add_btn = on_add_rc.clone();
            domain_add_btn.connect_clicked(move |_| {
                on_add_btn();
            });
            let on_add_entry = on_add_rc.clone();
            domain_entry.connect_entry_activated(move |_| {
                on_add_entry();
            });
        }

        domain_group.add(&domain_entry);
        domain_group.add(&domain_list);
        content.append(&domain_group);

        let clamp = adw::Clamp::builder()
            .maximum_size(500)
            .child(&content)
            .build();

        let scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vscrollbar_policy(gtk::PolicyType::Automatic)
            .vexpand(true)
            .hexpand(true)
            .child(&clamp)
            .build();

        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&header);
        toolbar.set_content(Some(&scroller));
        window.set_content(Some(&toolbar));
        window.present();
    }

    /// Open the multi-file chooser and import every selected WireGuard config,
    /// aggregating per-file failures so one bad file doesn't abort the batch.
    /// Shared by the "Manual import" option and the provider flows.
    fn open_manual_import<C>(
        parent: Option<&gtk::Window>,
        client: &C,
        list: &gtk::ListBox,
        indicators: &StatusIndicators,
    ) where
        C: NmClient + FirewallClient + Clone + Send + 'static,
    {
        let filter = gtk::FileFilter::new();
        filter.set_name(Some("WireGuard configuration (*.conf)"));
        filter.add_pattern("*.conf");
        let filters = gio::ListStore::new::<gtk::FileFilter>();
        filters.append(&filter);

        let dialog = gtk::FileDialog::builder()
            .title("Import WireGuard configuration")
            .modal(true)
            .filters(&filters)
            .default_filter(&filter)
            .build();

        let client = client.clone();
        let list = list.clone();
        let indicators = indicators.clone();
        // Reuse the window to parent any error dialogs raised while handling
        // the chosen file.
        let dialog_parent = parent.cloned();
        dialog.open_multiple(parent, gio::Cancellable::NONE, move |result| {
            let files = match result {
                Ok(files) => files,
                // The user dismissed the chooser; nothing to import.
                Err(_) => return,
            };

            // Collect a local path for every chosen file. Files without one
            // (rare; e.g. a non-local URI) are reported alongside any later
            // import failures rather than silently skipped.
            let mut paths: Vec<std::path::PathBuf> = Vec::new();
            let mut failures: Vec<String> = Vec::new();
            for index in 0..files.n_items() {
                let Some(file) = files.item(index).and_downcast::<gio::File>() else {
                    continue;
                };
                match file.path() {
                    Some(path) => paths.push(path),
                    None => failures.push(format!(
                        "{}: file has no local path",
                        file.basename()
                            .map(|name| name.display().to_string())
                            .unwrap_or_else(|| "selected file".to_string())
                    )),
                }
            }

            if paths.is_empty() {
                if !failures.is_empty() {
                    show_error_dialog(
                        dialog_parent.as_ref(),
                        &format!("Import failed:\n{}", failures.join("\n")),
                    );
                }
                return;
            }

            let task_client = client.clone();
            let client = client.clone();
            let list = list.clone();
            let indicators = indicators.clone();
            let dialog_parent = dialog_parent.clone();
            glib::spawn_future_local(async move {
                // Import sequentially on a worker thread, collecting a
                // message for each file that fails so one bad config does not
                // abort the rest of the batch.
                let outcome = spawn_blocking_flat(move || {
                    let mut errors = Vec::new();
                    for path in &paths {
                        if let Err(error) = task_client.import_wireguard_profile(path) {
                            errors.push(format!("{}: {error}", path.display()));
                        }
                    }
                    // Freshly imported profiles default to `autoconnect=yes`.
                    // Re-arm so exactly one profile is left set to come up at
                    // the next boot, rather than every profile just imported.
                    service::disable_nm_autoconnect(&task_client);
                    // The lockdown allow-list pins each profile's interface
                    // and endpoint, so a profile added now has no rule and
                    // would be rejected. Rebuild it against the new set.
                    profile_set_changed(&task_client);
                    Ok::<Vec<String>, String>(errors)
                })
                .await;

                // Refresh once: even a partly failed batch may have added
                // some profiles.
                refresh_profile_list(&client, &list, &indicators);

                match outcome {
                    Ok(import_errors) => {
                        failures.extend(import_errors);
                        if !failures.is_empty() {
                            show_error_dialog(
                                dialog_parent.as_ref(),
                                &format!("Some imports failed:\n{}", failures.join("\n")),
                            );
                        }
                    }
                    Err(err) => {
                        show_error_dialog(dialog_parent.as_ref(), &format!("Import failed: {err}"));
                    }
                }
            });
        });
    }

    /// Absolute path of an installed status shield, if it is on disk.
    ///
    /// The in-window banner loads the file directly instead of going through an
    /// icon-name lookup: this process installs those files itself moments
    /// earlier, so the path is known exactly, and a themed lookup can still be
    /// serving a pre-install view of the theme.
    ///
    /// The raster copy is used rather than the SVG because the banner draws at a
    /// fixed 20px, where scalability buys nothing, and decoding an SVG needs an
    /// image loader (`glycin-svg`/librsvg) that an AppImage cannot assume is
    /// installed on the host.
    fn status_icon_path(connected: bool) -> Option<std::path::PathBuf> {
        let name = if connected {
            ICON_CONNECTED
        } else {
            ICON_DISCONNECTED
        };
        let path = dirs::data_dir()?.join(format!("icons/hicolor/48x48/apps/{name}.png"));
        path.is_file().then_some(path)
    }

    /// Paint the in-window connection banner, using the same green/red shields
    /// as the tray so both surfaces read identically at a glance. The shields
    /// carry their own colour, so no `success`/`error` CSS class is applied.
    fn update_vpn_status_widget(connected: bool, icon: &gtk::Image, label: &gtk::Label) {
        icon.remove_css_class("success");
        icon.remove_css_class("error");

        match status_icon_path(connected) {
            Some(path) => icon.set_from_file(Some(&path)),
            // Falls back to the theme when the file is not there yet, e.g. the
            // very first launch on a read-only home.
            None if connected => icon.set_icon_name(Some(ICON_CONNECTED)),
            None => icon.set_icon_name(Some(ICON_DISCONNECTED)),
        }

        if connected {
            label.set_markup(
                "<span size='large' weight='bold' foreground='#2ec27e'>Connected</span>",
            );
        } else {
            label.set_markup(
                "<span size='large' weight='bold' foreground='#e01b24'>Disconnected</span>",
            );
        }
    }

    /// Show an error message in a modal dialog. Unlike the transient status
    /// line, the dialog body is selectable so the user can copy the text (handy
    /// for pasting an nmcli or firewall error into a bug report).
    fn show_error_dialog(parent: Option<&gtk::Window>, message: &str) {
        let dialog = adw::MessageDialog::new(parent, Some("Error"), None);
        let body = gtk::Label::builder()
            .label(message)
            .selectable(true)
            .wrap(true)
            .xalign(0.0)
            .max_width_chars(50)
            .build();
        dialog.set_extra_child(Some(&body));
        dialog.add_response("close", "_Close");
        dialog.set_default_response(Some("close"));
        dialog.set_close_response("close");
        dialog.present();
    }

    /// Push the stored connection state onto every surface that shows it: the
    /// status line, the forwarded-port row, and the tray indicator.
    ///
    /// The connection state and the forwarded port arrive from two independent
    /// async sources (the profile reload and the NAT-PMP probe), so both write
    /// to [`StatusIndicators`] and call this instead of updating widgets
    /// piecemeal and risking a half-updated view.
    fn sync_connection_status(indicators: &StatusIndicators) {
        let profile = indicators.active_profile.borrow().clone();
        let port = *indicators.active_port.borrow();
        let connected = profile.is_some();

        update_vpn_status_widget(connected, &indicators.vpn_icon, &indicators.vpn_label);

        match port {
            Some(port) => {
                indicators
                    .port_label
                    .set_markup(&format!("Forwarded port: <b><tt>{port}</tt></b>"));
                indicators
                    .port_copy_button
                    .set_tooltip_text(Some("Copy port to clipboard"));
                indicators.port_box.set_visible(true);
            }
            // Most servers do not offer port forwarding, so having no port is
            // the normal case and gets no error styling -- the row just hides.
            None => indicators.port_box.set_visible(false),
        }

        if let Some(indicator) = indicators.indicator.borrow().as_ref() {
            indicator.update_status(connected, profile.as_deref(), port);
        }
    }

    /// Ask the tunnel gateway for a forwarded port and show whatever it grants.
    ///
    /// This both creates and renews the lease: NAT-PMP treats a repeat request
    /// for the same mapping as a renewal, so calling it on the renew timer keeps
    /// the port alive. A failure means the server does not forward ports, which
    /// is reported by hiding the row rather than as an error.
    fn refresh_port_forwarding<C>(client: &C, indicators: &StatusIndicators, uuid: String)
    where
        C: NmClient + Clone + Send + 'static,
    {
        let client = client.clone();
        let indicators = indicators.clone();
        glib::spawn_future_local(async move {
            let outcome = spawn_blocking_flat(move || {
                let address = client.tunnel_address(&uuid).ok_or_else(|| {
                    AppError::PortForward("profile has no IPv4 tunnel address".to_string())
                })?;
                let gateway = portforward::gateway_for_address(&address).ok_or_else(|| {
                    AppError::PortForward(format!("no NAT-PMP gateway derivable from {address}"))
                })?;
                portforward::request_mapping(gateway)
            })
            .await;

            match outcome {
                Ok(port) => *indicators.active_port.borrow_mut() = Some(port),
                Err(error) => {
                    debug!("no forwarded port available: {error}");
                    *indicators.active_port.borrow_mut() = None;
                }
            }
            sync_connection_status(&indicators);
        });
    }

    /// Reload the profile list. The blocking NetworkManager/config work runs on
    /// the Gio thread pool so the GTK main thread (and thus the UI) never blocks
    /// on `nmcli`. Widget creation happens back on the main thread once the data
    /// is available.
    fn refresh_profile_list<C>(client: &C, list: &gtk::ListBox, indicators: &StatusIndicators)
    where
        C: NmClient + FirewallClient + Clone + Send + 'static,
    {
        let is_empty = list.first_child().is_none();
        if is_empty {
            indicators.log.set_label("Loading profiles\u{2026}");
        }

        let client_for_load = client.clone();
        let client_for_rows = client.clone();
        let list = list.clone();
        let indicators = indicators.clone();
        glib::spawn_future_local(async move {
            let outcome = spawn_blocking_flat(move || load_rows(&client_for_load)).await;
            match outcome {
                Ok(rows) => {
                    if rows.is_empty() {
                        indicators.log.set_label(
                            "No WireGuard profiles found. Import a configuration to add one.",
                        );
                    } else if is_empty {
                        indicators
                            .log
                            .set_label("Profiles loaded from NetworkManager.");
                    }
                    rebuild_eligibility_rows(&indicators, &rows);

                    let active = rows.iter().find(|r| r.is_active);
                    let was_connected = indicators.active_profile.borrow().is_some();
                    *indicators.active_profile.borrow_mut() = active.map(|r| r.name.clone());
                    if was_connected && active.is_none() {
                        notify_tunnel_dropped(&indicators);
                    }

                    // A port belongs to the tunnel that was granted it, so drop
                    // it whenever the active profile changes (including on
                    // disconnect) rather than showing a stale port.
                    let active_uuid = active.map(|r| r.uuid.clone());
                    if *indicators.port_profile.borrow() != active_uuid {
                        *indicators.port_profile.borrow_mut() = active_uuid.clone();
                        *indicators.active_port.borrow_mut() = None;
                    }
                    sync_connection_status(&indicators);

                    if let Some(uuid) = active_uuid {
                        refresh_port_forwarding(&client_for_rows, &indicators, uuid);
                    }

                    while let Some(child) = list.first_child() {
                        list.remove(&child);
                    }
                    for row in rows {
                        let row_widget =
                            build_profile_row(&client_for_rows, &row, &list, &indicators);
                        list.append(&row_widget);
                    }
                }
                Err(error) => {
                    indicators
                        .log
                        .set_label(&format!("Failed to load profiles: {error}"));
                }
            }
        });
    }

    fn load_rows(client: &impl NmClient) -> Result<Vec<profile_list::ProfileListRow>, String> {
        let config_path = config::default_config_path().map_err(|error| error.to_string())?;
        load_rows_with_path(client, &config_path)
    }

    fn load_rows_with_path(
        client: &impl NmClient,
        config_path: &std::path::Path,
    ) -> Result<Vec<profile_list::ProfileListRow>, String> {
        let profiles = client
            .list_wireguard_profiles()
            .map_err(|error| error.to_string())?;
        let app_cfg = config::load(config_path).map_err(|error| error.to_string())?;

        Ok(profile_list::build_rows(
            &profiles,
            &app_cfg.excluded_profile_ids,
            &app_cfg.profile_custom_info,
        ))
    }

    fn set_eligibility_for_profile(profile_id: &str, eligible: bool) -> Result<bool, String> {
        let config_path = config::default_config_path().map_err(|error| error.to_string())?;
        set_eligibility_for_profile_with_path(&config_path, profile_id, eligible)
    }

    fn set_eligibility_for_profile_with_path(
        config_path: &std::path::Path,
        profile_id: &str,
        eligible: bool,
    ) -> Result<bool, String> {
        let mut app_cfg = config::load(config_path).map_err(|error| error.to_string())?;
        let changed = eligibility::set_profile_eligible(
            &mut app_cfg.excluded_profile_ids,
            profile_id,
            eligible,
        );
        if changed {
            config::save(config_path, &app_cfg).map_err(|error| error.to_string())?;
        }
        Ok(changed)
    }

    fn rebuild_eligibility_rows(
        indicators: &StatusIndicators,
        rows: &[profile_list::ProfileListRow],
    ) {
        {
            let mut tracked = indicators.eligibility_rows.borrow_mut();
            for old in tracked.drain(..) {
                indicators.eligibility.remove(&old);
            }
            for row in rows {
                let switch_row = adw::SwitchRow::builder().title(&row.name).build();
                // Set state before wiring the handler so this programmatic
                // toggle doesn't fire a spurious config write.
                switch_row.set_active(row.eligible);
                {
                    let indicators = indicators.clone();
                    let uuid = row.uuid.clone();
                    let name = row.name.clone();
                    switch_row.connect_active_notify(move |sw| {
                        on_eligibility_toggled(&indicators, &uuid, &name, sw.is_active());
                    });
                }
                indicators.eligibility.add_row(&switch_row);
                tracked.push(switch_row);
            }
        }
        let autoconnect_on = load_flag(|c| c.autoconnect_at_boot);
        indicators.eligibility.set_sensitive(autoconnect_on);
        indicators
            .eligibility
            .set_enable_expansion(autoconnect_on && !rows.is_empty());
        if !autoconnect_on {
            indicators.eligibility.set_expanded(false);
        }
        update_eligibility_subtitle(indicators);
    }

    /// Persist a single profile's startup eligibility and refresh the summary
    /// subtitle. This only edits `excluded_profile_ids` in the config (no
    /// NetworkManager work), so it stays synchronous and never touches the
    /// profile list.
    fn on_eligibility_toggled(
        indicators: &StatusIndicators,
        uuid: &str,
        name: &str,
        eligible: bool,
    ) {
        match set_eligibility_for_profile(uuid, eligible) {
            Ok(_) => {
                let verb = if eligible { "Enabled" } else { "Disabled" };
                indicators
                    .log
                    .set_label(&format!("{verb} random login selection for '{name}'."));
            }
            Err(error) => {
                indicators.log.set_label(&format!(
                    "Failed to update eligibility for '{name}': {error}"
                ));
            }
        }
        update_eligibility_subtitle(indicators);
    }

    /// Summarise how many profiles are eligible for boot-time random selection
    /// in the expander subtitle, reading the live switch states.
    fn update_eligibility_subtitle(indicators: &StatusIndicators) {
        let autoconnect_on = load_flag(|c| c.autoconnect_at_boot);
        if !autoconnect_on {
            indicators
                .eligibility
                .set_subtitle("Disabled (Auto-Connect at Login is turned off)");
            return;
        }
        let tracked = indicators.eligibility_rows.borrow();
        let total = tracked.len();
        let subtitle = if total == 0 {
            "No profiles to choose from".to_string()
        } else {
            let eligible = tracked.iter().filter(|sw| sw.is_active()).count();
            format!("{eligible} of {total} eligible for random selection")
        };
        indicators.eligibility.set_subtitle(&subtitle);
    }

    fn build_connection_toggle<C>(
        client: &C,
        row: &profile_list::ProfileListRow,
        list: &gtk::ListBox,
        indicators: &StatusIndicators,
    ) -> gtk::Switch
    where
        C: NmClient + FirewallClient + Clone + Send + 'static,
    {
        let connection_toggle = gtk::Switch::new();
        connection_toggle.set_valign(gtk::Align::Center);
        connection_toggle.set_active(row.is_active);

        let client = client.clone();
        let row = row.clone();
        let list = list.clone();
        let indicators = indicators.clone();
        let guard = Rc::new(Cell::new(false));
        connection_toggle.connect_state_set(move |toggle, requested| {
            if guard.get() {
                return glib::Propagation::Proceed;
            }
            toggle.set_sensitive(false);

            let client = client.clone();
            let row = row.clone();
            let list = list.clone();
            let indicators = indicators.clone();
            let toggle = toggle.clone();
            let guard = guard.clone();
            glib::spawn_future_local(async move {
                let task_client = client.clone();
                let task_uuid = row.uuid.clone();
                let outcome = spawn_blocking_flat(move || {
                    if requested {
                        task_client.switch_to(&task_uuid)
                    } else {
                        task_client.disconnect_active()
                    }
                })
                .await;

                toggle.set_sensitive(true);
                let parent = toggle.root().and_downcast::<gtk::Window>();
                match outcome {
                    Ok(()) => {
                        refresh_profile_list(&client, &list, &indicators);
                    }
                    Err(error) => {
                        show_error_dialog(
                            parent.as_ref(),
                            &format!("Action failed for '{}': {error}", row.name),
                        );
                        revert_switch(&toggle, &guard, !requested);
                    }
                }
            });

            glib::Propagation::Proceed
        });

        connection_toggle
    }

    fn build_remove_button<C>(
        client: &C,
        row: &profile_list::ProfileListRow,
        list: &gtk::ListBox,
        indicators: &StatusIndicators,
    ) -> gtk::Button
    where
        C: NmClient + FirewallClient + Clone + Send + 'static,
    {
        let remove_button = gtk::Button::builder()
            .icon_name("user-trash-symbolic")
            .css_classes(vec!["flat".to_string()])
            .valign(gtk::Align::Center)
            .tooltip_text("Remove profile")
            .build();

        let client = client.clone();
        let row = row.clone();
        let list = list.clone();
        let indicators = indicators.clone();
        remove_button.connect_clicked(move |btn| {
            let parent = btn.root().and_downcast::<gtk::Window>();
            let confirm = adw::MessageDialog::new(
                parent.as_ref(),
                Some("Remove profile?"),
                Some(&format!(
                    "This permanently deletes '{}' from NetworkManager. This cannot be undone.",
                    row.name
                )),
            );
            confirm.add_response("cancel", "_Cancel");
            confirm.add_response("delete", "_Delete");
            confirm.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
            confirm.set_default_response(Some("cancel"));
            confirm.set_close_response("cancel");

            let client = client.clone();
            let row = row.clone();
            let list = list.clone();
            let indicators = indicators.clone();
            let parent = parent.clone();
            confirm.connect_response(None, move |_, response| {
                if response != "delete" {
                    return;
                }
                let client = client.clone();
                let row = row.clone();
                let list = list.clone();
                let indicators = indicators.clone();
                let parent = parent.clone();
                glib::spawn_future_local(async move {
                    let task_client = client.clone();
                    let task_uuid = row.uuid.clone();
                    let outcome = spawn_blocking_flat(move || {
                        task_client.delete_profile(&task_uuid)?;
                        // Deleting the armed profile would leave nothing set to
                        // come up at the next boot, so pick a replacement.
                        service::disable_nm_autoconnect(&task_client);
                        // Drop the deleted profile's stale allow-rule.
                        profile_set_changed(&task_client);
                        Ok::<(), AppError>(())
                    })
                    .await;
                    match outcome {
                        Ok(()) => {
                            // A NAT-PMP lease expires within a minute, so renew it on a timer for as
                            // long as a profile stays up. Without this the provider reclaims the
                            // port and the number on screen silently stops working.
                            {
                                let client = client.clone();
                                let indicators = indicators.clone();
                                glib::timeout_add_local(portforward::RENEW_INTERVAL, move || {
                                    let active_uuid = indicators.port_profile.borrow().clone();
                                    if let Some(uuid) = active_uuid {
                                        refresh_port_forwarding(&client, &indicators, uuid);
                                    }
                                    glib::ControlFlow::Continue
                                });
                            }

                            refresh_profile_list(&client, &list, &indicators);
                        }
                        Err(error) => {
                            show_error_dialog(
                                parent.as_ref(),
                                &format!("Failed to remove '{}': {error}", row.name),
                            );
                        }
                    }
                });
            });
            confirm.present();
        });

        remove_button
    }

    fn build_custom_info_box(custom: &str) -> gtk::Box {
        let info_box = gtk::Box::new(Orientation::Vertical, 4);
        info_box.set_margin_start(16);
        info_box.set_margin_end(16);
        info_box.set_margin_bottom(12);

        let divider = gtk::Separator::new(Orientation::Horizontal);
        divider.set_margin_bottom(8);
        info_box.append(&divider);

        let title_label = gtk::Label::builder()
            .label("<b>Provider Configuration Info:</b>")
            .use_markup(true)
            .xalign(0.0)
            .build();
        title_label.add_css_class("dim-label");
        info_box.append(&title_label);

        let info_label = gtk::Label::new(Some(custom));
        info_label.set_xalign(0.0);
        info_label.set_wrap(true);
        info_label.add_css_class("monospace");
        info_label.set_margin_start(8);
        info_box.append(&info_label);

        info_box.set_visible(false);
        info_box
    }

    fn build_profile_row<C>(
        client: &C,
        row: &profile_list::ProfileListRow,
        list: &gtk::ListBox,
        indicators: &StatusIndicators,
    ) -> gtk::ListBoxRow
    where
        C: NmClient + FirewallClient + Clone + Send + 'static,
    {
        let header_box = gtk::Box::new(Orientation::Horizontal, 12);
        header_box.set_margin_top(8);
        header_box.set_margin_bottom(8);
        header_box.set_margin_start(12);
        header_box.set_margin_end(12);

        let details = gtk::Label::new(Some(&row.name));
        details.set_xalign(0.0);
        details.set_hexpand(true);

        let connection_toggle = build_connection_toggle(client, row, list, indicators);

        let settings_button = gtk::Button::builder()
            .icon_name("preferences-system-symbolic")
            .css_classes(vec!["flat".to_string()])
            .valign(gtk::Align::Center)
            .tooltip_text("VPN options")
            .build();
        {
            let client = client.clone();
            let row = row.clone();
            settings_button.connect_clicked(move |btn| {
                let is_dark = adw::StyleManager::default().is_dark();
                if let Err(error) = client.edit_connection(&row.uuid, is_dark) {
                    let parent = btn.root().and_downcast::<gtk::Window>();
                    show_error_dialog(
                        parent.as_ref(),
                        &format!("Failed to edit connection '{}': {error}", row.name),
                    );
                }
            });
        }

        let remove_button = build_remove_button(client, row, list, indicators);

        header_box.append(&details);
        header_box.append(&connection_toggle);
        header_box.append(&settings_button);
        header_box.append(&remove_button);

        let container = gtk::Box::new(Orientation::Vertical, 0);
        container.append(&header_box);

        if let Some(ref custom) = row.custom_info {
            container.append(&build_custom_info_box(custom));
        }

        let list_row = gtk::ListBoxRow::new();
        list_row.set_child(Some(&container));
        list_row
    }

    #[cfg(test)]
    mod tests {
        use crate::config::AppConfig;
        use crate::nm::{ProfileState, WireguardProfile};
        use crate::testing::MockNmClient;

        use super::*;

        #[test]
        fn load_rows_fails_when_nm_fails() {
            let client = MockNmClient::failing_list();
            let config_path = crate::testing::temp_config_path("gui-fail");
            config::save(&config_path, &AppConfig::default()).expect("config should save");

            let result = load_rows_with_path(&client, &config_path);

            assert!(result.is_err());
            crate::testing::remove_temp_config(&config_path);
        }

        #[test]
        fn load_rows_maps_profiles() {
            let client = MockNmClient::new(vec![WireguardProfile {
                name: "wg-us".to_string(),
                uuid: "uuid-1".to_string(),
                state: ProfileState::Inactive,
            }]);

            let config_path = crate::testing::temp_config_path("gui-load");
            config::save(&config_path, &AppConfig::default()).expect("config should save");

            let result = load_rows_with_path(&client, &config_path);

            assert!(result.is_ok());
            crate::testing::remove_temp_config(&config_path);
        }

        #[test]
        fn set_eligibility_excludes_and_restores_profile() {
            let config_path = crate::testing::temp_config_path("gui-eligibility");
            config::save(&config_path, &AppConfig::default()).expect("config should save");

            // Marking a profile ineligible records it in the exclusion set.
            let changed = set_eligibility_for_profile_with_path(&config_path, "uuid-1", false)
                .expect("eligibility update should succeed");
            assert!(changed);
            let loaded = config::load(&config_path).expect("config should load");
            assert_eq!(
                loaded.excluded_profile_ids,
                std::collections::BTreeSet::from(["uuid-1".to_string()])
            );

            // Marking it eligible again clears the exclusion (opt-out default).
            let changed = set_eligibility_for_profile_with_path(&config_path, "uuid-1", true)
                .expect("eligibility update should succeed");
            assert!(changed);
            let loaded = config::load(&config_path).expect("config should load");
            assert!(loaded.excluded_profile_ids.is_empty());

            crate::testing::remove_temp_config(&config_path);
        }

        #[test]
        fn main_window_hosts_header_in_toolbar_view() {
            // Building an AdwApplicationWindow requires GTK; skip cleanly when no
            // display is available (e.g. headless CI). Where a display exists
            // this is a regression guard: build_main_window must host the header
            // bar inside an AdwToolbarView. Reintroducing set_titlebar() on the
            // AdwApplicationWindow would abort the process here instead.
            if adw::init().is_err() {
                eprintln!("skipping main_window test: libadwaita could not initialize");
                return;
            }

            let header = HeaderBar::new();
            let body = gtk::Box::new(Orientation::Vertical, 0);

            let window = build_main_window(&header, body.upcast_ref(), 720, 420);

            let content = window.content().expect("window content should be set");
            assert!(
                content.downcast_ref::<adw::ToolbarView>().is_some(),
                "header bar must be hosted in an AdwToolbarView, not via set_titlebar"
            );
        }
    }
}

#[cfg(feature = "gui")]
pub use enabled::run;

#[cfg(not(feature = "gui"))]
pub fn run<C: crate::nm::NmClient>(_client: C, _hidden: bool) -> crate::error::AppResult<()> {
    Err(crate::error::AppError::FeatureUnavailable(
        "GUI feature is disabled. Rebuild with `--features gui`.".to_string(),
    ))
}
