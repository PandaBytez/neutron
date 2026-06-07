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
    use gtk::gio;
    use gtk::glib;

    use crate::app::eligibility;
    use crate::app::profile_list;
    use crate::app::refresh_sync;
    use crate::config;
    use crate::error::AppResult;
    use crate::firewall::FirewallClient;
    use crate::nm::NmClient;

    #[derive(Clone)]
    struct StatusIndicators {
        log: gtk::Label,
        vpn_icon: gtk::Image,
        vpn_label: gtk::Label,
        /// Collapsible "Startup auto-connect" row in the Settings group. Its
        /// child switches choose which profiles join the boot-time random pool,
        /// keeping that configuration concern out of the operational rows.
        eligibility: adw::ExpanderRow,
        /// The eligibility switches currently shown inside `eligibility`, tracked
        /// so they can be cleared and rebuilt when the profile set changes
        /// (`adw::ExpanderRow` offers no clear-all). Shared, so toggle handlers
        /// can recompute the summary subtitle.
        eligibility_rows: Rc<RefCell<Vec<adw::SwitchRow>>>,
    }

    pub fn run<C>(client: C) -> AppResult<()>
    where
        C: NmClient + FirewallClient + Clone + Send + 'static,
    {
        let app = Application::builder()
            .application_id("io.gitlab.zento_vpn_manager.zento")
            .build();

        app.connect_activate(move |app| build_ui(app, client.clone()));

        // Launch GTK with only the program name. Forwarding the CLI subcommand
        // (e.g. `gui`) would make GApplication treat it as a file argument and
        // refuse to start with "This application can not open files".
        let program = std::env::args().next().unwrap_or_default();
        app.run_with_args(&[program]);
        Ok(())
    }

    fn build_ui<C>(app: &Application, client: C)
    where
        C: NmClient + FirewallClient + Clone + Send + 'static,
    {
        let header = HeaderBar::builder()
            .title_widget(&gtk::Label::new(Some("Zento")))
            .build();

        let status = gtk::Label::new(None);
        status.set_wrap(true);
        status.set_xalign(0.0);

        let list = gtk::ListBox::new();
        list.add_css_class("boxed-list");

        list.connect_row_activated(move |_, row_widget| {
            if let Some(child_widget) = row_widget.child() {
                if let Some(container_box) = child_widget.downcast_ref::<gtk::Box>() {
                    if let Some(info_box_widget) = container_box.first_child().and_then(|h| h.next_sibling()) {
                        let visible = info_box_widget.is_visible();
                        info_box_widget.set_visible(!visible);
                    }
                }
            }
        });

        let vpn_status_box = gtk::Box::new(Orientation::Horizontal, 8);
        vpn_status_box.set_halign(gtk::Align::Center);
        vpn_status_box.set_margin_bottom(16);

        let vpn_status_icon = gtk::Image::builder().pixel_size(20).build();
        let vpn_status_label = gtk::Label::builder().use_markup(true).build();
        update_vpn_status_widget(false, &vpn_status_icon, &vpn_status_label);

        vpn_status_box.append(&vpn_status_icon);
        vpn_status_box.append(&vpn_status_label);

        let eligibility_expander = adw::ExpanderRow::builder()
            .title("Startup auto-connect")
            .subtitle("Choose profiles eligible for random selection at boot")
            .build();

        let indicators = StatusIndicators {
            log: status.clone(),
            vpn_icon: vpn_status_icon.clone(),
            vpn_label: vpn_status_label.clone(),
            eligibility: eligibility_expander.clone(),
            eligibility_rows: Rc::new(RefCell::new(Vec::new())),
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

        let scroller = gtk::ScrolledWindow::builder()
            .hexpand(true)
            // Size the list to its content rather than stretching to the bottom
            // of the window: `propagate_natural_height` makes the scroller
            // request the list's natural height (capped by `max_content_height`,
            // beyond which it scrolls), and leaving `vexpand` off keeps any
            // leftover space below the list instead of inflating it. A short
            // list now ends right after the last profile; a constrained window
            // still shrinks the scroller and scrolls, so nothing is clipped.
            .vexpand(false)
            .propagate_natural_height(true)
            .max_content_height(PROFILE_LIST_MAX_HEIGHT)
            .child(&list)
            .build();

        let kill_switch_row = build_kill_switch_row(app, &client, &status);
        let lockdown_row = build_lockdown_row(app, &client, &status);
        let import = build_import_button(&client, &list, &indicators);

        let container = gtk::Box::new(Orientation::Vertical, 12);
        container.set_margin_top(24);
        container.set_margin_bottom(24);
        container.set_margin_start(24);
        container.set_margin_end(24);

        let logo = if std::path::Path::new(
            "/app/share/icons/hicolor/scalable/apps/io.gitlab.zento_vpn_manager.zento.svg",
        )
        .exists()
        {
            gtk::Image::from_file(
                "/app/share/icons/hicolor/scalable/apps/io.gitlab.zento_vpn_manager.zento.svg",
            )
        } else if std::path::Path::new("flatpak/io.gitlab.zento_vpn_manager.zento.svg").exists() {
            gtk::Image::from_file("flatpak/io.gitlab.zento_vpn_manager.zento.svg")
        } else {
            gtk::Image::from_icon_name("io.gitlab.zento_vpn_manager.zento")
        };
        logo.set_pixel_size(96);
        logo.set_halign(gtk::Align::Center);
        logo.set_margin_bottom(12);
        container.append(&logo);
        container.append(&vpn_status_box);

        // Settings Section
        let settings_group = adw::PreferencesGroup::builder().title("Settings").build();
        settings_group.add(&kill_switch_row);
        settings_group.add(&lockdown_row);
        settings_group.add(&eligibility_expander);

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
        container.append(&scroller);

        let clamp = adw::Clamp::builder()
            .maximum_size(500)
            .child(&container)
            .build();

        let (width, height) = load_window_size();
        let window = build_main_window(&header, &clamp.upcast::<gtk::Widget>(), width, height);
        window.set_application(Some(app));

        let monitor_child_for_close = monitor_child;
        window.connect_close_request(move |window| {
            if let Some(mut child) = monitor_child_for_close.borrow_mut().take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            // Remember the user's last window size for the next launch.
            save_window_size(window);
            glib::Propagation::Proceed
        });

        window.present();
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
            .title("Zento")
            .default_width(width)
            .default_height(height)
            .content(&toolbar_view)
            .build()
    }

    /// Width used the first time the app runs, before a size is remembered.
    const DEFAULT_WINDOW_WIDTH: i32 = 720;
    /// Height used the first time the app runs, before a size is remembered.
    const DEFAULT_WINDOW_HEIGHT: i32 = 420;

    /// Upper bound (px) on the profile list's natural height. The list grows to
    /// fit its rows up to this cap; past it the list scrolls instead of pushing
    /// the rest of the window off-screen.
    const PROFILE_LIST_MAX_HEIGHT: i32 = 360;

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

    /// Build the global kill-switch row: a single switch that applies (or
    /// removes) the NetworkManager kill-switch routing policy across *every*
    /// WireGuard profile at once. The blocking `nmcli` work runs off the GTK
    /// main thread; the switch is disabled while it runs and reverts on failure.
    fn build_kill_switch_row<C>(
        app: &Application,
        client: &C,
        status: &gtk::Label,
    ) -> adw::ActionRow
    where
        C: NmClient + Clone + Send + 'static,
    {
        let toggle = gtk::Switch::new();
        toggle.set_valign(gtk::Align::Center);
        toggle.set_active(load_kill_switch_enabled());

        let guard = Rc::new(Cell::new(false));
        {
            let app = app.clone();
            let client = client.clone();
            let status = status.clone();
            toggle.connect_state_set(move |toggle, requested| {
                // Ignore programmatic state changes (e.g. a revert) so they do
                // not re-trigger the NetworkManager work.
                if guard.get() {
                    return glib::Propagation::Proceed;
                }
                toggle.set_sensitive(false);

                let app = app.clone();
                let client = client.clone();
                let status = status.clone();
                let toggle = toggle.clone();
                let guard = guard.clone();
                glib::spawn_future_local(async move {
                    let task_client = client.clone();
                    let outcome = gio::spawn_blocking(move || {
                        apply_global_kill_switch(&task_client, requested)
                    })
                    .await;

                    toggle.set_sensitive(true);
                    match outcome {
                        Ok(Ok(())) => {
                            if requested {
                                notify_kill_switch_enabled(&app);
                            }
                        }
                        Ok(Err(error)) => {
                            status.set_label(&format!("Failed to update kill switch: {error}"));
                            revert_switch(&toggle, &guard, !requested);
                        }
                        Err(_) => {
                            status.set_label(
                                "Failed to update kill switch: background task panicked.",
                            );
                            revert_switch(&toggle, &guard, !requested);
                        }
                    }
                });

                glib::Propagation::Proceed
            });
        }

        let row = adw::ActionRow::builder()
            .title("Kill Switch")
            .subtitle("Drop all traffic if any WireGuard profile fails to connect")
            .build();
        row.add_suffix(&toggle);
        row.set_activatable_widget(Some(&toggle));
        row
    }

    /// Restore a switch to `active` without re-triggering its async handler.
    fn revert_switch(toggle: &gtk::Switch, guard: &Rc<Cell<bool>>, active: bool) {
        guard.set(true);
        toggle.set_active(active);
        guard.set(false);
    }

    /// Apply the global kill switch to every WireGuard profile and persist the
    /// new state to config. Runs on the Gio thread pool (off the GTK main
    /// thread); errors are surfaced as strings for the status label.
    ///
    /// Delegates to [`crate::app::set_global_kill_switch`] so the
    /// apply-before-persist ordering lives in exactly one place.
    fn apply_global_kill_switch<C: NmClient>(client: &C, enable: bool) -> Result<(), String> {
        let path = config::default_config_path().map_err(|error| error.to_string())?;
        crate::app::set_global_kill_switch(client, &path, enable).map_err(|error| error.to_string())
    }

    /// Read the remembered global kill-switch state from config (default off).
    fn load_kill_switch_enabled() -> bool {
        config::default_config_path()
            .and_then(|path| config::load(&path))
            .map(|app_cfg| app_cfg.kill_switch_enabled)
            .unwrap_or(false)
    }

    /// Send a desktop notification telling the user the kill switch is active.
    fn notify_kill_switch_enabled(app: &Application) {
        let notification = gio::Notification::new("Kill switch enabled");
        notification.set_body(Some(
            "All WireGuard profiles now drop traffic if the tunnel fails. Applies on next connect.",
        ));
        app.send_notification(Some("zento-kill-switch"), &notification);
    }

    /// Build the global lockdown row: a switch that installs (or removes) the
    /// always-on firewall blocking every non-VPN packet. Mirrors the kill-switch
    /// row, but the blocking `pkexec firewall-cmd` work (which may prompt for a
    /// password) runs off the GTK main thread; the switch is disabled while it
    /// runs and reverts on failure.
    fn build_lockdown_row<C>(app: &Application, client: &C, status: &gtk::Label) -> adw::ActionRow
    where
        C: NmClient + FirewallClient + Clone + Send + 'static,
    {
        let toggle = gtk::Switch::new();
        toggle.set_valign(gtk::Align::Center);
        toggle.set_active(load_lockdown_enabled());

        let guard = Rc::new(Cell::new(false));
        {
            let app = app.clone();
            let client = client.clone();
            let status = status.clone();
            toggle.connect_state_set(move |toggle, requested| {
                // Ignore programmatic state changes (e.g. a revert) so they do
                // not re-trigger the firewall work.
                if guard.get() {
                    return glib::Propagation::Proceed;
                }
                toggle.set_sensitive(false);

                let app = app.clone();
                let client = client.clone();
                let status = status.clone();
                let toggle = toggle.clone();
                let guard = guard.clone();
                glib::spawn_future_local(async move {
                    let task_client = client.clone();
                    let outcome =
                        gio::spawn_blocking(move || apply_global_lockdown(&task_client, requested))
                            .await;

                    toggle.set_sensitive(true);
                    match outcome {
                        Ok(Ok(())) => {
                            if requested {
                                notify_lockdown_enabled(&app);
                            }
                        }
                        Ok(Err(error)) => {
                            status.set_label(&format!("Failed to update lockdown: {error}"));
                            revert_switch(&toggle, &guard, !requested);
                        }
                        Err(_) => {
                            status
                                .set_label("Failed to update lockdown: background task panicked.");
                            revert_switch(&toggle, &guard, !requested);
                        }
                    }
                });

                glib::Propagation::Proceed
            });
        }

        let row = adw::ActionRow::builder()
            .title("Lockdown Mode")
            .subtitle("Strictly block non-VPN packets via system firewall (requires root)")
            .build();
        row.add_suffix(&toggle);
        row.set_activatable_widget(Some(&toggle));
        row
    }

    /// Apply the always-on lockdown firewall and persist the new state to config.
    /// Runs on the Gio thread pool (off the GTK main thread); errors are
    /// surfaced as strings for the status label.
    ///
    /// Delegates to [`crate::app::set_global_lockdown`] so the
    /// apply-before-persist ordering lives in exactly one place.
    fn apply_global_lockdown<C: NmClient + FirewallClient>(
        client: &C,
        enable: bool,
    ) -> Result<(), String> {
        let path = config::default_config_path().map_err(|error| error.to_string())?;
        crate::app::set_global_lockdown(client, &path, enable).map_err(|error| error.to_string())
    }

    /// Read the remembered global lockdown state from config (default off).
    fn load_lockdown_enabled() -> bool {
        config::default_config_path()
            .and_then(|path| config::load(&path))
            .map(|app_cfg| app_cfg.lockdown_enabled)
            .unwrap_or(false)
    }

    /// Send a desktop notification telling the user lockdown is active.
    fn notify_lockdown_enabled(app: &Application) {
        let notification = gio::Notification::new("Lockdown enabled");
        notification.set_body(Some(
            "All traffic is now blocked except the WireGuard tunnel, its handshake, and DNS \u{2014} even when no VPN is connected.",
        ));
        app.send_notification(Some("zento-lockdown"), &notification);
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
        C: NmClient + Clone + Send + 'static,
    {
        let button = gtk::Button::with_label("Import\u{2026}");
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
    /// file-import row. Mullvad is listed but inert until its flow lands.
    fn show_provider_chooser<C>(
        parent: Option<&gtk::Window>,
        client: &C,
        list: &gtk::ListBox,
        indicators: &StatusIndicators,
    ) where
        C: NmClient + Clone + Send + 'static,
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

        let proton_row = provider_chooser_row(
            "ProtonVPN",
            "Download configurations from your Proton account",
            true,
        );
        {
            let window = window.downgrade();
            let parent = parent.cloned();
            let client = client.clone();
            let list = list.clone();
            let indicators = indicators.clone();
            proton_row.connect_activated(move |_| {
                if let Some(window) = window.upgrade() {
                    window.close();
                }
                show_proton_import_dialog(parent.as_ref(), &client, &list, &indicators);
            });
        }
        providers.append(&proton_row);

        // Listed for discoverability but kept inert until the Mullvad flow lands.
        let mullvad_row = provider_chooser_row("MullvadVPN", "Coming soon", false);
        mullvad_row.set_sensitive(false);
        providers.append(&mullvad_row);

        let manual_row =
            provider_chooser_row("Manual import", "Import a WireGuard .conf file", true);
        {
            let window = window.downgrade();
            let parent = parent.cloned();
            let client = client.clone();
            let list = list.clone();
            let indicators = indicators.clone();
            manual_row.connect_activated(move |_| {
                if let Some(window) = window.upgrade() {
                    window.close();
                }
                open_manual_import(parent.as_ref(), &client, &list, &indicators);
            });
        }
        providers.append(&manual_row);

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

    /// ProtonVPN flow: explain how to fetch a WireGuard config from the account
    /// downloads page (opened via the link), then reuse the manual file picker
    /// to import the downloaded `.conf` file(s).
    fn show_proton_import_dialog<C>(
        parent: Option<&gtk::Window>,
        client: &C,
        list: &gtk::ListBox,
        indicators: &StatusIndicators,
    ) where
        C: NmClient + Clone + Send + 'static,
    {
        let dialog = adw::MessageDialog::new(parent, Some("Import from ProtonVPN"), None);

        let body = gtk::Label::builder()
            .use_markup(true)
            .wrap(true)
            .xalign(0.0)
            .width_request(440)
            .max_width_chars(60)
            .label(
                "To add a ProtonVPN profile:\n\n\
                 1. Open the WireGuard downloads page and sign in. \
                 <a href=\"https://account.protonvpn.com/downloads#wireguard-configuration\">Downloads page</a>\n\n\
                 2. Create and download a configuration for each server you want. \
                 <a href=\"https://protonvpn.com/support/wireguard-configurations\">Configuration guide</a>\n\n\
                 3. Choose the downloaded <tt>.conf</tt> file(s) below to import them.",
            )
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

    /// Open the multi-file chooser and import every selected WireGuard config,
    /// aggregating per-file failures so one bad file doesn't abort the batch.
    /// Shared by the "Manual import" option and the provider flows.
    fn open_manual_import<C>(
        parent: Option<&gtk::Window>,
        client: &C,
        list: &gtk::ListBox,
        indicators: &StatusIndicators,
    ) where
        C: NmClient + Clone + Send + 'static,
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
                let outcome = gio::spawn_blocking(move || {
                    let mut errors = Vec::new();
                    for path in &paths {
                        if let Err(error) = task_client.import_wireguard_profile(path) {
                            errors.push(format!("{}: {error}", path.display()));
                        }
                    }
                    errors
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
                    Err(_) => {
                        show_error_dialog(
                            dialog_parent.as_ref(),
                            "Import failed: background task panicked.",
                        );
                    }
                }
            });
        });
    }

    fn update_vpn_status_widget(connected: bool, icon: &gtk::Image, label: &gtk::Label) {
        if connected {
            icon.set_icon_name(Some("emblem-ok-symbolic"));
            icon.add_css_class("success");
            icon.remove_css_class("error");
            label.set_markup(
                "<span size='large' weight='bold' foreground='#2ec27e'>Connected</span>",
            );
        } else {
            icon.set_icon_name(Some("window-close-symbolic"));
            icon.add_css_class("error");
            icon.remove_css_class("success");
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

    /// Reload the profile list. The blocking NetworkManager/config work runs on
    /// the Gio thread pool so the GTK main thread (and thus the UI) never blocks
    /// on `nmcli`. Widget creation happens back on the main thread once the data
    /// is available.
    fn refresh_profile_list<C>(client: &C, list: &gtk::ListBox, indicators: &StatusIndicators)
    where
        C: NmClient + Clone + Send + 'static,
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
            let outcome = gio::spawn_blocking(move || load_rows(&client_for_load)).await;
            match outcome {
                Ok(Ok(rows)) => {
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
                    let any_active = rows.iter().any(|r| r.is_active);
                    update_vpn_status_widget(
                        any_active,
                        &indicators.vpn_icon,
                        &indicators.vpn_label,
                    );
                    while let Some(child) = list.first_child() {
                        list.remove(&child);
                    }
                    for row in rows {
                        let row_widget =
                            build_profile_row(&client_for_rows, &row, &list, &indicators);
                        list.append(&row_widget);
                    }
                }
                Ok(Err(error)) => {
                    indicators
                        .log
                        .set_label(&format!("Failed to load profiles: {error}"));
                }
                Err(_) => {
                    indicators
                        .log
                        .set_label("Failed to load profiles: background task panicked.");
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
        // Nothing to choose from when there are no profiles; disable the toggle
        // so the empty expander can't be opened.
        indicators
            .eligibility
            .set_enable_expansion(!rows.is_empty());
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
                    .set_label(&format!("{verb} startup auto-connect for '{name}'."));
            }
            Err(error) => {
                indicators.log.set_label(&format!(
                    "Failed to update startup eligibility for '{name}': {error}"
                ));
            }
        }
        update_eligibility_subtitle(indicators);
    }

    /// Summarise how many profiles are eligible for boot-time random selection
    /// in the expander subtitle, reading the live switch states.
    fn update_eligibility_subtitle(indicators: &StatusIndicators) {
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

    fn build_profile_row<C>(
        client: &C,
        row: &profile_list::ProfileListRow,
        list: &gtk::ListBox,
        indicators: &StatusIndicators,
    ) -> gtk::ListBoxRow
    where
        C: NmClient + Clone + Send + 'static,
    {
        let header_box = gtk::Box::new(Orientation::Horizontal, 12);
        // Inset the row content so fields don't butt up against the
        // `boxed-list` border drawn around the profile list.
        header_box.set_margin_top(8);
        header_box.set_margin_bottom(8);
        header_box.set_margin_start(12);
        header_box.set_margin_end(12);

        // Show only the profile name in the GUI row; connection state is conveyed
        // by the switch. Startup eligibility now lives in the Settings expander,
        // keeping these rows operational. The richer `format_cli_row` output
        // remains for the `list` CLI command.
        let details = gtk::Label::new(Some(&row.name));
        details.set_xalign(0.0);
        details.set_hexpand(true);

        // A single connection switch replaces the old Connect/Switch/Disconnect
        // buttons: flipping it on switches to this profile (deactivating any
        // other active tunnel), flipping it off disconnects the active tunnel.
        // The blocking `nmcli` work runs off the GTK main thread; the switch is
        // disabled while it runs and reverts to its previous position on failure.
        let connection_toggle = gtk::Switch::new();
        connection_toggle.set_valign(gtk::Align::Center);
        connection_toggle.set_active(row.is_active);
        {
            let client = client.clone();
            let row = row.clone();
            let list = list.clone();
            let indicators = indicators.clone();
            let guard = Rc::new(Cell::new(false));
            connection_toggle.connect_state_set(move |toggle, requested| {
                // Ignore programmatic state changes (e.g. a revert) so they do
                // not re-trigger a connect/disconnect.
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
                    let outcome = gio::spawn_blocking(move || {
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
                        Ok(Ok(())) => {
                            refresh_profile_list(&client, &list, &indicators);
                        }
                        Ok(Err(error)) => {
                            show_error_dialog(
                                parent.as_ref(),
                                &format!("Action failed for '{}': {error}", row.name),
                            );
                            revert_switch(&toggle, &guard, !requested);
                        }
                        Err(_) => {
                            show_error_dialog(
                                parent.as_ref(),
                                &format!(
                                    "Action failed for '{}': background task panicked",
                                    row.name
                                ),
                            );
                            revert_switch(&toggle, &guard, !requested);
                        }
                    }
                });

                glib::Propagation::Proceed
            });
        }

        header_box.append(&details);

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
        let remove_button = gtk::Button::builder()
            .icon_name("user-trash-symbolic")
            .css_classes(vec!["flat".to_string()])
            .valign(gtk::Align::Center)
            .tooltip_text("Remove profile")
            .build();
        {
            let client = client.clone();
            let row = row.clone();
            let list = list.clone();
            let indicators = indicators.clone();
            remove_button.connect_clicked(move |btn| {
                let parent = btn.root().and_downcast::<gtk::Window>();
                // Deleting a NetworkManager profile is destructive and
                // irreversible, so confirm before doing it.
                let confirm = adw::MessageDialog::new(
                    parent.as_ref(),
                    Some("Remove profile?"),
                    Some(&format!(
                        "This permanently deletes '{}' from NetworkManager. \
                         This cannot be undone.",
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
                        let outcome =
                            gio::spawn_blocking(move || task_client.delete_profile(&task_uuid))
                                .await;
                        match outcome {
                            Ok(Ok(())) => {
                                refresh_profile_list(&client, &list, &indicators);
                            }
                            Ok(Err(error)) => {
                                show_error_dialog(
                                    parent.as_ref(),
                                    &format!("Failed to remove '{}': {error}", row.name),
                                );
                            }
                            Err(_) => {
                                show_error_dialog(
                                    parent.as_ref(),
                                    &format!(
                                        "Failed to remove '{}': background task panicked",
                                        row.name
                                    ),
                                );
                            }
                        }
                    });
                });
                confirm.present();
            });
        }

        header_box.append(&connection_toggle);
        header_box.append(&settings_button);
        header_box.append(&remove_button);

        let container = gtk::Box::new(Orientation::Vertical, 0);
        container.append(&header_box);

        if let Some(ref custom) = row.custom_info {
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
            container.append(&info_box);
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

            let config_path = std::env::temp_dir().join(format!(
                "wireguard-manager-gui-test-fail-{}.json",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("time should move forward")
                    .as_nanos()
            ));
            config::save(&config_path, &AppConfig::default()).expect("config should save");

            let result = load_rows_with_path(&client, &config_path);

            assert!(result.is_err());
            let _ = std::fs::remove_file(config_path);
        }

        #[test]
        fn load_rows_maps_profiles() {
            let client = MockNmClient::new(vec![WireguardProfile {
                name: "wg-us".to_string(),
                uuid: "uuid-1".to_string(),
                state: ProfileState::Inactive,
            }]);

            let config_path = std::env::temp_dir().join(format!(
                "wireguard-manager-gui-test-{}.json",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("time should move forward")
                    .as_nanos()
            ));
            config::save(&config_path, &AppConfig::default()).expect("config should save");

            let result = load_rows_with_path(&client, &config_path);

            assert!(result.is_ok());
            let _ = std::fs::remove_file(config_path);
        }

        #[test]
        fn set_eligibility_excludes_and_restores_profile() {
            let config_path = std::env::temp_dir().join(format!(
                "wireguard-manager-gui-eligibility-{}.json",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("time should move forward")
                    .as_nanos()
            ));
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

            let _ = std::fs::remove_file(config_path);
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

            let window = build_main_window(&header, &body, 720, 420);

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
pub fn run<C: crate::nm::NmClient>(_client: C) -> crate::error::AppResult<()> {
    Err(crate::error::AppError::FeatureUnavailable(
        "GUI feature is disabled. Rebuild with `--features gui`.".to_string(),
    ))
}
