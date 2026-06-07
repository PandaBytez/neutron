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

        let refresh = gtk::Button::with_label("Refresh");
        // Size the button to its label instead of stretching across the full
        // window width (a vertical box would otherwise fill the cross axis).
        refresh.set_halign(gtk::Align::Start);
        {
            let client = client.clone();
            let list = list.clone();
            let status = status.clone();
            refresh.connect_clicked(move |_| {
                refresh_profile_list(&client, &list, &status);
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
            let status = status.clone();
            let mut last_seen_event = 0_u64;
            glib::timeout_add_seconds_local(1, move || {
                let current = monitor_events.load(Ordering::Relaxed);
                if current != last_seen_event {
                    last_seen_event = current;
                    refresh_profile_list(&client, &list, &status);
                }
                glib::ControlFlow::Continue
            });
        }

        refresh_profile_list(&client, &list, &status);

        let scroller = gtk::ScrolledWindow::builder()
            .hexpand(true)
            .vexpand(true)
            .child(&list)
            .build();

        let kill_switch_row = build_kill_switch_row(app, &client, &status);
        let lockdown_row = build_lockdown_row(app, &client, &status);
        let import = build_import_button(&client, &list, &status);

        // Group the manual actions on one row so they read as a toolbar rather
        // than a stacked column of full-width buttons.
        let actions = gtk::Box::new(Orientation::Horizontal, 12);
        actions.append(&refresh);
        actions.append(&import);

        let container = gtk::Box::new(Orientation::Vertical, 12);
        container.set_margin_top(24);
        container.set_margin_bottom(24);
        container.set_margin_start(24);
        container.set_margin_end(24);
        container.append(&kill_switch_row);
        container.append(&lockdown_row);
        container.append(&actions);
        container.append(&status);
        container.append(&scroller);

        let (width, height) = load_window_size();
        let window = build_main_window(&header, &container, width, height);
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
        body: &gtk::Box,
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
    fn build_kill_switch_row<C>(app: &Application, client: &C, status: &gtk::Label) -> gtk::Box
    where
        C: NmClient + Clone + Send + 'static,
    {
        let label = gtk::Label::new(Some("Kill switch (all profiles)"));
        label.set_xalign(0.0);
        label.set_hexpand(true);

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
                status.set_label(&format!(
                    "{} kill switch for all profiles\u{2026}",
                    if requested { "Enabling" } else { "Disabling" }
                ));

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
                            status.set_label(&format!(
                                "Kill switch {} for all profiles. Applies on next connect.",
                                if requested { "enabled" } else { "disabled" }
                            ));
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

        let row = gtk::Box::new(Orientation::Horizontal, 12);
        row.append(&label);
        row.append(&toggle);
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
    fn build_lockdown_row<C>(app: &Application, client: &C, status: &gtk::Label) -> gtk::Box
    where
        C: NmClient + FirewallClient + Clone + Send + 'static,
    {
        let label = gtk::Label::new(Some("Lockdown (always-on firewall)"));
        label.set_xalign(0.0);
        label.set_hexpand(true);

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
                status.set_label(&format!(
                    "{} lockdown firewall\u{2026}",
                    if requested { "Enabling" } else { "Disabling" }
                ));

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
                            status.set_label(&format!(
                                "Lockdown firewall {}.",
                                if requested { "enabled" } else { "disabled" }
                            ));
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

        let row = gtk::Box::new(Orientation::Horizontal, 12);
        row.append(&label);
        row.append(&toggle);
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
    fn build_import_button<C>(client: &C, list: &gtk::ListBox, status: &gtk::Label) -> gtk::Button
    where
        C: NmClient + Clone + Send + 'static,
    {
        let button = gtk::Button::with_label("Import\u{2026}");
        button.set_halign(gtk::Align::Start);

        let client = client.clone();
        let list = list.clone();
        let status = status.clone();
        button.connect_clicked(move |button| {
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

            // Parent the modal on the live window so it centers correctly; the
            // button is realized by click time, so its root is the window.
            let parent = button.root().and_downcast::<gtk::Window>();

            let client = client.clone();
            let list = list.clone();
            let status = status.clone();
            dialog.open(parent.as_ref(), gio::Cancellable::NONE, move |result| {
                let file = match result {
                    Ok(file) => file,
                    // The user dismissed the chooser; nothing to import.
                    Err(_) => return,
                };
                let Some(path) = file.path() else {
                    status.set_label("Import failed: the selected file has no local path.");
                    return;
                };

                status.set_label(&format!("Importing '{}'\u{2026}", path.display()));
                let task_client = client.clone();
                let task_path = path.clone();
                let client = client.clone();
                let list = list.clone();
                let status = status.clone();
                glib::spawn_future_local(async move {
                    let outcome = gio::spawn_blocking(move || {
                        task_client.import_wireguard_profile(&task_path)
                    })
                    .await;
                    match outcome {
                        Ok(Ok(message)) => {
                            status.set_label(&message);
                            refresh_profile_list(&client, &list, &status);
                        }
                        Ok(Err(error)) => {
                            status.set_label(&format!("Import failed: {error}"));
                        }
                        Err(_) => {
                            status.set_label("Import failed: background task panicked.");
                        }
                    }
                });
            });
        });

        button
    }

    /// Reload the profile list. The blocking NetworkManager/config work runs on
    /// the Gio thread pool so the GTK main thread (and thus the UI) never blocks
    /// on `nmcli`. Widget creation happens back on the main thread once the data
    /// is available.
    fn refresh_profile_list<C>(client: &C, list: &gtk::ListBox, status: &gtk::Label)
    where
        C: NmClient + Clone + Send + 'static,
    {
        while let Some(child) = list.first_child() {
            list.remove(&child);
        }
        status.set_label("Loading profiles\u{2026}");

        let client_for_load = client.clone();
        let client_for_rows = client.clone();
        let list = list.clone();
        let status = status.clone();
        glib::spawn_future_local(async move {
            let outcome = gio::spawn_blocking(move || load_rows(&client_for_load)).await;
            match outcome {
                Ok(Ok(rows)) => {
                    status.set_label("Profiles loaded from NetworkManager.");
                    for row in rows {
                        let row_widget = build_profile_row(&client_for_rows, &row, &list, &status);
                        list.append(&row_widget);
                    }
                }
                Ok(Err(error)) => {
                    status.set_label(&format!("Failed to load profiles: {error}"));
                }
                Err(_) => {
                    status.set_label("Failed to load profiles: background task panicked.");
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

    fn build_profile_row<C>(
        client: &C,
        row: &profile_list::ProfileListRow,
        list: &gtk::ListBox,
        status: &gtk::Label,
    ) -> gtk::ListBoxRow
    where
        C: NmClient + Clone + Send + 'static,
    {
        let container = gtk::Box::new(Orientation::Horizontal, 12);
        // Inset the row content so fields don't butt up against the
        // `boxed-list` border drawn around the profile list.
        container.set_margin_top(8);
        container.set_margin_bottom(8);
        container.set_margin_start(12);
        container.set_margin_end(12);

        // Show only the profile name in the GUI row; state is conveyed by the
        // connection switch and eligibility by its own toggle. The richer
        // `format_cli_row` output remains for the `list` CLI command.
        let details = gtk::Label::new(Some(&row.name));
        details.set_xalign(0.0);
        details.set_hexpand(true);

        let eligibility_toggle = gtk::CheckButton::with_label("Startup eligible");
        eligibility_toggle.set_active(row.eligible);
        {
            let client = client.clone();
            let row = row.clone();
            let list = list.clone();
            let status = status.clone();
            eligibility_toggle.connect_toggled(move |toggle| {
                match set_eligibility_for_profile(&row.uuid, toggle.is_active()) {
                    Ok(true) => {
                        status.set_label(&format!("Updated eligibility for '{}'.", row.name));
                        refresh_profile_list(&client, &list, &status);
                    }
                    Ok(false) => {
                        status.set_label(&format!("No eligibility change for '{}'.", row.name));
                    }
                    Err(error) => {
                        status.set_label(&format!(
                            "Failed to update eligibility for '{}': {error}",
                            row.name
                        ));
                    }
                }
            });
        }

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
            let status = status.clone();
            let guard = Rc::new(Cell::new(false));
            connection_toggle.connect_state_set(move |toggle, requested| {
                // Ignore programmatic state changes (e.g. a revert) so they do
                // not re-trigger a connect/disconnect.
                if guard.get() {
                    return glib::Propagation::Proceed;
                }
                toggle.set_sensitive(false);
                status.set_label(&format!(
                    "{} '{}'\u{2026}",
                    if requested {
                        "Connecting"
                    } else {
                        "Disconnecting"
                    },
                    row.name
                ));

                let client = client.clone();
                let row = row.clone();
                let list = list.clone();
                let status = status.clone();
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
                    match outcome {
                        Ok(Ok(())) => {
                            status.set_label(&format!(
                                "{} '{}'.",
                                if requested {
                                    "Connected"
                                } else {
                                    "Disconnected"
                                },
                                row.name
                            ));
                            refresh_profile_list(&client, &list, &status);
                        }
                        Ok(Err(error)) => {
                            status.set_label(&format!("Action failed for '{}': {error}", row.name));
                            revert_switch(&toggle, &guard, !requested);
                        }
                        Err(_) => {
                            status.set_label(&format!(
                                "Action failed for '{}': background task panicked",
                                row.name
                            ));
                            revert_switch(&toggle, &guard, !requested);
                        }
                    }
                });

                glib::Propagation::Proceed
            });
        }

        container.append(&details);
        container.append(&eligibility_toggle);
        container.append(&connection_toggle);

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
