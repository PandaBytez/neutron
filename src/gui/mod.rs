#[cfg(feature = "gui")]
mod enabled {
    use std::cell::RefCell;
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
    use crate::nm::NmClient;

    pub fn run<C>(client: C) -> AppResult<()>
    where
        C: NmClient + Clone + Send + 'static,
    {
        let app = Application::builder()
            .application_id("com.example.wireguardmanager")
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
        C: NmClient + Clone + Send + 'static,
    {
        let header = HeaderBar::builder()
            .title_widget(&gtk::Label::new(Some("WireGuard Manager")))
            .build();

        let status = gtk::Label::new(None);
        status.set_wrap(true);
        status.set_xalign(0.0);

        let list = gtk::ListBox::new();
        list.add_css_class("boxed-list");

        let refresh = gtk::Button::with_label("Refresh");
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

        let container = gtk::Box::new(Orientation::Vertical, 12);
        container.set_margin_top(24);
        container.set_margin_bottom(24);
        container.set_margin_start(24);
        container.set_margin_end(24);
        container.append(&refresh);
        container.append(&status);
        container.append(&scroller);

        let window = ApplicationWindow::builder()
            .application(app)
            .title("WireGuard Manager")
            .default_width(720)
            .default_height(420)
            .content(&container)
            .build();
        window.set_titlebar(Some(&header));

        let monitor_child_for_close = monitor_child;
        window.connect_close_request(move |_| {
            if let Some(mut child) = monitor_child_for_close.borrow_mut().take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            glib::Propagation::Proceed
        });

        window.present();
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
            &app_cfg.eligible_profile_ids,
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
            &mut app_cfg.eligible_profile_ids,
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

        let details = gtk::Label::new(Some(&profile_list::format_cli_row(row)));
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

        let actions = gtk::Box::new(Orientation::Horizontal, 6);
        for action in profile_list::available_actions(row) {
            let label = match action {
                profile_list::RowAction::Connect => "Connect",
                profile_list::RowAction::Switch => "Switch",
                profile_list::RowAction::Disconnect => "Disconnect",
            };

            let button = gtk::Button::with_label(label);
            let client = client.clone();
            let row = row.clone();
            let list = list.clone();
            let status = status.clone();
            button.connect_clicked(move |button| {
                button.set_sensitive(false);
                status.set_label(&format!("Working on '{}'\u{2026}", row.name));

                let button = button.clone();
                let client = client.clone();
                let row = row.clone();
                let list = list.clone();
                let status = status.clone();
                glib::spawn_future_local(async move {
                    let task_client = client.clone();
                    let task_row = row.clone();
                    let outcome = gio::spawn_blocking(move || {
                        profile_list::execute_action(&task_client, &task_row, action)
                    })
                    .await;

                    button.set_sensitive(true);
                    match outcome {
                        Ok(Ok(())) => {
                            status.set_label(&format!("Action completed for '{}'.", row.name));
                            refresh_profile_list(&client, &list, &status);
                        }
                        Ok(Err(error)) => {
                            status.set_label(&format!("Action failed for '{}': {error}", row.name));
                        }
                        Err(_) => {
                            status.set_label(&format!(
                                "Action failed for '{}': background task panicked",
                                row.name
                            ));
                        }
                    }
                });
            });
            actions.append(&button);
        }

        container.append(&details);
        container.append(&eligibility_toggle);
        container.append(&actions);

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
        fn set_eligibility_updates_config() {
            let config_path = std::env::temp_dir().join(format!(
                "wireguard-manager-gui-eligibility-{}.json",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("time should move forward")
                    .as_nanos()
            ));
            config::save(&config_path, &AppConfig::default()).expect("config should save");

            let changed = set_eligibility_for_profile_with_path(&config_path, "uuid-1", true)
                .expect("eligibility update should succeed");
            assert!(changed);

            let loaded = config::load(&config_path).expect("config should load");
            assert_eq!(
                loaded.eligible_profile_ids,
                std::collections::BTreeSet::from(["uuid-1".to_string()])
            );
            let _ = std::fs::remove_file(config_path);
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
