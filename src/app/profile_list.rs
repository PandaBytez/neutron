use crate::error::AppResult;
use crate::nm::{NmClient, WireguardProfile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileListRow {
    pub name: String,
    pub uuid: String,
    pub is_active: bool,
    pub state_label: &'static str,
    pub eligible: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowAction {
    Connect,
    Switch,
    Disconnect,
}

pub fn execute_action<C: NmClient>(
    client: &C,
    row: &ProfileListRow,
    action: RowAction,
) -> AppResult<()> {
    match action {
        RowAction::Connect => client.connect(&row.uuid),
        RowAction::Switch => client.switch_to(&row.uuid),
        RowAction::Disconnect => client.disconnect_active(),
    }
}

pub fn available_actions(row: &ProfileListRow) -> Vec<RowAction> {
    if row.is_active {
        vec![RowAction::Disconnect]
    } else {
        vec![RowAction::Connect, RowAction::Switch]
    }
}

pub fn format_cli_row(row: &ProfileListRow) -> String {
    let eligible = if row.eligible {
        "eligible"
    } else {
        "not-eligible"
    };
    format!("{} [{}] {}", row.name, row.state_label, eligible)
}

pub fn build_rows(
    profiles: &[WireguardProfile],
    eligible_profile_ids: &std::collections::BTreeSet<String>,
) -> Vec<ProfileListRow> {
    let mut rows: Vec<_> = profiles
        .iter()
        .map(|profile| ProfileListRow {
            name: profile.name.clone(),
            uuid: profile.uuid.clone(),
            is_active: profile.is_active(),
            state_label: if profile.is_active() {
                "active"
            } else {
                "inactive"
            },
            eligible: eligible_profile_ids.contains(&profile.uuid),
        })
        .collect();

    rows.sort_by(|a, b| a.name.cmp(&b.name));
    rows
}

#[cfg(test)]
mod tests {
    use crate::nm::{ProfileState, WireguardProfile};
    use crate::testing::MockNmClient;

    use super::*;

    fn profile(name: &str, uuid: &str, state: ProfileState) -> WireguardProfile {
        WireguardProfile {
            name: name.to_string(),
            uuid: uuid.to_string(),
            state,
        }
    }

    #[test]
    fn builds_rows_with_eligible_and_state_labels() {
        let mut eligible = std::collections::BTreeSet::new();
        eligible.insert("uuid-eu".to_string());

        let rows = build_rows(
            &[
                profile("wg-eu", "uuid-eu", ProfileState::Inactive),
                profile("wg-us", "uuid-us", ProfileState::Active),
            ],
            &eligible,
        );

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "wg-eu");
        assert_eq!(rows[0].state_label, "inactive");
        assert!(rows[0].eligible);
        assert_eq!(rows[1].name, "wg-us");
        assert_eq!(rows[1].state_label, "active");
        assert!(!rows[1].eligible);
    }

    #[test]
    fn sorts_rows_by_name() {
        let rows = build_rows(
            &[
                profile("wg-z", "uuid-z", ProfileState::Inactive),
                profile("wg-a", "uuid-a", ProfileState::Inactive),
            ],
            &std::collections::BTreeSet::new(),
        );

        assert_eq!(rows[0].name, "wg-a");
        assert_eq!(rows[1].name, "wg-z");
    }

    #[test]
    fn formats_cli_row_output() {
        let row = ProfileListRow {
            name: "wg-us".to_string(),
            uuid: "uuid-1".to_string(),
            is_active: true,
            state_label: "active",
            eligible: true,
        };

        let line = format_cli_row(&row);

        assert_eq!(line, "wg-us [active] eligible");
    }

    #[test]
    fn action_availability_for_active_row() {
        let row = ProfileListRow {
            name: "wg-us".to_string(),
            uuid: "uuid-1".to_string(),
            is_active: true,
            state_label: "active",
            eligible: true,
        };

        let actions = available_actions(&row);

        assert_eq!(actions, vec![RowAction::Disconnect]);
    }

    #[test]
    fn action_availability_for_inactive_row() {
        let row = ProfileListRow {
            name: "wg-eu".to_string(),
            uuid: "uuid-2".to_string(),
            is_active: false,
            state_label: "inactive",
            eligible: false,
        };

        let actions = available_actions(&row);

        assert_eq!(actions, vec![RowAction::Connect, RowAction::Switch]);
    }

    #[test]
    fn execute_action_maps_connect_to_uuid() {
        let row = ProfileListRow {
            name: "wg-us".to_string(),
            uuid: "uuid-1".to_string(),
            is_active: false,
            state_label: "inactive",
            eligible: false,
        };
        let client = MockNmClient::default();

        execute_action(&client, &row, RowAction::Connect).expect("connect should succeed");

        assert_eq!(client.calls(), vec!["connect:uuid-1".to_string()]);
    }

    #[test]
    fn execute_action_maps_switch_to_name() {
        let row = ProfileListRow {
            name: "wg-us".to_string(),
            uuid: "uuid-1".to_string(),
            is_active: false,
            state_label: "inactive",
            eligible: false,
        };
        let client = MockNmClient::default();

        execute_action(&client, &row, RowAction::Switch).expect("switch should succeed");

        assert_eq!(client.calls(), vec!["switch:uuid-1".to_string()]);
    }

    #[test]
    fn execute_action_maps_disconnect_without_target() {
        let row = ProfileListRow {
            name: "wg-us".to_string(),
            uuid: "uuid-1".to_string(),
            is_active: true,
            state_label: "active",
            eligible: true,
        };
        let client = MockNmClient::default();

        execute_action(&client, &row, RowAction::Disconnect).expect("disconnect should succeed");

        assert_eq!(client.calls(), vec!["disconnect".to_string()]);
    }
}
