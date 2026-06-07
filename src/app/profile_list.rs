use crate::nm::WireguardProfile;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileListRow {
    pub name: String,
    pub uuid: String,
    pub is_active: bool,
    pub state_label: &'static str,
    pub eligible: bool,
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
    excluded_profile_ids: &std::collections::BTreeSet<String>,
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
            eligible: !excluded_profile_ids.contains(&profile.uuid),
        })
        .collect();

    rows.sort_by(|a, b| a.name.cmp(&b.name));
    rows
}

#[cfg(test)]
mod tests {
    use crate::nm::{ProfileState, WireguardProfile};

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
        // Opt-out model: excluding uuid-us leaves wg-eu eligible by default.
        let mut excluded = std::collections::BTreeSet::new();
        excluded.insert("uuid-us".to_string());

        let rows = build_rows(
            &[
                profile("wg-eu", "uuid-eu", ProfileState::Inactive),
                profile("wg-us", "uuid-us", ProfileState::Active),
            ],
            &excluded,
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
    fn treats_empty_exclusion_set_as_all_eligible() {
        let rows = build_rows(
            &[
                profile("wg-eu", "uuid-eu", ProfileState::Inactive),
                profile("wg-us", "uuid-us", ProfileState::Active),
            ],
            &std::collections::BTreeSet::new(),
        );

        assert!(rows.iter().all(|row| row.eligible));
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
}
