use std::collections::BTreeSet;

pub fn set_profile_eligible(
    eligible_profile_ids: &mut BTreeSet<String>,
    profile_id: &str,
    eligible: bool,
) -> bool {
    if eligible {
        eligible_profile_ids.insert(profile_id.to_string())
    } else {
        eligible_profile_ids.remove(profile_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_profile_when_enabling() {
        let mut ids = BTreeSet::from(["uuid-1".to_string()]);

        let changed = set_profile_eligible(&mut ids, "uuid-2", true);

        assert!(changed);
        assert_eq!(
            ids,
            BTreeSet::from(["uuid-1".to_string(), "uuid-2".to_string()])
        );
    }

    #[test]
    fn does_not_duplicate_profile_when_enabling_again() {
        let mut ids = BTreeSet::from(["uuid-1".to_string()]);

        let changed = set_profile_eligible(&mut ids, "uuid-1", true);

        assert!(!changed);
        assert_eq!(ids, BTreeSet::from(["uuid-1".to_string()]));
    }

    #[test]
    fn removes_profile_when_disabling() {
        let mut ids = BTreeSet::from(["uuid-1".to_string(), "uuid-2".to_string()]);

        let changed = set_profile_eligible(&mut ids, "uuid-1", false);

        assert!(changed);
        assert_eq!(ids, BTreeSet::from(["uuid-2".to_string()]));
    }

    #[test]
    fn no_change_when_disabling_missing_profile() {
        let mut ids = BTreeSet::from(["uuid-2".to_string()]);

        let changed = set_profile_eligible(&mut ids, "uuid-1", false);

        assert!(!changed);
        assert_eq!(ids, BTreeSet::from(["uuid-2".to_string()]));
    }
}
