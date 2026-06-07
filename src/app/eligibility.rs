use std::collections::BTreeSet;

/// Update a profile's startup eligibility in the opt-out exclusion set.
///
/// Callers still think in terms of "eligible": passing `eligible = true` makes
/// the profile eligible by *removing* it from the exclusion set, while
/// `eligible = false` excludes it by *inserting* it. Returns whether the set
/// changed.
pub fn set_profile_eligible(
    excluded_profile_ids: &mut BTreeSet<String>,
    profile_id: &str,
    eligible: bool,
) -> bool {
    if eligible {
        excluded_profile_ids.remove(profile_id)
    } else {
        excluded_profile_ids.insert(profile_id.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_profile_when_disabling() {
        let mut excluded = BTreeSet::from(["uuid-1".to_string()]);

        let changed = set_profile_eligible(&mut excluded, "uuid-2", false);

        assert!(changed);
        assert_eq!(
            excluded,
            BTreeSet::from(["uuid-1".to_string(), "uuid-2".to_string()])
        );
    }

    #[test]
    fn does_not_duplicate_exclusion_when_disabling_again() {
        let mut excluded = BTreeSet::from(["uuid-1".to_string()]);

        let changed = set_profile_eligible(&mut excluded, "uuid-1", false);

        assert!(!changed);
        assert_eq!(excluded, BTreeSet::from(["uuid-1".to_string()]));
    }

    #[test]
    fn removes_exclusion_when_enabling() {
        let mut excluded = BTreeSet::from(["uuid-1".to_string(), "uuid-2".to_string()]);

        let changed = set_profile_eligible(&mut excluded, "uuid-1", true);

        assert!(changed);
        assert_eq!(excluded, BTreeSet::from(["uuid-2".to_string()]));
    }

    #[test]
    fn no_change_when_enabling_already_eligible_profile() {
        let mut excluded = BTreeSet::from(["uuid-2".to_string()]);

        let changed = set_profile_eligible(&mut excluded, "uuid-1", true);

        assert!(!changed);
        assert_eq!(excluded, BTreeSet::from(["uuid-2".to_string()]));
    }
}
