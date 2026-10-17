//! How a user's `stringAuthorities` are built for an app, as `UserService.getUserAuthorities`
//! builds them:
//!
//! 1. the user's own roles (`security_v2_user_role`, plus their direct sub-roles) and those
//!    roles' permissions, grouped by app code (`userRoles` cache): the app's list, then the
//!    app-less ("") list;
//! 2. then every profile the user holds in the app (or the app's default profiles when none),
//!    each expanded by `ProfileDAO.getProfileAuthorities` against the user's client hierarchy
//!    (`profileAuthsById_<profileId>` cache, keyed by client id);
//! 3. then `Authorities.Logged_IN`.
//!
//! The pure parts live here, with the Java quirks they carry; the reads are in `directory.rs`.

use std::collections::{HashMap, HashSet};

use crate::errors::{AuthError, AuthResult};
use crate::javamap::{grouping_order, long_hash};
use crate::model::ClientHierarchy;
use crate::store::{NamedRow, PermissionRow, RoleRecord};

pub const LOGGED_IN: &str = "Authorities.Logged_IN";

fn prefix(app_code: Option<&str>) -> String {
    match app_code {
        Some(a) => format!("Authorities.{}.", a.to_uppercase()),
        None => "Authorities.".to_string(),
    }
}

/// `AuthoritiesNameUtil.makeRoleName`. A missing name is the NullPointerException Java throws.
pub fn role_name(app_code: Option<&str>, name: Option<&str>) -> AuthResult<String> {
    let name = name.ok_or_else(|| AuthError::internal("role without a name"))?;
    Ok(format!("{}ROLE_{}", prefix(app_code), name.replace(' ', "_")))
}

/// `AuthoritiesNameUtil.makeProfileName`: `None` for a profile without a name.
pub fn profile_name(app_code: Option<&str>, name: Option<&str>) -> Option<String> {
    name.map(|n| format!("{}PROFILE_{}", prefix(app_code), n.replace(' ', "_")))
}

/// `AuthoritiesNameUtil.makePermissionName`.
pub fn permission_name(app_code: Option<&str>, name: Option<&str>) -> AuthResult<String> {
    let name = name.ok_or_else(|| AuthError::internal("permission without a name"))?;
    Ok(format!("{}{}", prefix(app_code), name.replace(' ', "_")))
}

fn distinct(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    items.into_iter().filter(|s| seen.insert(s.clone())).collect()
}

/// `Flux.distinct()` over rows: first occurrence kept.
pub fn distinct_rows<T: Clone + Eq + std::hash::Hash>(rows: Vec<T>) -> Vec<T> {
    let mut seen = HashSet::new();
    rows.into_iter().filter(|r| seen.insert(r.clone())).collect()
}

/// `RoleV2DAO.getRoleAuthoritiesPerApp`: role names then permission names, grouped by app code
/// (`""` for none).
pub fn role_map(roles: &[NamedRow], permissions: &[PermissionRow]) -> AuthResult<HashMap<String, Vec<String>>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for r in roles {
        let n = role_name(r.app_code.as_deref(), r.name.as_deref())?;
        map.entry(r.app_code.clone().unwrap_or_default()).or_default().push(n);
    }
    for p in permissions {
        let n = permission_name(p.app_code.as_deref(), p.name.as_deref())?;
        map.entry(p.app_code.clone().unwrap_or_default()).or_default().push(n);
    }
    Ok(map)
}

/// The role half of `getUserAuthorities`: the app's list, then the app-less one.
///
/// Java hands back the cached app-less list itself when the app has none, and then appends the
/// profile authorities to it, so its cached list grows on every request until evicted. That is
/// a bug with no visible use; here the list is copied (see DIFFERENCES.md).
pub fn role_authorities(map: &HashMap<String, Vec<String>>, app_code: Option<&str>) -> Vec<String> {
    let app = app_code.and_then(|a| map.get(a)).filter(|l| !l.is_empty());
    let default = map.get("").cloned().unwrap_or_default();
    match app {
        None => default,
        Some(app) if default.is_empty() => app.clone(),
        Some(app) => app.iter().cloned().chain(default).collect(),
    }
}

/// The record-selection step of `ProfileDAO.getProfileAuthorities`, quirks and all.
///
/// Rows are grouped by role id into a `HashMap` (`groupingBy`), iterated in its order. A role named once is kept
/// unless excluded. A role named by several profiles (the base profile and a client's
/// override) was meant to be resolved by client preference, but the Java code sorts and reads
/// the list it is building instead of the candidates: it re-sorts the records kept so far
/// (descending client preference, stable) and appends a copy of the last of them, dropping the
/// role itself. With nothing kept yet that is `getLast()` on an empty list, which throws. Both
/// are kept so the two implementations give the same authorities.
pub fn select_role_records(
    rows: &[RoleRecord],
    profile_id: u64,
    hierarchy: &ClientHierarchy,
) -> AuthResult<Vec<RoleRecord>> {
    let mut groups: Vec<(u64, Vec<RoleRecord>)> = Vec::new();
    for r in rows {
        let id = r.role_id.ok_or_else(|| AuthError::internal("element cannot be mapped to a null key"))?;
        match groups.iter_mut().find(|(g, _)| *g == id) {
            Some((_, list)) => list.push(r.clone()),
            None => groups.push((id, vec![r.clone()])),
        }
    }
    let ordered = grouping_order(groups.into_iter().map(|(id, list)| (long_hash(id), list)).collect());

    let pref = |r: &RoleRecord| r.profile_client_id.and_then(|c| hierarchy.client_order(c)).unwrap_or(-1);
    let mut records: Vec<RoleRecord> = Vec::new();
    for list in ordered {
        if list.len() == 1 {
            if list[0].exclude.unwrap_or(0) == 0 {
                records.push(list[0].clone());
            }
            continue;
        }
        let mut base = None;
        let mut others = 0;
        for r in &list {
            if r.profile_id == Some(profile_id) {
                base = Some(r.clone());
            } else {
                others += 1;
            }
        }
        if others == 0 {
            if let Some(b) = base {
                records.push(b);
            }
        } else {
            records.sort_by_key(|r| std::cmp::Reverse(pref(r)));
            let last = records.last().cloned().ok_or_else(|| AuthError::internal("NoSuchElementException"))?;
            records.push(last);
        }
    }
    Ok(records)
}

/// The final step of `ProfileDAO.getProfileAuthorities`: role names, sub-role names,
/// permission names, then profile names; nulls dropped, first occurrence kept.
pub fn profile_authority_names(
    profiles: &[NamedRow],
    roles: &[RoleRecord],
    sub_roles: &[NamedRow],
    permissions: &[PermissionRow],
) -> AuthResult<Vec<String>> {
    let mut out = Vec::new();
    for r in roles {
        out.push(role_name(r.app_code.as_deref(), r.role_name.as_deref())?);
    }
    for r in sub_roles {
        out.push(role_name(r.app_code.as_deref(), r.name.as_deref())?);
    }
    for p in permissions {
        out.push(permission_name(p.app_code.as_deref(), p.name.as_deref())?);
    }
    out.extend(profiles.iter().filter_map(|p| profile_name(p.app_code.as_deref(), p.name.as_deref())));
    Ok(distinct(out))
}

/// `getProfileAuthorities(Set<ULong>, hierarchy)`: the per-profile lists in `HashSet` order of
/// the profile ids, flattened, first occurrence kept.
pub fn merge_profile_lists(lists: Vec<Vec<String>>) -> Vec<String> {
    distinct(lists.into_iter().flatten())
}

/// `getUserAuthorities`: roles, profiles, `Authorities.Logged_IN` (duplicates between the two
/// halves are kept, as in Java).
pub fn user_authorities(roles: Vec<String>, profiles: Vec<String>) -> Vec<String> {
    let mut all = roles;
    all.extend(profiles);
    all.push(LOGGED_IN.to_string());
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(role: u64, profile: u64, client: u64, name: &str, exclude: i64) -> RoleRecord {
        RoleRecord {
            role_id: Some(role),
            profile_client_id: Some(client),
            profile_id: Some(profile),
            role_name: Some(name.into()),
            app_code: None,
            exclude: Some(exclude),
        }
    }

    fn named(id: u64, name: &str, app: Option<&str>) -> NamedRow {
        NamedRow { id: Some(id), name: Some(name.into()), app_code: app.map(str::to_string) }
    }

    #[test]
    fn names() {
        assert_eq!(role_name(Some("appbuilder"), Some("Page Manager")).unwrap(), "Authorities.APPBUILDER.ROLE_Page_Manager");
        assert_eq!(role_name(None, Some("Owner")).unwrap(), "Authorities.ROLE_Owner");
        assert!(role_name(None, None).is_err());
        assert_eq!(profile_name(Some("leadzump"), Some("Lead Admin")).as_deref(), Some("Authorities.LEADZUMP.PROFILE_Lead_Admin"));
        assert_eq!(profile_name(None, None), None);
        assert_eq!(permission_name(None, Some("Page READ")).unwrap(), "Authorities.Page_READ");
        assert!(permission_name(None, None).is_err());
    }

    #[test]
    fn role_map_groups_by_app() {
        let m = role_map(
            &[named(1, "Owner", None), named(2, "Viewer", Some("crm"))],
            &[PermissionRow { name: Some("Lead READ".into()), app_code: Some("crm".into()) }],
        )
        .unwrap();
        assert_eq!(m[""], vec!["Authorities.ROLE_Owner"]);
        assert_eq!(m["crm"], vec!["Authorities.CRM.ROLE_Viewer", "Authorities.CRM.Lead_READ"]);
        assert_eq!(role_authorities(&m, Some("crm")), vec!["Authorities.CRM.ROLE_Viewer", "Authorities.CRM.Lead_READ", "Authorities.ROLE_Owner"]);
        assert_eq!(role_authorities(&m, Some("other")), vec!["Authorities.ROLE_Owner"]);
        assert_eq!(role_authorities(&m, None), vec!["Authorities.ROLE_Owner"]);
        let only_app = role_map(&[named(2, "Viewer", Some("crm"))], &[]).unwrap();
        assert_eq!(role_authorities(&only_app, Some("crm")), vec!["Authorities.CRM.ROLE_Viewer"]);
        assert!(role_authorities(&HashMap::new(), Some("crm")).is_empty());
        assert!(role_map(&[NamedRow::default()], &[]).is_err());
        assert!(role_map(&[], &[PermissionRow::default()]).is_err());
    }

    #[test]
    fn single_roles_kept_unless_excluded_in_hash_order() {
        let h = ClientHierarchy { client_id: 5, level0: Some(1), ..Default::default() };
        let rows = vec![rec(18, 1, 1, "B", 0), rec(2, 1, 1, "A", 0), rec(3, 1, 1, "X", 1)];
        let out = select_role_records(&rows, 1, &h).unwrap();
        // 18 and 2 share bucket 2; groupingBy puts the later key (2) first.
        assert_eq!(out.iter().map(|r| r.role_id.unwrap()).collect::<Vec<_>>(), vec![2, 18]);
    }

    #[test]
    fn base_only_duplicates_keep_the_base_record() {
        let h = ClientHierarchy { client_id: 5, ..Default::default() };
        // Two rows of the base profile for one role (excluded or not, the base wins).
        let rows = vec![rec(7, 1, 5, "R", 1), rec(7, 1, 5, "R", 1)];
        let out = select_role_records(&rows, 1, &h).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn overridden_role_is_dropped_and_last_kept_record_repeated() {
        let h = ClientHierarchy { client_id: 5, level0: Some(1), ..Default::default() };
        // Role 1 is kept first; role 2 has a base row and a child-profile row.
        let rows = vec![rec(1, 10, 1, "Kept", 0), rec(2, 10, 1, "Over", 0), rec(2, 11, 5, "Over", 1)];
        let out = select_role_records(&rows, 10, &h).unwrap();
        assert_eq!(out.iter().map(|r| r.role_name.clone().unwrap()).collect::<Vec<_>>(), vec!["Kept", "Kept"]);
    }

    #[test]
    fn overridden_role_first_is_javas_no_such_element() {
        let h = ClientHierarchy { client_id: 5, ..Default::default() };
        let rows = vec![rec(2, 10, 1, "Over", 0), rec(2, 11, 5, "Over", 0)];
        assert!(select_role_records(&rows, 10, &h).is_err());
        assert!(select_role_records(&[RoleRecord::default()], 10, &h).is_err());
    }

    #[test]
    fn records_resorted_by_client_preference() {
        let h = ClientHierarchy { client_id: 5, level0: Some(1), ..Default::default() };
        // Kept so far: role 1 (client 5, pref 0), role 3 (client 1, pref 1). Role 4 overridden.
        let rows = vec![rec(1, 10, 5, "Near", 0), rec(3, 10, 1, "Far", 0), rec(4, 10, 1, "O", 0), rec(4, 12, 5, "O", 0)];
        let out = select_role_records(&rows, 10, &h).unwrap();
        let names: Vec<_> = out.iter().map(|r| r.role_name.clone().unwrap()).collect();
        assert_eq!(names, vec!["Far", "Near", "Near"]);
    }

    #[test]
    fn profile_names_in_order() {
        let names = profile_authority_names(
            &[named(1, "Owner", Some("appbuilder")), NamedRow::default()],
            &[RoleRecord { role_name: Some("Page Manager".into()), ..Default::default() }],
            &[named(9, "Page READ", None), named(9, "Page Manager", None)],
            &[PermissionRow { name: Some("Page_READ".into()), app_code: None }],
        )
        .unwrap();
        assert_eq!(
            names,
            vec![
                "Authorities.ROLE_Page_Manager",
                "Authorities.ROLE_Page_READ",
                "Authorities.Page_READ",
                "Authorities.APPBUILDER.PROFILE_Owner"
            ]
        );
        assert!(profile_authority_names(&[], &[RoleRecord::default()], &[], &[]).is_err());
        assert!(profile_authority_names(&[], &[], &[NamedRow::default()], &[]).is_err());
        assert!(profile_authority_names(&[], &[], &[], &[PermissionRow::default()]).is_err());
    }

    #[test]
    fn user_list_assembly() {
        let merged = merge_profile_lists(vec![vec!["a".into(), "b".into()], vec!["b".into(), "c".into()]]);
        assert_eq!(merged, vec!["a", "b", "c"]);
        let all = user_authorities(vec!["a".into()], merged);
        assert_eq!(all, vec!["a", "a", "b", "c", LOGGED_IN]);
        assert_eq!(distinct_rows(vec![1, 2, 1, 3]), vec![1, 2, 3]);
    }
}
