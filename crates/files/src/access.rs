//! `SecuredFileResourceService.checkReadAccessWithClientCode` and
//! `FilesAccessPathService.hasReadAccess`: may this caller read this secured path.

use anyhow::Result;
use platform::security::ContextAuthentication;

use crate::paths::Kind;
use crate::protected::{any_rule_under, prefix_of};
use crate::state::AppState;

const USER_IMAGES: &str = "_userImages";
const WITH_IN_CLIENT: &str = "_withInClient";
const WITH_IN_SUB_CLIENT: &str = "_withInSubClient";
const ALL_SUB_CLIENTS: &str = "_allSubClients";

/// `rp` is `<clientCode>/<path>` without a leading `/`.
pub async fn can_read_secured(state: &AppState, ca: &ContextAuthentication, rp: &str) -> Result<bool> {
    // `resourcePath.indexOf('/', 1)`.
    let (client_code, resource_path) = match find_from(rp, '/', 1) {
        Some(i) => (&rp[..i], &rp[i..]),
        None => (rp, ""),
    };

    let first_folder = find_from(resource_path, '/', 1).map(|i| {
        let start = usize::from(resource_path.starts_with('/'));
        &resource_path[start..i]
    });

    if let Some(folder) = first_folder {
        let special = matches!(folder, WITH_IN_CLIENT | WITH_IN_SUB_CLIENT | ALL_SUB_CLIENTS)
            || (folder == USER_IMAGES && client_code == "SYSTEM");
        if special {
            let caller = ca.client_code();
            return Ok(match folder {
                USER_IMAGES => true,
                WITH_IN_CLIENT => caller == client_code,
                // The owner of the file must manage the caller: a sub client reads its parent's
                // folder. Argument order is the Java one.
                WITH_IN_SUB_CLIENT => {
                    caller != client_code
                        && state
                            .security()
                            .does_client_manage_client_code(client_code, caller)
                            .await?
                }
                ALL_SUB_CLIENTS => {
                    state
                        .security()
                        .does_client_manage_client_code(client_code, caller)
                        .await?
                }
                _ => false,
            });
        }
    }

    has_secured_read_access(state, ca, resource_path, client_code).await
}

/// `FilesAccessPathService.hasReadAccess` for SECURED.
async fn has_secured_read_access(
    state: &AppState,
    ca: &ContextAuthentication,
    actual_path: &str,
    client_code: &str,
) -> Result<bool> {
    let path = actual_path.strip_suffix('/').unwrap_or(actual_path);

    let managed = if ca.is_system_client() {
        true
    } else {
        let target = state.security().client_id_by_code(client_code).await?;
        state
            .security()
            .is_user_client_manage_client(
                ca.url_app_code.as_deref(),
                ca.user.id,
                ca.user.client_id,
                target,
            )
            .await?
    };
    if !managed {
        return Ok(false);
    }

    if let Some(prefix) = prefix_of(protected_prefixes(state), path) {
        return protected_rule_allows(state, ca, Kind::Secured, path, client_code, prefix, false).await;
    }
    state
        .dao()
        .has_secured_path_read_access(path, ca.user.id, client_code, &ca.user.string_authorities)
        .await
}

/// `[files] protected_prefixes`.
pub fn protected_prefixes(state: &AppState) -> &[String] {
    &state.config().files.protected_prefixes
}

/// A SECURED path under the protected `prefix`: allowed only by a covering rule whose own PATH
/// is under that prefix (`crate::protected`). The caller has already checked that the client
/// is managed.
async fn protected_rule_allows(
    state: &AppState,
    ca: &ContextAuthentication,
    kind: Kind,
    path: &str,
    client_code: &str,
    prefix: &str,
    write: bool,
) -> Result<bool> {
    let rules = state
        .dao()
        .covering_rule_paths(kind, path, ca.user.id, client_code, &ca.user.string_authorities, write)
        .await?;
    Ok(any_rule_under(prefix, &rules))
}

/// The protected prefixes this caller may NOT reach in `client_code` (to read, or to write):
/// what a root listing hides, a root export leaves out and a root zip import skips. Empty for
/// STATIC.
pub async fn blocked_prefixes(
    state: &AppState,
    ca: &ContextAuthentication,
    client_code: &str,
    kind: Kind,
    write: bool,
) -> Result<Vec<String>> {
    let mut blocked = Vec::new();
    if kind != Kind::Secured {
        return Ok(blocked);
    }
    for p in protected_prefixes(state) {
        // The folder as listing, upload and export name it: no leading slash.
        let folder = p.trim().trim_matches('/');
        if folder.is_empty() {
            continue;
        }
        let allowed = if write {
            has_write_access(state, ca, folder, client_code, kind).await?
        } else {
            has_read_access(state, ca, folder, client_code, kind).await?
        };
        if !allowed {
            blocked.push(p.clone());
        }
    }
    Ok(blocked)
}

/// `FilesAccessPathService.hasReadAccess` for either type, as the listing and the export use it.
/// An unknown client code is no access here (Java fails on it with a 500).
pub async fn has_read_access(
    state: &AppState,
    ca: &ContextAuthentication,
    actual_path: &str,
    client_code: &str,
    kind: Kind,
) -> Result<bool> {
    let path = actual_path.strip_suffix('/').unwrap_or(actual_path);
    let Some(target) = state.security().client_id_by_code(client_code).await? else {
        return Ok(false);
    };
    let managed = ca.is_system_client()
        || state
            .security()
            .is_user_client_manage_client(ca.url_app_code.as_deref(), ca.user.id, ca.user.client_id, Some(target))
            .await?;
    if !managed {
        return Ok(false);
    }
    if kind == Kind::Secured {
        if let Some(prefix) = prefix_of(protected_prefixes(state), path) {
            return protected_rule_allows(state, ca, kind, path, client_code, prefix, false).await;
        }
    }
    state
        .dao()
        .has_path_access(kind, path, ca.user.id, client_code, &ca.user.string_authorities, false)
        .await
}

/// `FilesAccessPathService.hasWriteAccess`.
pub async fn has_write_access(
    state: &AppState,
    ca: &ContextAuthentication,
    actual_path: &str,
    client_code: &str,
    kind: Kind,
) -> Result<bool> {
    let path = actual_path.strip_suffix('/').unwrap_or(actual_path);
    let Some(target) = state.security().client_id_by_code(client_code).await? else {
        return Ok(false);
    };
    let managed = if ca.is_system_client() {
        state.security().valid_client_code(client_code).await? == Some(true)
    } else {
        state
            .security()
            .is_user_client_manage_client(ca.url_app_code.as_deref(), ca.user.id, ca.user.client_id, Some(target))
            .await?
    };
    if !managed {
        return Ok(false);
    }
    // Before the mobile uploader shortcut: a protected folder opens only by its own rules.
    if kind == Kind::Secured {
        if let Some(prefix) = prefix_of(protected_prefixes(state), path) {
            return protected_rule_allows(state, ca, kind, path, client_code, prefix, true).await;
        }
    }
    if ca.is_system_client() && path.contains(WITH_IN_CLIENT) && ca.has_authority("Authorities.ROLE_MobileApp_UPLOADER") {
        return Ok(true);
    }
    state
        .dao()
        .has_path_access(kind, path, ca.user.id, client_code, &ca.user.string_authorities, true)
        .await
}

/// `StaticFileResourceService.subClientListAccess`: the two static folders a managing client
/// shares with the clients it manages.
pub async fn sub_client_list_access(
    state: &AppState,
    ca: &ContextAuthentication,
    resource_path: &str,
    client_code: &str,
) -> Result<bool> {
    let rp = resource_path.trim();
    if rp.is_empty() {
        return Ok(false);
    }
    let rp = rp.strip_prefix('/').unwrap_or(rp);
    let end = find_from(rp, '/', 1).unwrap_or(rp.len());
    let first = &rp[usize::from(rp.starts_with('/')).min(end)..end];
    let caller = ca.client_code();
    match first {
        WITH_IN_SUB_CLIENT => Ok(caller != client_code
            && state.security().does_client_manage_client_code(client_code, caller).await?),
        ALL_SUB_CLIENTS => state.security().does_client_manage_client_code(client_code, caller).await,
        _ => Ok(false),
    }
}

/// `FilesAccessPathService.isClientBeingManaged`.
pub async fn is_client_being_managed(state: &AppState, managing: &str, client_code: &str) -> Result<bool> {
    if managing == client_code {
        return Ok(true);
    }
    state.security().does_client_manage_client_code(managing, client_code).await
}

/// `String.indexOf(ch, from)`.
fn find_from(s: &str, ch: char, from: usize) -> Option<usize> {
    s.get(from..)?.find(ch).map(|i| i + from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_of_from() {
        assert_eq!(find_from("CC/a/b", '/', 1), Some(2));
        assert_eq!(find_from("/a/b", '/', 1), Some(2));
        assert_eq!(find_from("/a", '/', 1), None);
        assert_eq!(find_from("", '/', 1), None);
    }
}
