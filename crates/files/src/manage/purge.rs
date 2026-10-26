//! The admin purge (Rust only, no Java counterpart): every file of a client, or every app
//! folder of an app, in both buckets, with the rows that describe them. Called by multi's purge
//! next to security's, core's and ui's.
//!
//! | Route | Who |
//! |---|---|
//! | `DELETE purge/client/{clientCode}?dryRun=` | a client that manages it, with `Client_DELETE` |
//! | `DELETE purge/app/{appCode}?dryRun=` | SYSTEM with `Application_DELETE` |
//!
//! A client's purge: every object under `<client>/` in the static and secured buckets, its
//! `files_file_system` rows, and its rows in `files_access_path`, `files_upload_download` and
//! `files_retention_policy`, and the secured access keys for paths under `<client>/`. An app's
//! purge: every root folder named exactly the app code, under every client and in both buckets
//! (the convention app-level retention reads), with the objects under it, and the app's
//! `files_retention_policy` rows. `dryRun` is true unless it is `false`; the report is
//! `{dryRun, objects: {bucket kind: n}, rows: {table: n}, errors}`.

use std::collections::BTreeMap;

use axum::http::StatusCode;
use axum::response::Response;
use platform::error::{AppError, AppResult};
use serde_json::{json, Value};

use super::Ctx;
use crate::fs::Fs;
use crate::paths::Kind;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Client(String),
    App(String),
}

impl Target {
    /// A purge target from its route: a client code is letters and digits and never SYSTEM;
    /// an app code may carry `_`.
    pub fn parse(kind: &str, code: &str) -> Option<Self> {
        let alnum = |s: &str, extra: bool| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || (extra && b == b'_'));
        match kind {
            "client" if alnum(code, false) && !code.eq_ignore_ascii_case("SYSTEM") => Some(Target::Client(code.to_string())),
            "app" if alnum(code, true) && code.bytes().any(|b| b.is_ascii_alphanumeric()) => Some(Target::App(code.to_string())),
            _ => None,
        }
    }

    fn authority(&self) -> &'static str {
        match self {
            Target::Client(_) => "Authorities.Client_DELETE",
            Target::App(_) => "Authorities.Application_DELETE",
        }
    }
}

/// `dryRun`: only `false` deletes anything.
pub fn dry_run(param: Option<&str>) -> bool {
    !matches!(param, Some(v) if v.trim().eq_ignore_ascii_case("false"))
}

#[derive(Debug, Default)]
struct Report {
    objects: BTreeMap<String, i64>,
    rows: BTreeMap<String, i64>,
    errors: Vec<String>,
}

pub(crate) async fn handle(cx: &Ctx, kind: &str, code: &str) -> AppResult<Response> {
    let Some(target) = Target::parse(kind, code) else {
        return Err(crate::errors::literal("FILES.PURGE_BAD_CODE", StatusCode::BAD_REQUEST, format!("not a purgeable {kind} code: {code:?}"))
            .param("code", code)
            .into());
    };
    let ca = cx.ca();
    // A client: only a client that manages it, never itself, never SYSTEM (`parse` refuses it).
    // An app: SYSTEM only.
    let allowed = ca.has_authority(target.authority())
        && match &target {
            Target::Client(c) => {
                let own = ca.client_code();
                !own.is_empty()
                    && own != c
                    && cx.st.security().does_client_manage_client_code(own, c).await.unwrap_or_else(|e| {
                        tracing::error!(error = %e, "files purge: could not ask security who manages the client");
                        false
                    })
            }
            Target::App(_) => ca.is_system_client(),
        };
    if !allowed {
        return Err(AppError::from(crate::errors::literal(
            "FILES.PURGE_FORBIDDEN",
            StatusCode::FORBIDDEN,
            format!("purge needs {} and, for a client, a caller whose client manages it (an app: SYSTEM)", target.authority()),
        )));
    }
    let dry = dry_run(cx.params.get("dryRun"));
    tracing::warn!(target = ?target, dry_run = dry, user = cx.user_id(), "files purge");
    let r = run(cx, &target, dry).await;
    Ok(crate::jackson::json(&json!({"dryRun": dry, "objects": r.objects, "rows": r.rows, "errors": r.errors})))
}

/// The object-key prefixes and the client of each, per bucket: `<client>/` for a client; for an
/// app, `<client>/<app>/` for every client holding a root folder of that name.
async fn prefixes(cx: &Ctx, target: &Target, kind: Kind, r: &mut Report) -> Vec<(String, String)> {
    match target {
        Target::Client(c) => vec![(c.clone(), format!("{c}/"))],
        Target::App(a) => match cx.st.dao().read_app_root_folders(kind, a).await {
            Ok(rows) => rows.into_iter().map(|(cc, _)| (cc.clone(), format!("{cc}/{a}/"))).collect(),
            Err(e) => {
                r.errors.push(format!("{}: app folders: {e:#}", kind.db_name()));
                Vec::new()
            }
        },
    }
}

async fn run(cx: &Ctx, target: &Target, dry: bool) -> Report {
    let mut r = Report::default();
    let mut touched: Vec<String> = Vec::new();
    for kind in [Kind::Static, Kind::Secured] {
        let store = cx.st.store(kind);
        for (cc, prefix) in prefixes(cx, target, kind, &mut r).await {
            let objects = match store.list_objects(&prefix).await {
                Ok(o) => o,
                Err(e) => {
                    r.errors.push(format!("{}: list {prefix}: {e:#}", kind.db_name()));
                    continue;
                }
            };
            let mut n = 0i64;
            for (key, _) in &objects {
                if !dry {
                    if let Err(e) = store.delete_object(key).await {
                        r.errors.push(format!("{}: delete {key}: {e:#}", kind.db_name()));
                        continue;
                    }
                    store.drop_local_copies(key).await;
                }
                n += 1;
            }
            *r.objects.entry(kind.db_name().to_string()).or_default() += n;
            if !touched.contains(&cc) {
                touched.push(cc.clone());
            }
            // The rows: the client's whole tree, or the app folder and everything under it.
            let rows = match target {
                Target::Client(c) => tree_rows(cx, kind, c, None, dry).await,
                Target::App(a) => match cx.st.dao().read_root_folder_id(kind, &cc, a).await {
                    Ok(Some(id)) => tree_rows(cx, kind, &cc, Some(id), dry).await,
                    Ok(None) => Ok(0),
                    Err(e) => Err(e),
                },
            };
            match rows {
                Ok(n) => *r.rows.entry("files_file_system".into()).or_default() += n,
                Err(e) => r.errors.push(format!("{}: rows of {prefix}: {e:#}", kind.db_name())),
            }
        }
    }
    let plain: Vec<(&str, String, String)> = match target {
        Target::Client(c) => vec![
            ("files_access_path", "CLIENT_CODE = ?".into(), c.clone()),
            ("files_upload_download", "CLIENT_CODE = ?".into(), c.clone()),
            ("files_retention_policy", "CLIENT_CODE = ?".into(), c.clone()),
            ("files_secured_access_keys", "PATH LIKE ?".into(), format!("{c}/%")),
        ],
        Target::App(a) => vec![("files_retention_policy", "APP_CODE = ?".into(), a.clone())],
    };
    let pool = cx.st.dao().pool();
    for (table, cond, value) in plain {
        let sql = if dry { format!("SELECT COUNT(*) FROM {table} WHERE {cond}") } else { format!("DELETE FROM {table} WHERE {cond}") };
        let n = if dry {
            sqlx::query_scalar::<_, i64>(&sql).bind(&value).fetch_one(pool).await.map_err(anyhow::Error::from)
        } else {
            sqlx::query(&sql).bind(&value).execute(pool).await.map(|x| x.rows_affected() as i64).map_err(anyhow::Error::from)
        };
        match n {
            Ok(0) => {}
            Ok(n) => *r.rows.entry(table.into()).or_default() += n,
            Err(e) => r.errors.push(format!("{table}: {e:#}")),
        }
    }
    if !dry {
        for cc in &touched {
            for kind in [Kind::Static, Kind::Secured] {
                Fs::new(&cx.st, kind).evict(cc).await;
            }
        }
        if r.rows.contains_key("files_retention_policy") {
            crate::retention::evict_caches(&cx.st).await;
        }
    }
    r
}

/// The `files_file_system` rows of a client (`folder` None: all of them) or of one folder and
/// everything under it: counted, or deleted children first.
async fn tree_rows(cx: &Ctx, kind: Kind, cc: &str, folder: Option<u64>, dry: bool) -> anyhow::Result<i64> {
    let pool = cx.st.dao().pool();
    let Some(root) = folder else {
        let sql = if dry {
            "SELECT COUNT(*) FROM files_file_system WHERE TYPE = ? AND CODE = ?"
        } else {
            "DELETE FROM files_file_system WHERE TYPE = ? AND CODE = ? ORDER BY PARENT_ID IS NULL, ID DESC"
        };
        return Ok(if dry {
            sqlx::query_scalar::<_, i64>(sql).bind(kind.db_name()).bind(cc).fetch_one(pool).await?
        } else {
            sqlx::query(sql).bind(kind.db_name()).bind(cc).execute(pool).await?.rows_affected() as i64
        });
    };
    // The folder's subtree, level by level; deleted deepest level first.
    let mut levels: Vec<Vec<u64>> = vec![vec![root]];
    loop {
        let parents = levels.last().cloned().unwrap_or_default();
        if parents.is_empty() || levels.len() > 64 {
            break;
        }
        let marks = vec!["?"; parents.len()].join(", ");
        let sql = format!("SELECT ID FROM files_file_system WHERE TYPE = ? AND CODE = ? AND PARENT_ID IN ({marks})");
        let mut q = sqlx::query_scalar::<_, u64>(&sql).bind(kind.db_name()).bind(cc);
        for p in &parents {
            q = q.bind(*p);
        }
        let children = q.fetch_all(pool).await?;
        if children.is_empty() {
            break;
        }
        levels.push(children);
    }
    let total: i64 = levels.iter().map(|l| l.len() as i64).sum();
    if !dry {
        for level in levels.iter().rev() {
            for chunk in level.chunks(1000) {
                let marks = vec!["?"; chunk.len()].join(", ");
                let sql = format!("DELETE FROM files_file_system WHERE ID IN ({marks})");
                let mut q = sqlx::query(&sql);
                for id in chunk {
                    q = q.bind(*id);
                }
                q.execute(pool).await?;
            }
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(Target::parse("client", "ABC1"), Some(Target::Client("ABC1".into())));
        assert_eq!(Target::parse("app", "my_app"), Some(Target::App("my_app".into())));
        for (k, c) in [("client", "SYSTEM"), ("client", "system"), ("client", "A_B"), ("client", ""), ("app", "a/b"), ("app", "_"), ("x", "A")] {
            assert_eq!(Target::parse(k, c), None, "{k} {c}");
        }
    }

    #[test]
    fn dry_run_unless_false() {
        assert!(dry_run(None));
        assert!(dry_run(Some("true")));
        assert!(dry_run(Some("no")));
        assert!(!dry_run(Some("false")));
        assert!(!dry_run(Some(" FALSE ")));
    }

    #[test]
    fn authorities() {
        assert_eq!(Target::Client("A".into()).authority(), "Authorities.Client_DELETE");
        assert_eq!(Target::App("a".into()).authority(), "Authorities.Application_DELETE");
    }
}
