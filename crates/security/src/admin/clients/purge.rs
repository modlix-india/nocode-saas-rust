//! Clean-slate purges: a hard delete of a client (with its users) or of an app, together with every
//! security row that hangs off it through a foreign key. No Java counterpart: Java only marks a
//! client `DELETED`, and its app `deleteEverything` leaves roles, profiles, packages and wallets
//! behind (their RESTRICT keys then make the delete fail).
//!
//! The rows to delete are found by walking the schema's own foreign keys from information_schema,
//! so a table added later is covered without touching this file. A `SET NULL` key is not walked:
//! MySQL clears it when the parent goes. Every other key is, and each row remembers how deep it was
//! found, so deleting the deepest rows first never trips a RESTRICT key, self references included.
//!
//! | Route | Who |
//! |---|---|
//! | `DELETE clients/purge/{idOrCode}?dryRun=` | SYSTEM with `Client_DELETE` |
//! | `DELETE applications/purge/{idOrCode}?dryRun=` | SYSTEM with `Application_DELETE` |
//!
//! `dryRun` is true unless it is `false`: the report then says what would go, and nothing changes.
//! The ui and core halves (definitions, tenant data) are their own units' purge routes; multi's
//! purge calls all three.

use std::collections::{BTreeMap, HashMap};

use axum::http::StatusCode;
use axum::routing::delete;
use axum::Router;
use serde_json::{json, Map, Value};
use sqlx::mysql::MySqlConnection;
use sqlx::Row as _;

use super::app_routes::opt_bool;
use super::common::{cache, pre_authorize};
use crate::admin::AdminState;
use crate::data::audit::{action, object, sox};
use crate::errors::{AuthError, AuthResult};
use crate::jackson::json as json_resp;
use crate::model::ContextAuth;
use crate::web_route_path;

/// Deeper than any real chain of rows; a row cycle stops the walk here instead of looping.
const MAX_DEPTH: u32 = 64;
/// Ids per `IN (...)`.
const CHUNK: usize = 1000;

const REFUSED: &str = "SEC.PURGE_REFUSED";
const NOT_FOUND: &str = "SEC.OBJECT_NOT_FOUND";

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/clients/purge/{idOrCode}", delete(purge_client_route))
        .route("/api/security/applications/purge/{idOrCode}", delete(purge_app_route))
}

web_route_path!(purge_client_route, AdminState, "/clients/purge/{idOrCode}", true, |s, r, ca, key| {
    pre_authorize(&ca, "Authorities.Client_DELETE")?;
    let dry_run = opt_bool(&r.params, "dryRun")? != Some(false);
    Ok(json_resp(&purge_client(&s, &ca, &key, dry_run).await?))
});

web_route_path!(purge_app_route, AdminState, "/applications/purge/{idOrCode}", true, |s, r, ca, key| {
    pre_authorize(&ca, "Authorities.Application_DELETE")?;
    let dry_run = opt_bool(&r.params, "dryRun")? != Some(false);
    Ok(json_resp(&purge_app(&s, &ca, &key, dry_run).await?))
});

/// What is being purged: the root row and how its ownership is recognised in the entity tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Client,
    App,
}

impl Kind {
    fn root_table(self) -> &'static str {
        match self {
            Kind::Client => "security_client",
            Kind::App => "security_app",
        }
    }

    fn code_column(self) -> &'static str {
        match self {
            Kind::Client => "CODE",
            Kind::App => "APP_CODE",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Kind::Client => "client",
            Kind::App => "application",
        }
    }

    /// The column of an entity table that says which client (or app) a row belongs to; `None` for
    /// a table that is not an entity of this kind's. A purge that reaches another owner's entity
    /// row (a profile whose root profile is ours, say) is refused rather than taking it along.
    fn owner_column(self, table: &str) -> Option<&'static str> {
        match (self, table) {
            (Kind::Client, "security_client") | (Kind::App, "security_app") => Some("ID"),
            (Kind::Client, "security_user" | "security_app" | "security_profile" | "security_role" | "security_v2_role")
            | (Kind::Client, "security_permission" | "security_package") => Some("CLIENT_ID"),
            (Kind::App, "security_profile" | "security_role" | "security_v2_role" | "security_permission" | "security_package") => {
                Some("APP_ID")
            }
            // An app purge never owns a client or a user: any such row reached is someone else's.
            (Kind::App, "security_client" | "security_user") => Some("NULL"),
            _ => None,
        }
    }
}

/// One foreign key: `child.column` points at `parent.referenced`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Fk {
    child: String,
    column: String,
    parent: String,
    referenced: String,
    rule: String,
}

/// Rows found, per table: id and the depth it was found at (a row is always deeper than every row
/// it points at through a walked key).
type Found = BTreeMap<String, HashMap<u64, u32>>;

/// `DELETE clients/purge/{idOrCode}`.
pub async fn purge_client(s: &AdminState, ca: &ContextAuth, key: &str, dry_run: bool) -> AuthResult<Value> {
    purge(s, ca, Kind::Client, key, dry_run).await
}

/// `DELETE applications/purge/{idOrCode}`.
pub async fn purge_app(s: &AdminState, ca: &ContextAuth, key: &str, dry_run: bool) -> AuthResult<Value> {
    purge(s, ca, Kind::App, key, dry_run).await
}

async fn purge(s: &AdminState, ca: &ContextAuth, kind: Kind, key: &str, dry_run: bool) -> AuthResult<Value> {
    if !ca.is_system_client() {
        return Err(AuthError::denied(ca, &["SYSTEM client"]));
    }
    let key = key.trim();
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(refused(StatusCode::BAD_REQUEST, format!("Not a {} id or code: {key:?}", kind.label())));
    }
    let mut tx = s.db.pool.begin().await?;
    let (id, code) = root(&mut tx, kind, key).await?;
    if kind == Kind::Client && code == "SYSTEM" {
        return Err(refused(StatusCode::BAD_REQUEST, "The SYSTEM client cannot be purged".into()));
    }
    let blockers = blockers(&mut tx, kind, id).await?;
    if !blockers.is_empty() {
        return Err(refused(StatusCode::CONFLICT, format!("{} {code} cannot be purged: {}", kind.label(), blockers.join("; "))));
    }
    let fks = foreign_keys(&mut tx).await?;
    let found = closure(&mut tx, &fks, kind.root_table(), &[id]).await?;
    let foreign = foreign_entities(&mut tx, kind, id, &found).await?;
    if !foreign.is_empty() {
        let list: Vec<String> = foreign.iter().map(|(t, n)| format!("{t} {n}")).collect();
        return Err(refused(
            StatusCode::CONFLICT,
            format!("{} {code} cannot be purged: it reaches rows owned by others ({})", kind.label(), list.join(", ")),
        ));
    }
    let counts: BTreeMap<String, usize> = found.iter().map(|(t, rows)| (t.clone(), rows.len())).collect();
    let users: Vec<u64> = found.get("security_user").map(|m| m.keys().copied().collect()).unwrap_or_default();
    let profiles: Vec<u64> = found.get("security_profile").map(|m| m.keys().copied().collect()).unwrap_or_default();
    if dry_run {
        tx.rollback().await?;
        return Ok(report(kind, id, &code, true, &counts));
    }
    delete_found(&mut tx, &found).await?;
    tx.commit().await?;

    let by = Some(ca.user.id());
    let what = match kind {
        Kind::Client => (object::CLIENT, format!("Client purged: {code} with {} user(s)", users.len())),
        Kind::App => (object::APP, format!("Application purged: {code}")),
    };
    sox(&s.db, Some(id), what.0, action::DELETE, what.1, by);
    evict(s, kind, id, &code, &profiles).await;
    tracing::info!(kind = kind.label(), id, code, rows = counts.values().sum::<usize>(), "purged");
    Ok(report(kind, id, &code, false, &counts))
}

fn refused(status: StatusCode, message: String) -> AuthError {
    if status == StatusCode::NOT_FOUND {
        return AuthError::literal(status, NOT_FOUND, message);
    }
    AuthError::literal(status, REFUSED, message)
}

fn report(kind: Kind, id: u64, code: &str, dry_run: bool, counts: &BTreeMap<String, usize>) -> Value {
    let tables: Map<String, Value> = counts.iter().map(|(t, n)| (t.clone(), Value::from(*n))).collect();
    json!({"dryRun": dry_run, "kind": kind.label(), "id": id, "code": code, "tables": tables,
           "rows": counts.values().sum::<usize>()})
}

/// The root row's id and code, by id when the key is all digits, else by code. Locked for the
/// transaction so a concurrent change waits.
async fn root(conn: &mut MySqlConnection, kind: Kind, key: &str) -> AuthResult<(u64, String)> {
    let by_id = key.bytes().all(|b| b.is_ascii_digit());
    let sql = format!(
        "SELECT ID, CAST({code} AS CHAR) AS CODE FROM {table} WHERE {col} = ? FOR UPDATE",
        code = kind.code_column(),
        table = kind.root_table(),
        col = if by_id { "ID" } else { kind.code_column() },
    );
    let row = sqlx::query(&sql).bind(key).fetch_optional(&mut *conn).await?;
    let Some(row) = row else {
        return Err(refused(StatusCode::NOT_FOUND, format!("No {} {key}", kind.label())));
    };
    Ok((row.try_get::<u64, _>("ID")?, row.try_get::<String, _>("CODE")?))
}

/// Why this purge must not run, in plain words; empty when it may.
async fn blockers(conn: &mut MySqlConnection, kind: Kind, id: u64) -> AuthResult<Vec<String>> {
    let checks: &[(&str, &str)] = match kind {
        Kind::Client => &[
            (
                "SELECT COUNT(*) FROM security_client_hierarchy WHERE CLIENT_ID <> ? AND ? IN \
                 (MANAGE_CLIENT_LEVEL_0, MANAGE_CLIENT_LEVEL_1, MANAGE_CLIENT_LEVEL_2, MANAGE_CLIENT_LEVEL_3)",
                "manages {} client(s); purge those first",
            ),
            ("SELECT COUNT(*) FROM security_app WHERE CLIENT_ID = ?", "owns {} app(s); purge those first"),
            (
                "SELECT (SELECT COUNT(*) FROM security_invoice WHERE CLIENT_ID = ? OR SELLER_CLIENT_ID = ?) + \
                 (SELECT COUNT(*) FROM security_payment WHERE CLIENT_ID = ?)",
                "has {} invoice/payment row(s)",
            ),
        ],
        Kind::App => &[
            ("SELECT COUNT(*) FROM security_invoice WHERE APP_ID = ?", "has {} invoice row(s)"),
            (
                "SELECT COUNT(*) FROM security_app_dependency WHERE DEP_APP_ID = ? AND APP_ID <> ?",
                "{} other app(s) depend on it",
            ),
        ],
    };
    // Every `?` in a check is the root's id.
    let mut out = Vec::new();
    for (sql, says) in checks {
        let mut q = sqlx::query_scalar::<_, i64>(sql);
        for _ in 0..sql.matches('?').count() {
            q = q.bind(id);
        }
        let n = q.fetch_one(&mut *conn).await?;
        if n > 0 {
            out.push(says.replace("{}", &n.to_string()));
        }
    }
    Ok(out)
}

/// The schema's foreign keys between its own tables.
async fn foreign_keys(conn: &mut MySqlConnection) -> AuthResult<Vec<Fk>> {
    let rows = sqlx::query(
        "SELECT CAST(k.TABLE_NAME AS CHAR) AS C, CAST(k.COLUMN_NAME AS CHAR) AS COL, \
         CAST(k.REFERENCED_TABLE_NAME AS CHAR) AS P, CAST(k.REFERENCED_COLUMN_NAME AS CHAR) AS REF, \
         CAST(r.DELETE_RULE AS CHAR) AS RULE \
         FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r \
         ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME \
         WHERE k.TABLE_SCHEMA = DATABASE() AND k.REFERENCED_TABLE_SCHEMA = DATABASE()",
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(Fk {
            child: r.try_get("C")?,
            column: r.try_get("COL")?,
            parent: r.try_get("P")?,
            referenced: r.try_get("REF")?,
            rule: r.try_get("RULE")?,
        });
    }
    Ok(out)
}

/// The keys a walk follows out of `parent`: all but `SET NULL`, which MySQL clears itself.
fn walked<'a>(fks: &'a [Fk], parent: &'a str) -> impl Iterator<Item = &'a Fk> + 'a {
    fks.iter().filter(move |f| f.parent == parent && !f.rule.eq_ignore_ascii_case("SET NULL"))
}

/// Every row that points, directly or through other rows, at the root rows.
async fn closure(conn: &mut MySqlConnection, fks: &[Fk], root: &str, ids: &[u64]) -> AuthResult<Found> {
    let mut found = Found::new();
    found.entry(root.to_string()).or_default().extend(ids.iter().map(|i| (*i, 0)));
    let mut frontier: Vec<(String, Vec<u64>, u32)> = vec![(root.to_string(), ids.to_vec(), 0)];
    while let Some((table, ids, depth)) = frontier.pop() {
        if depth >= MAX_DEPTH {
            return Err(AuthError::internal(format!("purge walk passed depth {MAX_DEPTH} at {table}: a cycle of rows?")));
        }
        for fk in walked(fks, &table) {
            let children = child_ids(conn, fk, &ids).await?;
            let deeper = remember(&mut found, &fk.child, children, depth + 1);
            if !deeper.is_empty() {
                frontier.push((fk.child.clone(), deeper, depth + 1));
            }
        }
    }
    Ok(found)
}

/// Records `ids` of `table` at `depth`; returns the ones that are new or now found deeper (their
/// own children have to be walked again so they stay deeper still).
fn remember(found: &mut Found, table: &str, ids: Vec<u64>, depth: u32) -> Vec<u64> {
    let seen = found.entry(table.to_string()).or_default();
    let mut deeper = Vec::new();
    for id in ids {
        match seen.get(&id) {
            Some(&d) if d >= depth => {}
            _ => {
                seen.insert(id, depth);
                deeper.push(id);
            }
        }
    }
    deeper
}

/// The ids of `fk.child` rows pointing at the given `fk.parent` rows.
async fn child_ids(conn: &mut MySqlConnection, fk: &Fk, parent_ids: &[u64]) -> AuthResult<Vec<u64>> {
    let mut out = Vec::new();
    if fk.referenced == "ID" {
        for chunk in parent_ids.chunks(CHUNK) {
            let sql = format!("SELECT ID FROM `{}` WHERE `{}` IN ({})", fk.child, fk.column, marks(chunk.len()));
            let mut q = sqlx::query_scalar::<_, u64>(&sql);
            for id in chunk {
                q = q.bind(*id);
            }
            out.extend(q.fetch_all(&mut *conn).await?);
        }
        return Ok(out);
    }
    // A key on another column (security_client_url.APP_CODE -> security_app.APP_CODE): the
    // parents' values first.
    let mut values: Vec<String> = Vec::new();
    for chunk in parent_ids.chunks(CHUNK) {
        let sql = format!("SELECT CAST(`{}` AS CHAR) FROM `{}` WHERE ID IN ({})", fk.referenced, fk.parent, marks(chunk.len()));
        let mut q = sqlx::query_scalar::<_, Option<String>>(&sql);
        for id in chunk {
            q = q.bind(*id);
        }
        values.extend(q.fetch_all(&mut *conn).await?.into_iter().flatten());
    }
    for chunk in values.chunks(CHUNK) {
        let sql = format!("SELECT ID FROM `{}` WHERE `{}` IN ({})", fk.child, fk.column, marks(chunk.len()));
        let mut q = sqlx::query_scalar::<_, u64>(&sql);
        for v in chunk {
            q = q.bind(v.as_str());
        }
        out.extend(q.fetch_all(&mut *conn).await?);
    }
    Ok(out)
}

fn marks(n: usize) -> String {
    vec!["?"; n].join(", ")
}

/// Entity rows in the walk that belong to another client or app, per table.
async fn foreign_entities(conn: &mut MySqlConnection, kind: Kind, id: u64, found: &Found) -> AuthResult<BTreeMap<String, usize>> {
    let mut out = BTreeMap::new();
    for (table, rows) in found {
        let Some(owner) = kind.owner_column(table) else { continue };
        let ids: Vec<u64> = rows.keys().copied().collect();
        let mut n = 0usize;
        for chunk in ids.chunks(CHUNK) {
            let sql = format!(
                "SELECT COUNT(*) FROM `{table}` WHERE ID IN ({}) AND NOT ({owner} <=> ?)",
                marks(chunk.len())
            );
            let mut q = sqlx::query_scalar::<_, i64>(&sql);
            for i in chunk {
                q = q.bind(*i);
            }
            n += q.bind(id).fetch_one(&mut *conn).await? as usize;
        }
        if n > 0 {
            out.insert(table.clone(), n);
        }
    }
    Ok(out)
}

/// The order rows go in: deepest first, so no RESTRICT key is ever left pointing at a deleted row.
fn delete_plan(found: &Found) -> Vec<(u32, String, Vec<u64>)> {
    let mut by_depth: BTreeMap<(u32, String), Vec<u64>> = BTreeMap::new();
    for (table, rows) in found {
        for (id, depth) in rows {
            by_depth.entry((*depth, table.clone())).or_default().push(*id);
        }
    }
    let mut plan: Vec<(u32, String, Vec<u64>)> = by_depth.into_iter().map(|((d, t), mut ids)| {
        ids.sort_unstable();
        (d, t, ids)
    }).collect();
    plan.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    plan
}

async fn delete_found(conn: &mut MySqlConnection, found: &Found) -> AuthResult<()> {
    for (_, table, ids) in delete_plan(found) {
        for chunk in ids.chunks(CHUNK) {
            let sql = format!("DELETE FROM `{table}` WHERE ID IN ({})", marks(chunk.len()));
            let mut q = sqlx::query(&sql);
            for id in chunk {
                q = q.bind(*id);
            }
            q.execute(&mut *conn).await?;
        }
    }
    Ok(())
}

/// Every cache a purged client, user, app or profile can sit in, here and in the other units.
async fn evict(s: &AdminState, kind: Kind, id: u64, code: &str, profiles: &[u64]) {
    let svc = &s.caches().service;
    for name in [
        crate::caches::TOKEN,
        crate::caches::USER,
        crate::caches::USER_ROLES,
        crate::caches::CLIENT_TYPE_CODE_LEVEL,
        crate::caches::MANAGED_CLIENT,
        crate::caches::CLIENT_MANAGER,
        crate::caches::USER_SUB_ORG,
        crate::caches::DESIGNATION,
        crate::caches::DEPARTMENT,
        crate::caches::BILLING_CONFIG_BY_CODES,
        crate::caches::WALLET_STATUS,
        cache::CLIENT_HIERARCHY,
        cache::CLIENT_URI,
        cache::CLIENT_URL,
        cache::GATEWAY_URL_CLIENT_APP_CODE,
        cache::APP_READ_ACCESS,
        cache::APP_WRITE_ACCESS,
        cache::APP_INHERITANCE,
        cache::INHERITANCE_ORDER,
        cache::APP_DEPENDENCIES,
        cache::APP_DEP_LIST,
    ] {
        svc.evict_all_everywhere(name).await;
    }
    match kind {
        Kind::Client => {
            svc.evict_everywhere(cache::CLIENT_CODE, code).await;
            svc.evict_everywhere(cache::CLIENT_ID, &id.to_string()).await;
        }
        Kind::App => {
            for name in [cache::APP_BY_CODE, cache::APP_BY_CODE_EXPLICIT, cache::APP_STATUS] {
                svc.evict_everywhere(name, code).await;
            }
            svc.evict_everywhere(cache::APP_BY_ID, &id.to_string()).await;
        }
    }
    for p in profiles {
        svc.evict_all_everywhere(&format!("{}{p}", crate::caches::PROFILE_AUTHS_PREFIX)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fk(child: &str, column: &str, parent: &str, rule: &str) -> Fk {
        Fk { child: child.into(), column: column.into(), parent: parent.into(), referenced: "ID".into(), rule: rule.into() }
    }

    #[test]
    fn set_null_keys_are_not_walked() {
        let fks = vec![
            fk("security_user", "CLIENT_ID", "security_client", "RESTRICT"),
            fk("security_user", "REPORTING_TO", "security_user", "SET NULL"),
            fk("security_user_token", "USER_ID", "security_user", "CASCADE"),
        ];
        let from_user: Vec<&str> = walked(&fks, "security_user").map(|f| f.child.as_str()).collect();
        assert_eq!(from_user, vec!["security_user_token"]);
        let from_client: Vec<&str> = walked(&fks, "security_client").map(|f| f.child.as_str()).collect();
        assert_eq!(from_client, vec!["security_user"]);
    }

    #[test]
    fn a_row_found_again_deeper_is_walked_again() {
        let mut found = Found::new();
        assert_eq!(remember(&mut found, "t", vec![1, 2], 1), vec![1, 2]);
        assert!(remember(&mut found, "t", vec![1], 1).is_empty(), "same depth: nothing new");
        assert!(remember(&mut found, "t", vec![2], 0).is_empty(), "shallower: kept deeper");
        assert_eq!(remember(&mut found, "t", vec![2, 3], 2), vec![2, 3]);
        assert_eq!(found["t"][&2], 2);
    }

    #[test]
    fn deepest_rows_go_first_and_self_references_by_row() {
        let mut found = Found::new();
        found.entry("security_client".into()).or_default().insert(7, 0);
        found.entry("security_user".into()).or_default().insert(70, 1);
        // A root profile (depth 1) and a profile that points at it (depth 2): same table, two steps.
        found.entry("security_profile".into()).or_default().extend([(5, 1), (6, 2)]);
        found.entry("security_profile_user".into()).or_default().insert(9, 2);
        let plan: Vec<(u32, String, Vec<u64>)> = delete_plan(&found);
        let order: Vec<(u32, &str)> = plan.iter().map(|(d, t, _)| (*d, t.as_str())).collect();
        assert_eq!(
            order,
            vec![(2, "security_profile"), (2, "security_profile_user"), (1, "security_profile"), (1, "security_user"), (0, "security_client")]
        );
        assert_eq!(plan[0].2, vec![6]);
        assert_eq!(plan[2].2, vec![5]);
    }

    #[test]
    fn ownership_columns() {
        assert_eq!(Kind::Client.owner_column("security_client"), Some("ID"));
        assert_eq!(Kind::Client.owner_column("security_profile"), Some("CLIENT_ID"));
        assert_eq!(Kind::Client.owner_column("security_user_token"), None, "link rows go with their parent");
        assert_eq!(Kind::App.owner_column("security_profile"), Some("APP_ID"));
        assert_eq!(Kind::App.owner_column("security_user"), Some("NULL"), "an app purge owns no user");
        assert_eq!(Kind::App.owner_column("security_app_access"), None);
    }

    #[test]
    fn placeholders() {
        assert_eq!(marks(3), "?, ?, ?");
        assert_eq!(marks(1), "?");
    }
}
