//! `ClientUrlController` and `ClientUrlService`: a client's hostnames for an app, the app's draft
//! hostname, and the per-session draft-edit grants.
//!
//! | Route | Who |
//! |---|---|
//! | `GET`/`POST clienturls`, `POST clienturls/query`, `GET`/`DELETE clienturls/{id}` | `Client_UPDATE`, a managed client |
//! | `GET clienturls/fetchUrls`, `GET clienturls/urls` | signed in (`urls`: read access to the app) |
//! | `GET`/`POST clienturls/draft`, `POST clienturls/draft/token`, `.../token/extend` | signed in, write access to the app (SYSTEM always) |
//!
//! Every write to the table evicts what Java evicts: `clientUrl`, `uri`,
//! `gatewayClientAppCodeType` and the two certificate caches.

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use chrono::{Duration, NaiveDateTime};
use rand::RngCore;
use serde_json::{json, Value};

use super::cloudflare::CustomHostnames;
use crate::web::page_of;
use super::common::{bare, blank, cache, err, no_content, object_body, pre_authorize, Kind};
use super::common::{FORBIDDEN_WRITE_APPLICATION_ACCESS, MANDATORY_APP_CODE, OBJECT_NOT_FOUND, URL_IS_APP_SUBDOMAIN};
use super::entity::{self, col, extra, Col, Entity, Row, CREATED_AT, CREATED_BY, ID, UPDATED_AT, UPDATED_BY};
use crate::admin::AdminState;
use crate::condition::{ColType, Table};
use crate::errors::{AuthError, AuthResult};
use crate::jackson::{json as json_resp, Obj};
use crate::model::ContextAuth;
use crate::spring::Pageable;
use crate::web::{query_body, req_str, to_u64};
use crate::{web_route, web_route_path};

pub const URL_TYPES: &[&str] = &["LIVE", "DRAFT"];

static COLS: [Col; 11] = [
    ID,
    CREATED_AT,
    CREATED_BY,
    UPDATED_AT,
    UPDATED_BY,
    col("clientId", "CLIENT_ID", Kind::U64, true),
    col("urlPattern", "URL_PATTERN", Kind::Str, true),
    col("appCode", "APP_CODE", Kind::Str, true),
    col("urlType", "URL_TYPE", Kind::Enum(URL_TYPES), true),
    extra("clientCode", Kind::Str),
    extra("clientName", Kind::Str),
];

/// The `ClientUrl` DTO over `security_client_url` (`ClientUrlDAO` is a client-check DAO).
pub static CLIENT_URL: Entity = Entity {
    pojo: "ClientUrl",
    table: "security_client_url",
    cols: &COLS,
    setters: &[
        ("clientId", "clientId"),
        ("urlPattern", "urlPattern"),
        ("appCode", "appCode"),
        ("urlType", "urlType"),
        ("clientCode", "clientCode"),
        ("clientName", "clientName"),
    ],
    aliases: &[],
    filter: Table {
        name: "security_client_url",
        columns: &[
            ("ID", ColType::Num),
            ("CLIENT_ID", ColType::Num),
            ("URL_PATTERN", ColType::Str),
            ("APP_CODE", ColType::Str),
            ("URL_TYPE", ColType::Enum),
            ("CREATED_BY", ColType::Num),
            ("CREATED_AT", ColType::Ts),
            ("UPDATED_BY", ColType::Num),
            ("UPDATED_AT", ColType::Ts),
        ],
    },
    client_column: Some("CLIENT_ID"),
};

/// `ClientUrl`'s field initializer: `urlType = LIVE`.
pub fn initial() -> Row {
    json!({"urlType": "LIVE"}).as_object().cloned().unwrap_or_default()
}

/// Draft hosts live under the platform's own domain, whatever the app's live domain is.
const DRAFT_HOST_BASE_DOMAIN: &str = ".modlix.com";
/// `security.draftToken.expiryMinutes`' default (not in this unit's configuration).
pub const DRAFT_TOKEN_EXPIRY_MINUTES: i64 = 30;

/// `ClientUrlService.trimBackSlash`, including its reach into the untrimmed string.
pub fn trim_back_slash(s: &str) -> AuthResult<String> {
    if s.trim().is_empty() {
        return Ok(s.to_string());
    }
    let n: Vec<char> = s.trim().chars().collect();
    if n.last() != Some(&'/') {
        return Ok(n.iter().collect());
    }
    let orig: Vec<char> = s.chars().collect();
    let mut end = orig.len() as isize - 1;
    while end >= 0 && orig[end as usize] == '/' {
        end -= 1;
    }
    let to = (end + 1) as usize;
    if to > n.len() {
        return Err(AuthError::internal(format!("begin 0, end {to}, length {}", n.len())));
    }
    Ok(n[..to].iter().collect())
}

/// `ClientUrlPattern.hostOf(pattern)`: the host the resolver's regex finds, lower case.
pub fn host_of(pattern: Option<&str>) -> String {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let Some(p) = pattern.filter(|p| !p.trim().is_empty()) else { return String::new() };
    let re = RE.get_or_init(|| regex::Regex::new(r"(http://|https://)?([^:]+)(:(\d{0,5}))?").expect("static regex"));
    re.captures(&p.trim().to_lowercase()).and_then(|c| c.get(2).map(|m| m.as_str().to_string())).unwrap_or_default()
}

/// 128 bits of the OS's randomness as 32 lower-case hex characters.
pub fn random_hex() -> String {
    let mut raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

/// `newDraftHost()`: `d<32 hex><appCodeSuffix>.modlix.com`.
pub fn new_draft_host(suffix: &str) -> String {
    format!("d{}{suffix}{DRAFT_HOST_BASE_DOMAIN}", random_hex())
}

/// `draftTokenHost(token)`: `t-<token><appCodeSuffix>.modlix.com`.
pub fn draft_token_host(token: &str, suffix: &str) -> String {
    format!("t-{token}{suffix}{DRAFT_HOST_BASE_DOMAIN}")
}

/// `DraftTokenResponse`.
pub fn draft_token_json(token: &str, suffix: &str, expires_at: NaiveDateTime) -> Value {
    Obj::new()
        .put("token", token)
        .put("host", draft_token_host(token, suffix))
        .put("expiresAt", expires_at.and_utc().timestamp())
        .build()
}

/// The Cloudflare client this unit runs with: unconfigured until its configuration carries a
/// token and a zone (see the piece's report).
pub fn cloudflare() -> CustomHostnames {
    CustomHostnames::unconfigured()
}

/// `syncToCloudflare(entity, add)`: LIVE rows only, and only when configured.
async fn sync_to_cloudflare(cf: &CustomHostnames, row: &Row, add: bool) {
    if entity::str_of(row, "urlType") != Some("LIVE") || !cf.is_configured() {
        return;
    }
    let host = host_of(entity::str_of(row, "urlPattern"));
    if host.trim().is_empty() {
        return;
    }
    if add {
        cf.add_hostname(&host).await;
    } else {
        cf.remove_hostname(&host).await;
    }
}

/// The evictions every write to the table makes.
pub async fn evict_url_caches(s: &AdminState) {
    let svc = &s.caches().service;
    for name in [cache::CLIENT_URL, cache::CLIENT_URI, cache::GATEWAY_URL_CLIENT_APP_CODE, cache::CERTIFICATE, cache::CERTIFICATE_LAST_UPDATED] {
        svc.evict_all_everywhere(name).await;
    }
}

/// The routing evictions alone (`mintDraftUrl`).
async fn evict_routing_caches(s: &AdminState) {
    let svc = &s.caches().service;
    for name in [cache::CLIENT_URL, cache::CLIENT_URI, cache::GATEWAY_URL_CLIENT_APP_CODE] {
        svc.evict_all_everywhere(name).await;
    }
}

/// `checkNotAnAppSubdomain`: a pattern on an existing app's own platform hostname is refused.
async fn check_not_an_app_subdomain(s: &AdminState, pattern: Option<&str>) -> AuthResult<()> {
    let host = host_of(pattern);
    let Some(code) = s.dir().subdomain_app_code(&host) else { return Ok(()) };
    if let Some(app) = s.dir().app_by_code(&code).await? {
        return Err(err(StatusCode::CONFLICT, URL_IS_APP_SUBDOMAIN, &[&host, &app.app_code])
            .with_param("app", app.app_name.as_deref().unwrap_or(&app.app_code)));
    }
    Ok(())
}

/// The caller may act on a URL of `client_id`: SYSTEM, its own client, or one it manages.
async fn may_access(s: &AdminState, ca: &ContextAuth, client_id: Option<u64>) -> AuthResult<bool> {
    if ca.is_system_client() || client_id == Some(ca.user.client_id()) {
        return Ok(true);
    }
    s.caller_manages_client(ca, client_id.unwrap_or(0)).await
}

/// `ClientUrlService.read(id)`: the DAO's 404, then the service's 404 for a URL not reachable.
pub async fn read(s: &AdminState, ca: &ContextAuth, id: u64) -> AuthResult<Row> {
    let r = entity::read_by_id(&s.db, &CLIENT_URL, id).await?;
    if may_access(s, ca, entity::u64_of(&r, "clientId")).await? {
        return Ok(r);
    }
    Err(err(StatusCode::NOT_FOUND, OBJECT_NOT_FOUND, &["Client URL", &id.to_string()]))
}

/// `ClientUrlService.create(entity)`: `None` when the caller may not use the client (Java's
/// empty answer).
pub async fn create(s: &AdminState, ca: &ContextAuth, mut entity: Row) -> AuthResult<Option<Row>> {
    if let Some(p) = entity::str_of(&entity, "urlPattern").map(str::to_string) {
        entity.insert("urlPattern".into(), Value::from(trim_back_slash(&p)?));
    }
    check_not_an_app_subdomain(s, entity::str_of(&entity, "urlPattern")).await?;
    let client_id = entity::u64_of(&entity, "clientId");
    if client_id.is_some() && !may_access(s, ca, client_id).await? {
        return Ok(None);
    }
    if client_id.is_none() {
        entity.insert("clientId".into(), Value::from(ca.user.client_id()));
    }
    entity.insert("createdBy".into(), Value::from(ca.user.id()));
    let id = entity::insert(&s.db, &CLIENT_URL, &entity).await?;
    let created = entity::read_by_id(&s.db, &CLIENT_URL, id).await?;
    sync_to_cloudflare(&cloudflare(), &created, true).await;
    evict_url_caches(s).await;
    Ok(Some(created))
}

/// `ClientUrlService.createForRegistration(entity)`: the registration's own URL, no caller check
/// (`CREATED_BY` is the caller's id, 0 for an anonymous sign-up).
pub async fn create_for_registration(s: &AdminState, ca: &ContextAuth, mut entity: Row) -> AuthResult<Row> {
    if let Some(p) = entity::str_of(&entity, "urlPattern").map(str::to_string) {
        entity.insert("urlPattern".into(), Value::from(trim_back_slash(&p)?));
    }
    check_not_an_app_subdomain(s, entity::str_of(&entity, "urlPattern")).await?;
    entity.insert("createdBy".into(), Value::from(ca.user.id()));
    let id = entity::insert(&s.db, &CLIENT_URL, &entity).await?;
    let created = entity::read_by_id(&s.db, &CLIENT_URL, id).await?;
    evict_url_caches(s).await;
    Ok(created)
}

/// `ClientUrlService.delete(id)`.
pub async fn delete(s: &AdminState, ca: &ContextAuth, id: u64) -> AuthResult<u64> {
    let r = read(s, ca, id).await?;
    let n = entity::delete(&s.db, &CLIENT_URL, id).await?;
    sync_to_cloudflare(&cloudflare(), &r, false).await;
    evict_url_caches(s).await;
    Ok(n)
}

/// `readPageFilter`: the client-check restriction, then the page.
pub async fn page(s: &AdminState, ca: &ContextAuth, pageable: &Pageable, cond: Option<&crate::condition::Cond>) -> AuthResult<Value> {
    let sql = cond.map(|c| crate::condition::to_sql(c, &CLIENT_URL.filter)).transpose()?.flatten();
    let (rows, count) = entity::page(&s.db, &CLIENT_URL, crate::data::crud::client_check(ca), sql, pageable).await?;
    Ok(page_of(rows.iter().map(|r| CLIENT_URL.to_json(r, vec![])).collect(), pageable, count))
}

/// `getUrlsBasedOnApp(appCode, suffix)`: the LIVE patterns (the caller's client's unless
/// SYSTEM), plus the app's own address when a suffix is given; `None` for an unknown app.
pub async fn urls_of_app(s: &AdminState, ca: &ContextAuth, app_code: &str, suffix: Option<&str>) -> AuthResult<Option<Vec<String>>> {
    if app_code.trim().is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, MANDATORY_APP_CODE, &[]));
    }
    let client_id = ca.user.client_id();
    let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new("SELECT URL_PATTERN FROM security_client_url WHERE (APP_CODE = ");
    qb.push_bind(app_code.to_string()).push(" AND URL_TYPE = 'LIVE'");
    if !ca.is_system_client() {
        qb.push(" AND CLIENT_ID = ").push_bind(client_id);
    }
    qb.push(")");
    let mut urls: Vec<String> = qb.build_query_scalar().fetch_all(&s.db.pool).await?;
    let Some(app) = s.dir().app_by_code(app_code).await? else { return Ok(None) };
    if let Some(sfx) = suffix.filter(|x| !x.trim().is_empty()) {
        let env = &s.auth.settings.app_code_suffix;
        if app.client_id == client_id {
            urls.push(format!("https://{app_code}{env}{sfx}/"));
        } else {
            urls.push(format!("https://{app_code}{env}{sfx}/{}/page/", ca.client_code.clone().unwrap_or_else(|| "null".into())));
        }
    }
    Ok(Some(urls))
}

/// `%` and `_` (and the escape itself) taken literally under `ESCAPE '!'`.
fn like_literal(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    out.push('%');
    for c in v.chars() {
        if matches!(c, '!' | '%' | '_') {
            out.push('!');
        }
        out.push(c);
    }
    out.push('%');
    out
}

/// `ClientUrlDAO.getClientUrls`: an app's LIVE URLs labelled with their client, in a fixed order.
async fn client_urls_rows(
    s: &AdminState,
    app_code: &str,
    client_code: Option<&str>,
    restrict_to: Option<u64>,
    url_pattern: Option<&str>,
    client_name: Option<&str>,
    pageable: &Pageable,
) -> AuthResult<(Vec<Row>, i64)> {
    let build = |select: &str| {
        let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new(format!(
            "SELECT {select} FROM security_client_url LEFT JOIN security_client ON security_client.ID = security_client_url.CLIENT_ID \
             WHERE (security_client_url.APP_CODE = "
        ));
        qb.push_bind(app_code.to_string()).push(" AND security_client_url.URL_TYPE = 'LIVE'");
        if let Some(c) = client_code.filter(|c| !c.trim().is_empty()) {
            qb.push(" AND security_client.CODE = ").push_bind(c.to_string());
        }
        if let Some(p) = url_pattern.filter(|p| !p.trim().is_empty()) {
            qb.push(" AND security_client_url.URL_PATTERN LIKE ").push_bind(like_literal(p)).push(" ESCAPE '!'");
        }
        if let Some(n) = client_name.filter(|n| !n.trim().is_empty()) {
            qb.push(" AND security_client.NAME LIKE ").push_bind(like_literal(n)).push(" ESCAPE '!'");
        }
        if let Some(id) = restrict_to {
            qb.push(format!(
                " AND security_client_url.CLIENT_ID IN (SELECT security_client_hierarchy.CLIENT_ID FROM security_client_hierarchy WHERE {})",
                crate::data::manage_client_condition(id)
            ));
        }
        qb.push(")");
        qb
    };
    let mut qb = build(&format!("{}, security_client.CODE AS client_code, security_client.NAME AS client_name", CLIENT_URL.select_list()));
    qb.push(" ORDER BY security_client.NAME ASC, security_client_url.URL_PATTERN ASC, security_client_url.ID ASC LIMIT ")
        .push_bind(pageable.size)
        .push(" OFFSET ")
        .push_bind(pageable.offset());
    let rows = qb.build().fetch_all(&s.db.pool).await?;
    let count: i64 = build("COUNT(*)").build_query_scalar().fetch_one(&s.db.pool).await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let mut row = CLIENT_URL.read_row(r)?;
        row.insert("clientCode".into(), entity::read_value(r, "client_code", Kind::Str)?);
        row.insert("clientName".into(), entity::read_value(r, "client_name", Kind::Str)?);
        out.push(row);
    }
    Ok((out, count))
}

/// `getClientUrls(appCode, clientCode, urlPattern, clientName, pageable)`.
pub async fn client_urls(
    s: &AdminState,
    ca: &ContextAuth,
    app_code: &str,
    client_code: Option<&str>,
    url_pattern: Option<&str>,
    client_name: Option<&str>,
    pageable: &Pageable,
) -> AuthResult<Value> {
    let refused = || err(StatusCode::FORBIDDEN, FORBIDDEN_WRITE_APPLICATION_ACCESS, &[]);
    let all_clients = blank(client_code);
    if !s.dir().has_read_access(app_code, ca.client_code.as_deref()).await? {
        return Err(refused());
    }
    if !all_clients {
        let managed = match s.client_by_code(client_code.unwrap_or("")).await? {
            Some(c) => s.caller_manages_client(ca, c.id()).await?,
            None => false,
        };
        if !managed {
            return Err(refused());
        }
    }
    let restrict = (all_clients && !ca.is_system_client()).then(|| ca.user.client_id());
    let (rows, count) = client_urls_rows(s, app_code, client_code, restrict, url_pattern, client_name, pageable).await?;
    Ok(page_of(rows.iter().map(|r| CLIENT_URL.to_json(r, vec![])).collect(), pageable, count))
}

/// The draft routes' gate: SYSTEM, or write access to the app; then the caller's client.
async fn draft_client(s: &AdminState, ca: &ContextAuth, app_code: &str) -> AuthResult<Option<u64>> {
    let allowed = ca.is_system_client() || s.db.has_write_access(app_code, ca.client_code.as_deref().unwrap_or("")).await?;
    if !allowed {
        return Ok(None);
    }
    Ok(match ca.client_code.as_deref() {
        Some(code) => s.client_by_code(code).await?.map(|c| c.id()),
        None => None,
    })
}

/// `ClientUrlDAO.getDraftUrl(appCode, clientId)`.
async fn draft_row(s: &AdminState, app_code: &str, client_id: u64) -> AuthResult<Option<Row>> {
    let sql = format!(
        "SELECT {} FROM security_client_url WHERE (APP_CODE = ? AND CLIENT_ID = ? AND URL_TYPE = 'DRAFT') LIMIT 1",
        CLIENT_URL.select_list()
    );
    let r = sqlx::query(&sql).bind(app_code).bind(client_id).fetch_optional(&s.db.pool).await?;
    r.as_ref().map(|r| CLIENT_URL.read_row(r)).transpose()
}

/// `getDraftUrl(appCode)`.
pub async fn draft_url(s: &AdminState, ca: &ContextAuth, app_code: &str) -> AuthResult<Option<Row>> {
    let Some(client) = draft_client(s, ca, app_code).await? else { return Ok(None) };
    draft_row(s, app_code, client).await
}

/// `mintDraftUrl(appCode)`: the app's draft hostname, rotated when one exists.
pub async fn mint_draft_url(s: &AdminState, ca: &ContextAuth, app_code: &str) -> AuthResult<Row> {
    let Some(client) = draft_client(s, ca, app_code).await? else {
        return Err(err(StatusCode::FORBIDDEN, FORBIDDEN_WRITE_APPLICATION_ACCESS, &[]));
    };
    let host = new_draft_host(&s.auth.settings.app_code_suffix);
    let saved = match draft_row(s, app_code, client).await? {
        Some(mut existing) => {
            // `super.update` through `updatableEntity`: the stored row with the new pattern.
            let id = entity::u64_of(&existing, "id").unwrap_or(0);
            let mut stored = read(s, ca, id).await?;
            stored.insert("urlPattern".into(), Value::from(host));
            stored.insert("updatedBy".into(), Value::from(ca.user.id()));
            entity::update(&s.db, &CLIENT_URL, &stored).await?;
            existing = entity::read_by_id(&s.db, &CLIENT_URL, id).await?;
            existing
        }
        None => {
            let fresh = json!({"clientId": client, "appCode": app_code, "urlPattern": host, "urlType": "DRAFT", "createdBy": ca.user.id()});
            let id = entity::insert(&s.db, &CLIENT_URL, fresh.as_object().unwrap_or(&Row::new())).await?;
            entity::read_by_id(&s.db, &CLIENT_URL, id).await?
        }
    };
    evict_routing_caches(s).await;
    Ok(saved)
}

/// `mintDraftToken(appCode)`: the caller's live grant pushed forward, or a new one.
pub async fn mint_draft_token(s: &AdminState, ca: &ContextAuth, app_code: &str) -> AuthResult<Value> {
    let Some(client) = draft_client(s, ca, app_code).await? else {
        return Err(err(StatusCode::FORBIDDEN, FORBIDDEN_WRITE_APPLICATION_ACCESS, &[]));
    };
    let now = s.auth.clock.utc();
    let expires_at = now + Duration::minutes(DRAFT_TOKEN_EXPIRY_MINUTES);
    let user = ca.user.id();
    let live: Option<String> = sqlx::query_scalar(
        "SELECT TOKEN FROM security_draft_token WHERE (USER_ID = ? AND APP_CODE = ? AND CLIENT_ID = ? AND EXPIRES_AT > ?) \
         ORDER BY EXPIRES_AT DESC LIMIT 1",
    )
    .bind(user)
    .bind(app_code)
    .bind(client)
    .bind(now)
    .fetch_optional(&s.db.pool)
    .await?;
    let token = match live {
        Some(t) => {
            extend(s, &t, user, expires_at).await?;
            t
        }
        None => {
            let t = random_hex();
            sqlx::query(
                "INSERT INTO security_draft_token (TOKEN, APP_CODE, CLIENT_ID, USER_ID, EXPIRES_AT, CREATED_BY) VALUES (?, ?, ?, ?, ?, NULL)",
            )
            .bind(&t)
            .bind(app_code)
            .bind(client)
            .bind(user)
            .bind(expires_at)
            .execute(&s.db.pool)
            .await?;
            t
        }
    };
    Ok(draft_token_json(&token, &s.auth.settings.app_code_suffix, expires_at))
}

async fn extend(s: &AdminState, token: &str, user: u64, expires_at: NaiveDateTime) -> AuthResult<u64> {
    Ok(sqlx::query("UPDATE security_draft_token SET EXPIRES_AT = ? WHERE (TOKEN = ? AND USER_ID = ?)")
        .bind(expires_at)
        .bind(token)
        .bind(user)
        .execute(&s.db.pool)
        .await?
        .rows_affected())
}

/// `extendDraftToken(token)`: only the minting user's own grant.
pub async fn extend_draft_token(s: &AdminState, ca: &ContextAuth, token: &str) -> AuthResult<Value> {
    let refused = || err(StatusCode::FORBIDDEN, FORBIDDEN_WRITE_APPLICATION_ACCESS, &[]);
    let row: Option<(String, u64)> = sqlx::query_as("SELECT TOKEN, USER_ID FROM security_draft_token WHERE TOKEN = ? LIMIT 1")
        .bind(token)
        .fetch_optional(&s.db.pool)
        .await?;
    let Some((token, user_id)) = row else {
        return Err(refused());
    };
    if user_id != ca.user.id() {
        return Err(refused());
    }
    let expires_at = s.auth.clock.utc() + Duration::minutes(DRAFT_TOKEN_EXPIRY_MINUTES);
    extend(s, &token, user_id, expires_at).await?;
    Ok(draft_token_json(&token, &s.auth.settings.app_code_suffix, expires_at))
}

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/clienturls", get(read_page).post(create_route))
        .route("/api/security/clienturls/query", post(query))
        .route("/api/security/clienturls/fetchUrls", get(fetch_urls))
        .route("/api/security/clienturls/urls", get(urls_route))
        .route("/api/security/clienturls/draft", get(get_draft).post(post_draft))
        .route("/api/security/clienturls/draft/token", post(post_draft_token))
        .route("/api/security/clienturls/draft/token/extend", post(post_draft_token_extend))
        .route("/api/security/clienturls/{id}", get(read_route).delete(delete_route))
}

web_route!(read_page, AdminState, "/clienturls", true, |s, r, ca| {
    let pageable = Pageable::from_params(&r.params);
    let cond = crate::condition::from_params(&r.params.0);
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    Ok(json_resp(&page(&s, &ca, &pageable, cond.as_ref()).await?))
});

web_route!(query, AdminState, "/clienturls/query", true, |s, r, ca| {
    let (pageable, cond) = query_body(&r.body)?;
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    Ok(json_resp(&page(&s, &ca, &pageable, cond.as_ref()).await?))
});

web_route!(create_route, AdminState, "/clienturls", true, |s, r, ca| {
    let body = object_body(&r.body)?;
    let entity = CLIENT_URL.from_body(&body, initial())?;
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    Ok(match create(&s, &ca, entity).await? {
        Some(row) => json_resp(&CLIENT_URL.to_json(&row, vec![])),
        None => crate::web::nothing(),
    })
});

web_route_path!(read_route, AdminState, "/clienturls/{id}", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    Ok(json_resp(&CLIENT_URL.to_json(&read(&s, &ca, id).await?, vec![])))
});

web_route_path!(delete_route, AdminState, "/clienturls/{id}", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    delete(&s, &ca, id).await?;
    Ok(no_content())
});

web_route!(fetch_urls, AdminState, "/clienturls/fetchUrls", true, |s, r, ca| {
    let app = req_str(&r.params, "appCode")?;
    Ok(match urls_of_app(&s, &ca, app, r.params.get("suffix")).await? {
        Some(list) => json_resp(&Value::from(list)),
        None => crate::web::nothing(),
    })
});

web_route!(urls_route, AdminState, "/clienturls/urls", true, |s, r, ca| {
    let app = req_str(&r.params, "appCode")?;
    let pageable = Pageable::from_params(&r.params);
    let v = client_urls(&s, &ca, app, r.params.get("clientCode"), r.params.get("urlPattern"), r.params.get("clientName"), &pageable).await?;
    Ok(json_resp(&v))
});

web_route!(get_draft, AdminState, "/clienturls/draft", true, |s, r, ca| {
    let app = req_str(&r.params, "appCode")?;
    Ok(match draft_url(&s, &ca, app).await? {
        Some(row) => json_resp(&CLIENT_URL.to_json(&row, vec![])),
        None => bare(StatusCode::NOT_FOUND),
    })
});

web_route!(post_draft, AdminState, "/clienturls/draft", true, |s, r, ca| {
    let app = req_str(&r.params, "appCode")?;
    Ok(json_resp(&CLIENT_URL.to_json(&mint_draft_url(&s, &ca, app).await?, vec![])))
});

web_route!(post_draft_token, AdminState, "/clienturls/draft/token", true, |s, r, ca| {
    let app = req_str(&r.params, "appCode")?;
    Ok(json_resp(&mint_draft_token(&s, &ca, app).await?))
});

web_route!(post_draft_token_extend, AdminState, "/clienturls/draft/token/extend", true, |s, r, ca| {
    let token = req_str(&r.params, "token")?;
    Ok(json_resp(&extend_draft_token(&s, &ca, token).await?))
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_patterns() {
        assert_eq!(host_of(Some("https://Shop.Example.com:8443")), "shop.example.com");
        assert_eq!(host_of(Some("kk28.dev.modlix.com")), "kk28.dev.modlix.com");
        assert_eq!(host_of(Some(" ")), "");
        assert_eq!(host_of(None), "");
        assert_eq!(host_of(Some(":")), "");
        assert_eq!(trim_back_slash("a.com///").unwrap(), "a.com");
        assert_eq!(trim_back_slash(" a.com/").unwrap(), "a.com/");
        assert_eq!(trim_back_slash(" ").unwrap(), " ");
        assert_eq!(trim_back_slash("a.com").unwrap(), "a.com");
        assert!(trim_back_slash("a.com/ ").is_err());
        assert_eq!(like_literal("a_b%c!"), "%a!_b!%c!!%");
    }

    #[test]
    fn draft_hosts() {
        let h = new_draft_host(".local");
        assert!(h.starts_with('d') && h.ends_with(".local.modlix.com") && h.len() == 1 + 32 + ".local.modlix.com".len());
        assert!(h[1..33].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(draft_token_host("ab", ""), "t-ab.modlix.com");
        let at = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap().naive_utc();
        assert_eq!(draft_token_json("ab", ".local", at), json!({"token": "ab", "host": "t-ab.local.modlix.com", "expiresAt": 1_800_000_000}));
        assert_ne!(random_hex(), random_hex());
        assert!(!cloudflare().is_configured());
    }

    #[test]
    fn url_json_in_dto_order() {
        let r = CLIENT_URL.from_body(&json!({"clientId": 1, "urlPattern": "a.com", "appCode": "x", "clientName": "N"}), initial()).unwrap();
        let v = CLIENT_URL.to_json(&r, vec![]);
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["clientId", "urlPattern", "appCode", "urlType", "clientName"]);
    }

    #[tokio::test]
    async fn live_urls_sync_to_a_configured_cloudflare() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let recorded = calls.clone();
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let recorded = recorded.clone();
            async move {
                recorded.lock().unwrap().push(format!("{} {}", req.method(), req.uri()));
                axum::Json(json!({"success": true, "result": [{"id": "h1"}]}))
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let cf = CustomHostnames::new("t", "zone", super::super::cloudflare::OWN_DOMAINS, &base);
        let live = |p: &str| json!({"urlType": "LIVE", "urlPattern": p}).as_object().cloned().unwrap();
        sync_to_cloudflare(&cf, &live("https://shop.example.test/"), true).await;
        sync_to_cloudflare(&cf, &live("https://shop.example.test"), false).await;
        sync_to_cloudflare(&cf, &live(""), true).await;
        sync_to_cloudflare(&cf, &json!({"urlType": "DRAFT", "urlPattern": "x.test"}).as_object().cloned().unwrap(), true).await;
        sync_to_cloudflare(&CustomHostnames::unconfigured(), &live("x.test"), true).await;
        let seen = calls.lock().unwrap().clone();
        assert!(seen.iter().any(|c| c.starts_with("POST")) && seen.iter().any(|c| c.starts_with("DELETE")), "{seen:?}");
    }
}
