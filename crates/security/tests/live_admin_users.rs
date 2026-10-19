//! security-admin's users, profiles, roles and organisation routes against the local `security`
//! schema, ported from `UserControllerTest`, `ProfileControllerTest`, `RoleV2ControllerTest`,
//! `DesignationControllerTest`, `DepartmentControllerTest`, `ClientManagerControllerTest`,
//! `OtpControllerTest`, `AuthorityExpressionControllerTest` and the service tests behind them
//! (`UserServiceTest`, `UserInviteServiceTest`, `UserRequestServiceTest`, `ProfileServiceTest`,
//! `RoleV2ServiceTest`, `DesignationServiceTest`, `DepartmentServiceTest`, `ClientManagerServiceTest`,
//! `OtpServiceTest`, `UserSubOrganizationServiceTest`), with the expected values read from the same
//! schema.
//!
//! Gated: `SECURITY_AUTH_LIVE=1` with `eval "$(tools/local-env.py)"`. Reads change nothing (an OTP
//! sent to an `example.invalid` address aside). The lifecycle test writes only to objects it
//! makes: two scratch clients (`ZZRUL`, `ZZRUM`; brought back to ACTIVE on later runs, as the API
//! only marks a client DELETED), and in them departments, designations, roles, users, managers,
//! invites, a request, a profile and an override of a SYSTEM root profile it makes too; all are
//! removed again (users and clients marked DELETED). Events are logged, not published; no Redis.

use std::panic::AssertUnwindSafe;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use platform::cache::CacheService;
use platform::config::MySqlConfig;
use serde_json::{json, Value};
use sqlx::{MySqlPool, Row};
use tower::ServiceExt;

use security::config::AuthConfig;

struct Live {
    router: Router,
    pool: MySqlPool,
    /// Holds the MySQL advisory lock the in-crate live tests take too, so no two of them (even
    /// from two processes) run at once: the reads count rows the lifecycle adds and removes, and
    /// both use the same scratch clients.
    _lock: sqlx::MySqlConnection,
}

const LOCK: &str = "security-admin-users-live";

async fn live() -> Option<Live> {
    let (Ok(_), Ok(password), Ok(key)) =
        (std::env::var("SECURITY_AUTH_LIVE"), std::env::var("MODLIX__DATABASE__PASSWORD"), std::env::var("MODLIX__JWT__KEY"))
    else {
        eprintln!("skipped: SECURITY_AUTH_LIVE / MODLIX__DATABASE__PASSWORD / MODLIX__JWT__KEY not set");
        return None;
    };
    let mut cfg = AuthConfig::default();
    cfg.database = MySqlConfig { database: "security".into(), password, max_connections: 4, ..Default::default() };
    cfg.jwt.key = key;
    cfg.security.app_code_suffix = ".local".into();
    cfg.security.subdomain_endings = ".local.modlix.com, .local.sitezump.ai".into();
    cfg.wallet.publish_events = false;
    cfg.events.publish_events = false;
    cfg.otp.publish_events = false;
    let pool = platform::db::mysql_pool(&cfg.database).await.unwrap();
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let state = security::admin::build(&cfg, pool.clone(), cache, None).unwrap();
    let mut lock = pool.acquire().await.unwrap().detach();
    let got: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?, 1800)").bind(LOCK).fetch_one(&mut lock).await.unwrap();
    assert_eq!(got, Some(1), "could not take the live-test lock");
    Some(Live { router: security::admin::router(state), pool, _lock: lock })
}

const P: &str = "/api/security";
const PASSWORD: &str = "Pass@1234";

fn basic(user: u64) -> String {
    use base64::Engine;
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{PASSWORD}")))
}

fn as_user(user: u64, client: &str) -> Vec<(&'static str, String)> {
    vec![("authorization", basic(user)), ("clientcode", client.into()), ("appcode", "appbuilder".into())]
}

/// SYSTEM user 142.
fn sys() -> Vec<(&'static str, String)> {
    as_user(142, "SYSTEM")
}

/// User 110, an Owner of client FIN.
fn owner() -> Vec<(&'static str, String)> {
    as_user(110, "FIN")
}

/// User 8 of FIN: signed in, no authority.
fn plain() -> Vec<(&'static str, String)> {
    as_user(8, "FIN")
}

fn anon(client: &str) -> Vec<(&'static str, String)> {
    vec![("clientcode", client.into()), ("appcode", "appbuilder".into())]
}

struct Resp {
    status: StatusCode,
    body: String,
    content_type: Option<String>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }

    /// Java's text for this error: the coded body's `debugMessage`, without its `[key]`.
    fn message(&self) -> String {
        let d = self.json()["debugMessage"].as_str().unwrap_or("").to_string();
        match d.strip_prefix('[').and_then(|r| r.split_once("] ")) {
            Some((_, rest)) => rest.to_string(),
            None => d,
        }
    }
}

impl Live {
    async fn call(&self, method: &str, path: &str, headers: &[(&str, String)], body: Option<Value>) -> Resp {
        let mut b = Request::builder().method(method).uri(format!("{P}{path}")).header("host", "localhost:8001").header("x-real-ip", "127.0.0.1");
        for (k, v) in headers {
            b = b.header(*k, v);
        }
        let req = match body {
            Some(v) => b.header("content-type", "application/json").body(Body::from(v.to_string())).unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let content_type = resp.headers().get("content-type").map(|v| v.to_str().unwrap().to_string());
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        Resp { status, body: String::from_utf8_lossy(&bytes).into_owned(), content_type }
    }

    async fn ok(&self, method: &str, path: &str, headers: &[(&str, String)], body: Option<Value>) -> Value {
        let r = self.call(method, path, headers, body).await;
        assert_eq!(r.status, StatusCode::OK, "{method} {path}: {}", r.body);
        if r.body.is_empty() {
            Value::Null
        } else {
            r.json()
        }
    }

    async fn status(&self, method: &str, path: &str, headers: &[(&str, String)], body: Option<Value>) -> StatusCode {
        self.call(method, path, headers, body).await.status
    }

    /// A refusal: its status and message.
    async fn refused(&self, method: &str, path: &str, headers: &[(&str, String)], body: Option<Value>) -> (StatusCode, String) {
        let r = self.call(method, path, headers, body).await;
        (r.status, r.message())
    }

    async fn scalar(&self, sql: &str) -> Option<u64> {
        sqlx::query(sql).fetch_optional(&self.pool).await.unwrap().map(|r| r.try_get::<u64, _>(0).unwrap())
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(sql).fetch_one(&self.pool).await.unwrap()
    }
}

/// SYSTEM's constant appbuilder OTP, when its policy has one.
async fn constant_otp(l: &Live) -> Option<String> {
    let v: Option<Option<String>> =
        sqlx::query_scalar("SELECT CONSTANT_VALUE FROM security_client_otp_policy WHERE CLIENT_ID = 1 AND APP_ID = 2 AND IS_CONSTANT = 1")
            .fetch_optional(&l.pool)
            .await
            .unwrap();
    v.flatten().map(|c| c.trim().to_string()).filter(|c| !c.is_empty())
}

#[tokio::test]
async fn organisation_and_roles_read_as_java_does() {
    let Some(l) = live().await else { return };
    // DesignationControllerTest / DepartmentControllerTest: a client-checked page, and the fills.
    let page = l.ok("GET", "/designations?size=5&fetchParentDesignation=true&fetchDepartment=true", &sys(), None).await;
    let total = l.count("SELECT COUNT(*) FROM security_designation").await;
    assert_eq!(page["totalElements"], total);
    assert_eq!(page["pageable"]["pageSize"], 5);
    let mine = l.ok("GET", "/designations?size=200", &owner(), None).await;
    for d in mine["content"].as_array().unwrap() {
        // An owner of FIN sees FIN's and the clients FIN manages.
        assert!(d["clientId"].as_u64().is_some());
    }
    assert_eq!(l.status("GET", "/designations", &plain(), None).await, StatusCode::FORBIDDEN);
    let r = l.call("GET", "/designations", &plain(), None).await;
    assert_eq!((r.json()["code"].as_str(), r.content_type.as_deref()), (Some("COMMON.PERMISSION_REQUIRED"), Some("application/json")));
    assert_eq!(r.message(), "Access Denied: needs Authorities.Client_CREATE or Authorities.Client_UPDATE");
    assert_eq!(l.status("GET", "/designations", &anon("SYSTEM"), None).await, StatusCode::UNAUTHORIZED);
    let missing = l.call("GET", "/designations/999999999", &sys(), None).await;
    assert_eq!((missing.status, missing.message().as_str()), (StatusCode::NOT_FOUND, "Designation with id 999999999 not found"));
    assert_eq!(l.status("GET", "/designations/abc", &sys(), None).await, StatusCode::BAD_REQUEST);
    let q = l.ok("POST", "/departments/query", &sys(), Some(json!({"size": 2, "condition": {"field": "name", "operator": "STRING_LOOSE_EQUAL", "value": "Sales"}}))).await;
    assert!(q["content"].as_array().map_or(true, |c| c.len() <= 2));
    l.ok("GET", "/departments?size=3&fetchParentDepartment=true", &sys(), None).await;

    // RoleV2ControllerTest: the enriched page, a role, its sub-roles, the assignable roles.
    let roles = l.ok("GET", "/rolev2?size=40", &sys(), None).await;
    let with_app = roles["content"].as_array().unwrap().iter().find(|r| r["appId"].is_u64());
    if let Some(r) = with_app {
        assert!(r["appName"].is_string(), "appName carries the app's code: {r}");
    }
    let parent = l.scalar("SELECT ROLE_ID FROM security_v2_role_role GROUP BY ROLE_ID LIMIT 1").await.unwrap();
    let subs = l.ok("GET", &format!("/rolev2/{parent}/subRoles"), &sys(), None).await;
    let n = l.count(&format!("SELECT COUNT(*) FROM security_v2_role_role WHERE ROLE_ID = {parent}")).await;
    assert_eq!(subs.as_array().unwrap().len() as i64, n);
    l.ok("GET", &format!("/rolev2/{parent}"), &sys(), None).await;
    assert_eq!(l.status("GET", "/rolev2/999999999", &sys(), None).await, StatusCode::NOT_FOUND);
    for app in ["appbuilder", "leadzump", "nothing"] {
        let a = l.call("GET", &format!("/rolev2/assignable/{app}"), &owner(), None).await;
        assert!(a.status == StatusCode::OK || a.status == StatusCode::FORBIDDEN, "{app}: {}", a.body);
    }
    let refused = l.call("GET", "/rolev2/assignable/nosuch", &sys(), None).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    l.ok("POST", "/rolev2/query", &sys(), Some(json!({"size": 3}))).await;
}

#[tokio::test]
async fn profiles_read_with_their_roles() {
    let Some(l) = live().await else { return };
    // ProfileControllerTest: a profile's lines carry their role and its names.
    let Some(pid) = l.scalar("SELECT ID FROM security_profile WHERE ROOT_PROFILE_ID IS NULL AND CLIENT_ID = 1 AND ARRANGEMENT LIKE '%roleId%' LIMIT 1").await else {
        return;
    };
    let p = l.ok("GET", &format!("/app/profiles/{pid}"), &sys(), None).await;
    assert_eq!(p["id"], pid);
    let arr = p["arrangement"].as_object().unwrap();
    let line = arr.values().find(|v| v.get("roleId").is_some()).unwrap();
    assert!(line["role"]["id"].is_u64() && line.get("assignable").is_some(), "{line}");
    let app = p["appId"].as_u64().unwrap();
    let page = l.ok("GET", &format!("/app/{app}/profiles?size=100"), &sys(), None).await;
    assert!(page["content"].as_array().unwrap().iter().any(|x| x["id"] == pid));
    assert_eq!(l.status("GET", "/app/profiles/999999999", &sys(), None).await, StatusCode::NOT_FOUND);
    assert_eq!(l.status("GET", "/app/profiles/x", &sys(), None).await, StatusCode::BAD_REQUEST);
    assert_eq!(l.status("GET", &format!("/app/profiles/{pid}"), &plain(), None).await, StatusCode::FORBIDDEN);
    // Every override reads (through its root) for the SYSTEM caller.
    let overrides: Vec<u64> = sqlx::query_scalar("SELECT ID FROM security_profile WHERE ROOT_PROFILE_ID IS NOT NULL").fetch_all(&l.pool).await.unwrap();
    for o in overrides {
        let r = l.call("GET", &format!("/app/profiles/{o}"), &sys(), None).await;
        assert!(r.status == StatusCode::OK, "{o}: {}", r.body);
    }
    // The validation of POST app/profiles, answered before anything is written.
    let needs_app = l.call("POST", "/app/profiles", &sys(), Some(json!({"name": "x"}))).await;
    assert_eq!(needs_app.status, StatusCode::BAD_REQUEST);
    assert_eq!(l.status("POST", "/app/profiles", &sys(), Some(json!({"appId": 2, "name": "x"}))).await, StatusCode::FORBIDDEN);
    assert_eq!(l.status("POST", "/app/profiles", &plain(), Some(json!({"appId": 2, "name": "x"}))).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn users_read_and_refuse_as_java_does() {
    let Some(l) = live().await else { return };
    // UserControllerTest: the page, its fills, a user, members, the sub-organisation.
    let page = l.ok("GET", "/users?size=5&fetchClients=true&fetchDesignation=true&fetchReportingTo=true", &sys(), None).await;
    for u in page["content"].as_array().unwrap() {
        assert_eq!(u["client"]["id"], u["clientId"], "fetchClients fills the user's client");
        assert!(u.get("password").is_none());
    }
    l.ok("GET", "/users?size=3&fetchProfiles=true&appCode=leadzump", &owner(), None).await;
    l.ok("POST", "/users/query", &owner(), Some(json!({"size": 3}))).await;
    assert_eq!(l.status("GET", "/users", &plain(), None).await, StatusCode::FORBIDDEN);
    let me = l.ok("GET", "/users/8", &plain(), None).await;
    assert_eq!(me["id"], 8);
    let other = l.call("GET", "/users/110", &plain(), None).await;
    assert_eq!((other.status, other.message().as_str()), (StatusCode::FORBIDDEN, "Permission/Role User READ is required to use this operation"));
    let members = l.ok("GET", "/users/members?size=3", &plain(), None).await;
    for m in members.as_array().unwrap() {
        assert!(m["name"].is_string() && m.get("emailId").is_none(), "{m}");
    }
    assert_eq!(l.status("GET", "/users/members?includeInactive=x", &plain(), None).await, StatusCode::BAD_REQUEST);
    let sub = l.ok("GET", "/users/sub-org", &owner(), None).await;
    assert!(sub.as_array().unwrap().iter().any(|i| i == 110));
    assert_eq!(l.status("GET", "/users/exists", &sys(), None).await, StatusCode::BAD_REQUEST);
    l.ok("GET", "/users/exists?email=nobody@example.invalid", &sys(), None).await;
    assert_eq!(l.status("POST", "/users/noMapping", &sys(), Some(json!({}))).await, StatusCode::BAD_REQUEST);
    l.ok("GET", "/users/110/app/270/assignedProfiles", &sys(), None).await;
    l.ok("GET", "/users/invites?size=3", &sys(), None).await;
    l.ok("POST", "/users/invites/query?appId=2", &sys(), Some(json!({"size": 3}))).await;
    l.ok("GET", "/users/requests?size=3", &sys(), None).await;
    l.ok("POST", "/users/requests/query?requesterSearch=zz", &sys(), Some(json!({"size": 3}))).await;
    assert_eq!(l.status("GET", "/users/requests", &plain(), None).await, StatusCode::FORBIDDEN);
    assert_eq!(l.status("GET", "/users/requestUser/nope", &sys(), None).await, StatusCode::NOT_FOUND);
    // The sign-in client picker answers anyone.
    let picker = l.ok("POST", "/users/findUserClients", &anon("SYSTEM"), Some(json!({"userName": "nobody@example.invalid"}))).await;
    assert_eq!(picker, json!([]));
    assert_eq!(l.status("POST", "/users/findUserClients?appLevel=x", &anon("SYSTEM"), Some(json!({}))).await, StatusCode::BAD_REQUEST);
    // ClientManagerControllerTest reads.
    l.ok("GET", "/client-managers/110", &sys(), None).await;
    assert_eq!(l.status("GET", "/client-managers/999999999", &sys(), None).await, StatusCode::FORBIDDEN);
    // The reset routes refuse a signed-in caller.
    let reset = l.call("POST", "/users/reset/password/otp/generate", &sys(), Some(json!({"userName": "x"}))).await;
    assert_eq!(reset.status, StatusCode::FORBIDDEN);
    let npe = l.call("POST", "/users/reset/password", &anon("SYSTEM"), Some(json!({"newPassword": PASSWORD}))).await;
    assert_eq!(npe.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn authority_expressions_and_otp() {
    let Some(l) = live().await else { return };
    // AuthorityExpressionControllerTest.
    let g = l.ok("POST", "/authorities/parse", &plain(), Some(json!({"expression": "Authorities.A or Authorities.B and Authorities.C"}))).await;
    assert_eq!(g["groups"].as_array().unwrap().len(), 2);
    let bad = l.ok("POST", "/authorities/parse", &plain(), Some(json!({"expression": "(("}))).await;
    assert_eq!(bad["supported"], false);
    assert_eq!(l.status("POST", "/authorities/parse", &anon("SYSTEM"), Some(json!({}))).await, StatusCode::UNAUTHORIZED);
    // OtpControllerTest: nothing verifies without an OTP that was sent; a null purpose fails as Java's does.
    let anyone = anon("SYSTEM");
    assert_eq!(l.ok("POST", "/otp/verify", &anyone, Some(json!({}))).await, json!(false));
    let e = "zz-live-otp@example.invalid";
    assert_eq!(l.ok("POST", "/otp/verify", &anyone, Some(json!({"emailId": e, "otp": "1", "purpose": "LOGIN"}))).await, json!(false));
    assert_eq!(l.status("POST", "/otp/verify", &anyone, Some(json!({"emailId": e, "otp": "1"}))).await, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(l.status("POST", "/otp/verify", &anyone, Some(json!({"purpose": "login"}))).await, StatusCode::BAD_REQUEST);
    let unknown = l.call("POST", "/otp/generate", &anon("NOSUCH"), Some(json!({"emailId": e, "purpose": "VERIFICATION"}))).await;
    assert_eq!((unknown.status, unknown.message().as_str()), (StatusCode::UNAUTHORIZED, "Unknown client information requested"));
    // With a constant OTP policy (SYSTEM / appbuilder locally) an OTP can be generated and verified once.
    if let Some(code) = constant_otp(&l).await {
        assert_eq!(l.ok("POST", "/otp/generate", &anyone, Some(json!({"emailId": e, "purpose": "VERIFICATION"}))).await, json!(true));
        assert_eq!(l.ok("POST", "/otp/verify", &anyone, Some(json!({"emailId": e, "otp": code, "purpose": "VERIFICATION"}))).await, json!(true));
        assert_eq!(l.ok("POST", "/otp/verify", &anyone, Some(json!({"emailId": e, "otp": code, "purpose": "VERIFICATION"}))).await, json!(false));
    }
}

/// A scratch client, created through the clients route or brought back to ACTIVE, with read
/// access to appbuilder.
async fn scratch_client(l: &Live, code: &str, name: &str, parent: Option<u64>) -> u64 {
    let id = match l.scalar(&format!("SELECT ID FROM security_client WHERE CODE = '{code}'")).await {
        Some(id) => {
            // Only ever this test's own client: everything in it gets swept.
            let stored: Option<String> = sqlx::query_scalar("SELECT NAME FROM security_client WHERE ID = ?").bind(id).fetch_one(&l.pool).await.unwrap();
            assert_eq!(stored.as_deref(), Some(name), "client {code} is not this test's scratch client");
            l.ok("PATCH", &format!("/clients/{id}"), &sys(), Some(json!({"statusCode": "ACTIVE"}))).await;
            id
        }
        None => {
            let mut body = json!({"code": code, "name": name, "typeCode": "BUS", "tokenValidityMinutes": 60, "localeCode": "en"});
            if let Some(p) = parent {
                body["parentClientId"] = json!(p);
            }
            l.ok("POST", "/clients", &sys(), Some(body)).await["id"].as_u64().unwrap()
        }
    };
    if l.count(&format!("SELECT COUNT(*) FROM security_app_access WHERE CLIENT_ID = {id} AND APP_ID = 2")).await == 0 {
        l.ok("POST", "/applications/2/access", &sys(), Some(json!({"clientId": id, "writeAccess": false}))).await;
    }
    id
}

async fn ids(l: &Live, sql: &str) -> Vec<u64> {
    sqlx::query_scalar(sql).fetch_all(&l.pool).await.unwrap()
}

/// What an earlier, failed run left in the scratch clients (`clients[0]` and the one below it),
/// removed through the routes; the clients are this test's own, so everything in them is.
/// Only a user of its client can remove an override, so one is made for that, given a profile
/// with the profile rights, and swept with the rest.
async fn sweep(l: &Live, clients: &[u64]) {
    let s = sys();
    let list = clients.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
    let overrides: Vec<(u64, u64)> =
        sqlx::query_as(&format!("SELECT ID, CLIENT_ID FROM security_profile WHERE CLIENT_ID IN ({list}) AND ROOT_PROFILE_ID IS NOT NULL"))
            .fetch_all(&l.pool)
            .await
            .unwrap();
    if !overrides.is_empty() {
        let tag = chrono::Utc::now().timestamp_millis() % 1_000_000_000;
        let arr = json!({"p1": {"roleId": 192}, "p2": {"roleId": 194}});
        let body = json!({"appId": 2, "clientId": clients[0], "name": format!("zz sweeper {tag}"), "arrangement": arr});
        let profile = l.ok("POST", "/app/profiles", &s, Some(body)).await["id"].as_u64().unwrap();
        let mut sweepers = std::collections::HashMap::new();
        for (id, client) in overrides {
            if !sweepers.contains_key(&client) {
                let body = json!({"clientId": client, "userName": format!("zzsweep{tag}c{client}"), "statusCode": "ACTIVE"});
                let user = l.ok("POST", "/users", &s, Some(body)).await["id"].as_u64().unwrap();
                l.ok("POST", &format!("/users/{user}/updatePassword"), &s, Some(json!({"newPassword": PASSWORD}))).await;
                l.ok("GET", &format!("/users/{user}/assignProfile/{profile}"), &s, None).await;
                let code: String = sqlx::query_scalar("SELECT CODE FROM security_client WHERE ID = ?").bind(client).fetch_one(&l.pool).await.unwrap();
                sweepers.insert(client, as_user(user, &code));
            }
            l.call("DELETE", &format!("/app/profiles/{id}"), &sweepers[&client], None).await;
        }
    }
    for (user, client) in sqlx::query_as::<_, (u64, u64)>(&format!("SELECT MANAGER_ID, CLIENT_ID FROM security_client_manager WHERE CLIENT_ID IN ({list})"))
        .fetch_all(&l.pool)
        .await
        .unwrap()
    {
        l.call("DELETE", &format!("/client-managers/{user}/{client}"), &s, None).await;
    }
    for id in ids(l, &format!("SELECT ID FROM security_profile WHERE CLIENT_ID IN ({list}) AND ROOT_PROFILE_ID IS NULL")).await {
        l.call("DELETE", &format!("/app/profiles/{id}"), &s, None).await;
    }
    for id in ids(l, &format!("SELECT ID FROM security_v2_role WHERE CLIENT_ID IN ({list})")).await {
        l.call("DELETE", &format!("/rolev2/{id}"), &s, None).await;
    }
    for id in ids(l, &format!("SELECT ID FROM security_designation WHERE CLIENT_ID IN ({list})")).await {
        l.call("DELETE", &format!("/designations/{id}"), &s, None).await;
    }
    for id in ids(l, &format!("SELECT ID FROM security_department WHERE CLIENT_ID IN ({list}) ORDER BY PARENT_DEPARTMENT_ID IS NULL, ID")).await {
        l.call("DELETE", &format!("/departments/{id}"), &s, None).await;
    }
    let codes: Vec<String> = sqlx::query_scalar(&format!("SELECT INVITE_CODE FROM security_user_invite WHERE CLIENT_ID IN ({list})")).fetch_all(&l.pool).await.unwrap();
    for code in codes {
        l.call("DELETE", &format!("/users/invite/{code}"), &s, None).await;
    }
    for id in ids(l, &format!("SELECT ID FROM security_user WHERE CLIENT_ID IN ({list}) AND STATUS_CODE <> 'DELETED'")).await {
        l.call("DELETE", &format!("/users/{id}"), &s, None).await;
    }
}

/// The lines of a profile read back, without what the read fills in (what a client sends to
/// override it).
fn bare_lines(arrangement: &Value) -> Value {
    let mut out = arrangement.clone();
    for line in out.as_object_mut().unwrap().values_mut() {
        let m = line.as_object_mut().unwrap();
        for k in ["role", "name", "shortName", "description", "assignable"] {
            m.remove(k);
        }
        if let Some(subs) = m.get_mut("subArrangements") {
            *subs = bare_lines(subs);
        }
    }
    out
}

/// Every write goes to objects this test makes: two clients (`ZZRUL`, and `ZZRUM` under it), and
/// in them departments, designations, roles, users, managers, invites, a request, two profiles
/// and an override of one by the client below. Real roles are only named as the lines of the
/// scratch profiles.
#[tokio::test]
async fn scratch_lifecycle() {
    let Some(l) = live().await else { return };
    let c = scratch_client(&l, "ZZRUL", "ZZ rust live users", None).await;
    let m = scratch_client(&l, "ZZRUM", "ZZ rust live managed", Some(c)).await;
    sweep(&l, &[c, m]).await;
    assert_eq!(l.count(&format!("SELECT COUNT(*) FROM security_client_hierarchy WHERE CLIENT_ID = {m} AND MANAGE_CLIENT_LEVEL_0 = {c}")).await, 1);
    let run = format!("{}", chrono::Utc::now().timestamp() % 1_000_000);
    let s = sys();
    let none = 999_999_999u64;

    // ---- departments and designations (DesignationServiceTest, DepartmentServiceTest) ----
    let dep = l.ok("POST", "/departments", &s, Some(json!({"clientId": c, "name": format!(" zz dep {run} "), "description": "d"}))).await;
    let dep_id = dep["id"].as_u64().unwrap();
    assert_eq!(dep["name"], format!("zz dep {run}"), "the name is trimmed");
    assert_eq!(l.status("POST", "/departments", &s, Some(json!({"clientId": c, "name": format!("zz dep {run}")}))).await, StatusCode::CONFLICT);
    assert_eq!(l.status("POST", "/departments", &s, Some(json!({"clientId": c, "name": " "}))).await, StatusCode::BAD_REQUEST);
    // A parent of another client (or none at all): Java's check raises an unknown message key.
    let r = l.refused("POST", "/departments", &s, Some(json!({"clientId": c, "name": "x", "parentDepartmentId": none}))).await;
    assert_eq!(r, (StatusCode::FORBIDDEN, "Internal Server Error (Unknown)".to_string()));
    let sub = l.ok("POST", "/departments", &s, Some(json!({"clientId": c, "name": format!("zz sub {run}"), "parentDepartmentId": dep_id}))).await;
    let sub_id = sub["id"].as_u64().unwrap();
    let des = l.ok("POST", "/designations", &s, Some(json!({"clientId": c, "name": format!("zz lead {run}"), "departmentId": dep_id}))).await;
    let des_id = des["id"].as_u64().unwrap();
    let des2 = l
        .ok("POST", "/designations", &s, Some(json!({"clientId": c, "name": format!("zz rep {run}"), "departmentId": dep_id, "parentDesignationId": des_id})))
        .await;
    let des2_id = des2["id"].as_u64().unwrap();
    let filled = l.ok("GET", &format!("/designations?clientId={c}&fetchParentDesignation=true&fetchDepartment=true&size=100"), &s, None).await;
    let rep = filled["content"].as_array().unwrap().iter().find(|d| d["id"] == des2_id).unwrap().clone();
    assert_eq!((rep["parentDesignation"]["id"].as_u64(), rep["department"]["id"].as_u64()), (Some(des_id), Some(dep_id)));
    let body = json!({"clientId": c, "name": format!("zz rep2 {run}"), "departmentId": dep_id, "parentDesignationId": des_id, "nextDesignationId": des_id});
    let put = l.ok("PUT", &format!("/designations/{des2_id}"), &s, Some(body)).await;
    assert_eq!(put["nextDesignationId"], des_id);
    assert_eq!(l.status("PATCH", &format!("/designations/{des2_id}"), &s, Some(json!({"departmentId": "x"}))).await, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(l.status("PATCH", &format!("/designations/{des2_id}"), &s, Some(json!({"name": [1]}))).await, StatusCode::BAD_REQUEST);
    let patched = l.ok("PATCH", &format!("/designations/{des2_id}"), &s, Some(json!({"description": "p"}))).await;
    assert_eq!(patched["description"], "p");
    let dpatch = l.ok("PATCH", &format!("/departments/{sub_id}"), &s, Some(json!({"description": "p2"}))).await;
    assert_eq!(dpatch["description"], "p2");

    // ---- roles (RoleV2ServiceTest) ----
    let ra = l.ok("POST", "/rolev2", &s, Some(json!({"clientId": c, "name": format!("zz role a {run}"), "shortName": "A"}))).await;
    let rb = l.ok("POST", "/rolev2", &s, Some(json!({"clientId": c, "name": format!("zz role b {run}")}))).await;
    let (ra_id, rb_id) = (ra["id"].as_u64().unwrap(), rb["id"].as_u64().unwrap());
    assert_eq!(l.status("POST", "/rolev2", &plain(), Some(json!({"clientId": c, "name": "x"}))).await, StatusCode::FORBIDDEN);
    let renamed = l.ok("PUT", &format!("/rolev2/{ra_id}"), &s, Some(json!({"name": format!("zz role a2 {run}"), "clientId": 1}))).await;
    assert_eq!((renamed["name"].as_str(), renamed["clientId"].as_u64()), (Some(format!("zz role a2 {run}").as_str()), Some(c)));
    l.ok("PATCH", &format!("/rolev2/{ra_id}"), &s, Some(json!({"description": "p"}))).await;
    assert_eq!(l.status("PATCH", &format!("/rolev2/{ra_id}"), &s, Some(json!({"appId": "x"}))).await, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(l.ok("POST", &format!("/rolev2/{ra_id}/subRoles/{rb_id}"), &s, None).await, json!(true));
    let subs = l.ok("GET", &format!("/rolev2/{ra_id}/subRoles"), &s, None).await;
    assert_eq!(subs[0]["id"], rb_id);
    let r = l.refused("POST", &format!("/rolev2/{rb_id}/subRoles/{ra_id}"), &s, None).await;
    assert_eq!(r, (StatusCode::BAD_REQUEST, format!("Role zz role a2 {run} already contains role zz role b {run}, so adding it would make a loop")));
    let page = l.ok("GET", &format!("/rolev2?clientId={c}&size=100"), &s, None).await;
    let a = page["content"].as_array().unwrap().iter().find(|r| r["id"] == ra_id).unwrap().clone();
    assert_eq!(a["subRoles"][0]["id"], rb_id);
    assert_eq!(l.ok("DELETE", &format!("/rolev2/{ra_id}/subRoles/{rb_id}"), &s, None).await, json!(true));

    // ---- profiles (ProfileServiceTest) ----
    // The scratch client's working profile: Owner, the user, role and profile rights, and one
    // line that is not assignable.
    let arr = json!({
        "own": {"roleId": 196, "order": 0},
        "admin": {"name": "Admin", "order": 1, "subArrangements": {
            "u1": {"roleId": 70}, "u2": {"roleId": 71}, "u3": {"roleId": 69}, "r1": {"roleId": 80},
            "p1": {"roleId": 192}, "p2": {"roleId": 194}, "x": {"roleId": 82, "assignable": false}
        }}
    });
    let p = l.ok("POST", "/app/profiles", &s, Some(json!({"appId": 2, "clientId": c, "name": format!("zz prof {run}"), "arrangement": arr}))).await;
    let p_id = p["id"].as_u64().unwrap();
    assert!(p["arrangement"]["own"]["role"]["id"] == 196 && p["arrangement"]["admin"]["assignable"] == true, "{p}");
    let roles: Vec<u64> = sqlx::query_scalar("SELECT ROLE_ID FROM security_profile_role WHERE PROFILE_ID = ? AND EXCLUDE = 0 ORDER BY ROLE_ID")
        .bind(p_id)
        .fetch_all(&l.pool)
        .await
        .unwrap();
    assert_eq!(roles, vec![69, 70, 71, 80, 192, 194, 196], "the assignable lines' roles");
    assert_eq!(l.status("POST", "/app/profiles", &s, Some(json!({"appId": 2, "clientId": c, "name": format!("zz prof {run}")}))).await, StatusCode::CONFLICT);
    let r = l.call("POST", "/app/profiles", &s, Some(json!({"appId": 2, "clientId": c, "name": "x", "arrangement": {"k": {"roleId": none}}}))).await;
    assert_eq!((r.status, r.message().is_empty()), (StatusCode::BAD_REQUEST, false), "a role the client cannot reach: {}", r.body);
    let mut again = p.clone();
    again["description"] = json!("d2");
    again["arrangement"] = arr.clone();
    let up = l.ok("PUT", "/app/profiles", &s, Some(again)).await;
    assert_eq!((up["id"].as_u64(), up["description"].as_str()), (Some(p_id), Some("d2")));
    assert_eq!(l.ok("POST", &format!("/app/profiles/{p_id}/restrictClient/{m}"), &s, None).await, json!(true));
    assert_eq!(l.status("POST", &format!("/app/profiles/{p_id}/restrictClient/{m}"), &s, None).await, StatusCode::INTERNAL_SERVER_ERROR);
    // A second profile of the client, for the client below it to override.
    let root_arr = json!({"g": {"name": "Group", "order": 0, "subArrangements": {"g1": {"roleId": 80}, "g2": {"roleId": 70}}}, "r": {"roleId": 192, "order": 1}});
    let root = l.ok("POST", "/app/profiles", &s, Some(json!({"appId": 2, "clientId": c, "name": format!("zz root {run}"), "title": "Root", "arrangement": root_arr}))).await;
    let root_id = root["id"].as_u64().unwrap();
    assert_eq!(root["clientId"], c);

    // ---- users (UserServiceTest) ----
    let email = |t: &str| format!("zzrl{run}{t}@example.invalid");
    let body = json!({"clientId": c, "userName": format!("zzrl{run}a"), "emailId": email("a"), "firstName": "One", "statusCode": "ACTIVE", "password": "ignored"});
    let u1_id = l.ok("POST", "/users", &s, Some(body)).await["id"].as_u64().unwrap();
    assert_eq!(l.count(&format!("SELECT COUNT(*) FROM security_user WHERE ID = {u1_id} AND PASSWORD IS NULL")).await, 1, "a body never sets a password");
    let body = json!({"clientId": c, "userName": format!("zzrl{run}b"), "emailId": email("b"), "statusCode": "ACTIVE", "reportingTo": u1_id});
    let u2_id = l.ok("POST", "/users", &s, Some(body)).await["id"].as_u64().unwrap();
    let body = json!({"clientId": m, "userName": format!("zzrl{run}d"), "emailId": email("d"), "statusCode": "ACTIVE"});
    let u4_id = l.ok("POST", "/users", &s, Some(body)).await["id"].as_u64().unwrap();
    assert_eq!(l.status("POST", "/users", &plain(), Some(json!({"clientId": c, "userName": "x"}))).await, StatusCode::FORBIDDEN);
    let body = json!({"clientId": c, "userName": format!("zzrl{run}a"), "emailId": email("a"), "firstName": "Two", "statusCode": "ACTIVE"});
    let edited = l.ok("PUT", &format!("/users/{u1_id}"), &s, Some(body)).await;
    assert_eq!(edited["firstName"], "Two");
    let taken = l.refused("PUT", &format!("/users/{u1_id}"), &s, Some(json!({"clientId": c, "userName": format!("zzrl{run}a"), "emailId": email("b")}))).await;
    assert_eq!(taken, (StatusCode::CONFLICT, "A user with this email already exists in this organisation".to_string()));
    l.ok("PATCH", &format!("/users/{u1_id}"), &s, Some(json!({"lastName": "P"}))).await;
    assert_eq!(l.ok("PATCH", &format!("/users/makeUserInActive?userId={u1_id}"), &s, None).await, json!(true));
    assert_eq!(l.ok("PATCH", &format!("/users/makeUserActive?userId={u1_id}"), &s, None).await, json!(true));
    assert_eq!(l.ok("POST", &format!("/users/unblockUser?userId={u1_id}"), &s, None).await, json!(true));
    let d = l.ok("PUT", &format!("/users/{u2_id}/designation/{des_id}"), &s, None).await;
    assert_eq!(d["designationId"], des_id);
    let r = l.refused("PUT", &format!("/users/{u2_id}/designation/{none}"), &s, None).await;
    assert_eq!(r, (StatusCode::BAD_REQUEST, "User cannot be assigned with the specified designation.".to_string()));
    let r = l.refused("PUT", &format!("/users/{u2_id}/reportingManager/{u2_id}"), &s, None).await;
    assert_eq!(r, (StatusCode::BAD_REQUEST, "User cannot report to specified reporting to user.".to_string()));
    let cleared = l.ok("DELETE", &format!("/users/{u2_id}/reportingManager"), &s, None).await;
    assert!(cleared.get("reportingTo").is_none(), "{cleared}");
    l.ok("PUT", &format!("/users/{u2_id}/reportingManager/{u1_id}"), &s, None).await;
    // A role of the scratch client is not the SYSTEM caller's to hand out (its app check
    // reads the client id as the app id), but an owner of the client can.
    assert_eq!(l.status("GET", &format!("/users/{u1_id}/assignRole/{ra_id}"), &s, None).await, StatusCode::FORBIDDEN);
    assert_eq!(l.ok("GET", &format!("/users/{u1_id}/assignProfile/{p_id}"), &s, None).await, json!(true));
    let assigned = l.ok("GET", &format!("/users/{u1_id}/app/2/assignedProfiles"), &s, None).await;
    assert_eq!(assigned[0]["id"], p_id);

    // Passwords: refusals, then the change.
    assert_eq!(l.status("POST", &format!("/users/{u1_id}/updatePassword"), &s, Some(json!({}))).await, StatusCode::FORBIDDEN);
    let short = l.call("POST", &format!("/users/{u1_id}/updatePassword"), &s, Some(json!({"newPassword": "short"}))).await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST, "{}", short.body);
    for u in [u1_id, u2_id, u4_id] {
        assert_eq!(l.ok("POST", &format!("/users/{u}/updatePassword"), &s, Some(json!({"newPassword": PASSWORD}))).await, json!(true));
    }
    // The client below may use the profile it is restricted to.
    assert_eq!(l.ok("GET", &format!("/users/{u4_id}/assignProfile/{p_id}"), &s, None).await, json!(true));
    let (h1, h2) = (as_user(u1_id, "ZZRUL"), as_user(u2_id, "ZZRUL"));
    let same = l.refused("POST", "/users/updatePassword", &h1, Some(json!({"oldPassword": PASSWORD, "newPassword": PASSWORD}))).await;
    assert_eq!(same, (StatusCode::FORBIDDEN, "Please choose a new password that's different from your current one.".to_string()));
    assert_eq!(l.ok("GET", &format!("/users/{u2_id}"), &h2, None).await["id"], u2_id);
    assert_eq!(l.status("GET", "/users", &h2, None).await, StatusCode::FORBIDDEN);
    let listed = l.ok("GET", "/app/2/profiles?size=500", &h1, None).await;
    let ids: Vec<u64> = listed["content"].as_array().unwrap().iter().filter_map(|x| x["id"].as_u64()).collect();
    assert!(ids.contains(&p_id) && ids.contains(&root_id), "{ids:?}");
    let sub_org = l.ok("GET", "/users/sub-org", &h1, None).await;
    assert!(sub_org.as_array().unwrap().iter().any(|i| i == u2_id), "{sub_org}");
    // The owner hands out the client's own role.
    assert_eq!(l.ok("GET", &format!("/users/{u2_id}/assignRole/{ra_id}"), &h1, None).await, json!(true));
    assert_eq!(l.ok("GET", &format!("/users/{u2_id}/assignRole/{ra_id}"), &h1, None).await, json!(true), "already there");
    assert_eq!(l.ok("GET", &format!("/users/{u2_id}/removeRole/{ra_id}"), &h1, None).await, json!(true));

    // ---- the override by the client below, read through the root ----
    let mut lines = bare_lines(&root["arrangement"]);
    lines.as_object_mut().unwrap().insert("zzextra".into(), json!({"name": "Extra", "order": 9}));
    let body = json!({"rootProfileId": root_id, "appId": 2, "clientId": m, "name": root["name"], "title": "Mine", "arrangement": lines});
    let o = l.ok("POST", "/app/profiles", &s, Some(body)).await;
    let o_id = o["id"].as_u64().unwrap();
    assert_eq!(o["rootProfileId"], root_id);
    let stored: Option<String> = sqlx::query_scalar("SELECT NAME FROM security_profile WHERE ID = ?").bind(o_id).fetch_one(&l.pool).await.unwrap();
    assert_eq!(stored, None, "a name equal to the root's is not stored");
    let o_roles = l.count(&format!("SELECT COUNT(*) FROM security_profile_role WHERE PROFILE_ID = {o_id}")).await;
    assert_eq!(o_roles, 0, "the same roles as the root's: nothing added or dropped");
    let h4 = as_user(u4_id, "ZZRUM");
    let below = l.ok("GET", &format!("/app/profiles/{root_id}"), &h4, None).await;
    assert_eq!((below["id"].as_u64(), below["title"].as_str()), (Some(o_id), Some("Mine")));
    assert!(below["arrangement"]["zzextra"].is_object() && below["arrangement"]["g"]["subArrangements"]["g1"]["role"]["id"] == 80, "{below}");
    let above = l.ok("GET", &format!("/app/profiles/{root_id}"), &h1, None).await;
    assert_eq!((above["id"].as_u64(), above["title"].as_str()), (Some(root_id), Some("Root")));
    // A user of another client is read by a manager of that client (ZZRUL manages ZZRUM and u1
    // is ZZRUL's Owner), not by a user of the client below, though both hold User READ (U7 in
    // DIFFERENCES.md; Java answers both).
    assert_eq!(l.ok("GET", &format!("/users/{u4_id}"), &h1, None).await["id"], u4_id);
    let r = l.refused("GET", &format!("/users/{u1_id}"), &h4, None).await;
    assert_eq!(r, (StatusCode::NOT_FOUND, format!("User with id {u1_id} not found")));

    // ---- client managers (ClientManagerServiceTest) ----
    assert_eq!(l.status("POST", &format!("/client-managers/{u2_id}/{c}"), &s, None).await, StatusCode::BAD_REQUEST, "of their own client");
    assert_eq!(l.ok("POST", &format!("/client-managers/{u2_id}/{m}"), &s, None).await, json!(true));
    let of = l.ok("GET", &format!("/client-managers/{u2_id}"), &s, None).await;
    assert_eq!((of["content"][0]["id"].as_u64(), of["totalElements"].as_i64()), (Some(m), Some(1)));
    let moved = l.ok("POST", &format!("/client-managers/migrateTo/{u1_id}?fromUid={u2_id}&removeManager=true"), &s, None).await;
    assert_eq!(moved, json!(2), "Java's count: the rows added plus the rows removed");
    assert_eq!(l.ok("GET", &format!("/client-managers/{u2_id}"), &s, None).await["totalElements"], 0);
    assert_eq!(l.status("POST", &format!("/client-managers/migrateTo/{u1_id}?fromUid={u1_id}"), &s, None).await, StatusCode::BAD_REQUEST);
    assert_eq!(l.ok("POST", &format!("/client-managers/{m}?oldManagerId={u1_id}&newManagerId={u2_id}"), &s, None).await, json!(true));
    assert_eq!(l.status("PUT", &format!("/client-managers/{m}/managers"), &s, Some(json!([]))).await, StatusCode::BAD_REQUEST);
    assert_eq!(l.status("PUT", &format!("/client-managers/{c}/managers"), &s, Some(json!([u1_id]))).await, StatusCode::BAD_REQUEST);
    assert_eq!(l.ok("PUT", &format!("/client-managers/{m}/managers"), &s, Some(json!([u1_id]))).await, json!(true));
    let managers: Vec<u64> = sqlx::query_scalar("SELECT MANAGER_ID FROM security_client_manager WHERE CLIENT_ID = ?").bind(m).fetch_all(&l.pool).await.unwrap();
    assert_eq!(managers, vec![u1_id]);
    assert_eq!(l.ok("DELETE", &format!("/client-managers/{u1_id}/{m}"), &s, None).await, json!(true));

    // ---- invites (UserInviteServiceTest) ----
    let body = json!({"clientId": c, "emailId": email("i"), "firstName": "Inv", "designationId": des_id, "reportingTo": u1_id});
    let inv = l.ok("POST", "/users/invite", &s, Some(body)).await;
    assert_eq!(inv["existingUser"], false);
    let code = inv["userRequest"]["inviteCode"].as_str().unwrap().to_string();
    let r = l.refused("POST", "/users/invite", &s, Some(json!({"clientId": c, "emailId": email("i")}))).await;
    assert_eq!(r, (StatusCode::CONFLICT, "An invite with this email is already pending for this organisation".to_string()));
    let r = l.refused("POST", "/users/invite", &s, Some(json!({"clientId": c, "emailId": email("z"), "reportingTo": none}))).await;
    assert_eq!(r, (StatusCode::NOT_FOUND, format!("User with id {none} not found")));
    let an = anon("ZZRUL");
    let details = l.ok("GET", &format!("/users/inviteDetails/{code}"), &an, None).await;
    assert_eq!(details["emailId"], email("i"));
    let listed = l.ok("GET", &format!("/users/invites?clientId={c}&size=100"), &s, None).await;
    let row = listed["content"].as_array().unwrap().iter().find(|i| i["inviteCode"] == code.as_str()).unwrap().clone();
    assert!(row["designationName"].is_string() && row["reportingToName"].is_string(), "{row}");
    let short = l.call("POST", "/users/acceptInvite", &an, Some(json!({"inviteCode": code, "passType": "PASSWORD", "password": "short"}))).await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST, "{}", short.body);
    let accepted = l.ok("POST", "/users/acceptInvite", &an, Some(json!({"inviteCode": code, "passType": "PASSWORD", "password": PASSWORD}))).await;
    let u3_id = accepted["userId"].as_u64().or_else(|| accepted["authentication"]["user"]["id"].as_u64()).unwrap();
    assert!(accepted["authentication"]["accessToken"].is_string(), "the new user is signed in: {accepted}");
    let u3 = l.ok("GET", &format!("/users/{u3_id}"), &s, None).await;
    assert_eq!((u3["designationId"].as_u64(), u3["reportingTo"].as_u64()), (Some(des_id), Some(u1_id)));
    let again = l.refused("POST", "/users/acceptInvite", &an, Some(json!({"inviteCode": code, "passType": "PASSWORD", "password": PASSWORD}))).await;
    assert_eq!(again, (StatusCode::FORBIDDEN, "Cannot create User Invitation Error for the selected client".to_string()), "the invite is used");
    let code2 = l.ok("POST", "/users/invite", &s, Some(json!({"clientId": c, "emailId": email("k")}))).await["userRequest"]["inviteCode"].as_str().unwrap().to_string();
    assert_eq!(l.ok("DELETE", &format!("/users/invite/{code2}"), &s, None).await, json!(true));
    let r = l.refused("DELETE", &format!("/users/invite/{code2}"), &s, None).await;
    assert_eq!(r, (StatusCode::FORBIDDEN, "Cannot delete User Invite for the selected client".to_string()));

    // ---- access requests (UserRequestServiceTest) ----
    assert_eq!(l.ok("GET", "/users/request?appCode=appbuilder", &h2, None).await, json!(false));
    let req = l.ok("POST", "/users/request", &h2, Some(json!({"appCode": "appbuilder"}))).await;
    let rid = req["requestId"].as_str().unwrap().to_string();
    assert_eq!(req["status"], "PENDING");
    let r = l.refused("POST", "/users/request", &h2, Some(json!({"appCode": "appbuilder"}))).await;
    assert_eq!(r, (StatusCode::BAD_REQUEST, "User Access Request for appbuilder already exists.".to_string()));
    assert_eq!(l.ok("GET", "/users/request?appCode=appbuilder", &h2, None).await, json!(true));
    assert_eq!(l.ok("GET", &format!("/users/requestUser/{rid}"), &s, None).await["id"], u2_id);
    let found = l.ok("POST", &format!("/users/requests/query?requesterSearch=zzrl{run}b"), &s, Some(json!({"size": 5}))).await;
    assert_eq!(found["content"][0]["requestId"], rid.as_str());
    assert_eq!(l.status("POST", "/users/acceptRequest", &s, Some(json!({"requestId": rid}))).await, StatusCode::BAD_REQUEST);
    assert_eq!(l.status("POST", "/users/acceptRequest", &s, Some(json!({"requestId": rid, "profileId": none}))).await, StatusCode::NOT_FOUND);
    assert_eq!(l.ok("POST", "/users/acceptRequest", &s, Some(json!({"requestId": rid, "profileId": p_id}))).await, json!(true));
    assert_eq!(l.status("POST", &format!("/users/rejectRequest/{rid}"), &s, None).await, StatusCode::BAD_REQUEST, "decided already");

    // ---- the password reset by OTP (SYSTEM's constant appbuilder OTP, when it has one) ----
    // The second user's: no one signs in as them after this, so the new password is a new one.
    if let Some(otp) = constant_otp(&l).await {
        let who = email("b");
        let reset = |pw: &str| json!({"authRequest": {"userName": who, "otp": otp}, "newPassword": pw});
        assert_eq!(l.ok("POST", "/users/reset/password/otp/generate", &an, Some(json!({"userName": who}))).await, json!(true));
        assert_eq!(l.ok("POST", "/users/reset/password/otp/verify", &an, Some(json!({"userName": who, "otp": otp}))).await, json!(true));
        let same = l.call("POST", "/users/reset/password", &an, Some(reset(PASSWORD))).await;
        assert_eq!(
            (same.status, same.message().as_str()),
            (StatusCode::BAD_REQUEST, "Your new Password cannot be the same as your previous Password. Please choose a different one.;")
        );
        assert_eq!(l.ok("POST", "/users/reset/password", &an, Some(reset("Pass@5678"))).await, json!(true));
        let used = l.refused("POST", "/users/reset/password", &an, Some(reset("Pass@6789"))).await;
        assert_eq!(used, (StatusCode::FORBIDDEN, "Wrong OTP, Please check the OTP and try again.".to_string()), "the OTP is spent");
    }
    let picker = l.ok("POST", "/users/findUserClients", &an, Some(json!({"userName": email("b")}))).await;
    assert_eq!(picker[0]["client"]["code"], "ZZRUL", "{picker}");

    // ---- cleanup, through the routes; users and clients are only marked DELETED ----
    assert_eq!(l.ok("DELETE", &format!("/app/profiles/{root_id}"), &h1, None).await, json!(false), "overridden below");
    assert_eq!(l.ok("DELETE", &format!("/app/profiles/{o_id}"), &h4, None).await, json!(true));
    assert_eq!(l.ok("DELETE", &format!("/app/profiles/{root_id}"), &h1, None).await, json!(true));
    assert_eq!(l.ok("DELETE", &format!("/app/profiles/{p_id}"), &s, None).await, json!(true));
    assert_eq!(l.status("DELETE", &format!("/app/profiles/{none}"), &s, None).await, StatusCode::NOT_FOUND);
    for path in [format!("/rolev2/{ra_id}"), format!("/rolev2/{rb_id}"), format!("/designations/{des2_id}"), format!("/designations/{des_id}")] {
        assert_eq!(l.status("DELETE", &path, &s, None).await, StatusCode::NO_CONTENT, "{path}");
    }
    assert_eq!(l.status("DELETE", &format!("/designations/{des_id}"), &s, None).await, StatusCode::NOT_FOUND);
    for path in [format!("/departments/{sub_id}"), format!("/departments/{dep_id}")] {
        assert_eq!(l.status("DELETE", &path, &s, None).await, StatusCode::NO_CONTENT, "{path}");
    }
    for u in [u4_id, u3_id, u2_id, u1_id] {
        assert_eq!(l.status("DELETE", &format!("/users/{u}"), &s, None).await, StatusCode::NO_CONTENT);
    }
    let status: String = sqlx::query_scalar("SELECT STATUS_CODE FROM security_user WHERE ID = ?").bind(u1_id).fetch_one(&l.pool).await.unwrap();
    assert_eq!(status, "DELETED");
    sweep(&l, &[c, m]).await;
    for client in [m, c] {
        if let Some(access) = l.scalar(&format!("SELECT ID FROM security_app_access WHERE CLIENT_ID = {client} AND APP_ID = 2")).await {
            assert_eq!(l.ok("DELETE", &format!("/applications/2/access?accessId={access}"), &s, None).await, json!(true));
        }
        l.call("DELETE", &format!("/clients/{client}"), &s, None).await;
    }
}

/// The business-wide identity rule of invites (QA-0445, nocode-saas 7c3093e3b). Every write goes
/// to objects this run makes: a business under SYSTEM and a channel partner under it, with codes
/// of this run (`ZZQB...`, `ZZQP...`), their users and invites; all are removed at the end, even
/// when a check fails (users and clients marked DELETED).
#[tokio::test]
async fn invites_follow_the_business_wide_identity_rule() {
    use futures::FutureExt;
    let Some(l) = live().await else { return };
    let s = sys();
    let run = chrono::Utc::now().timestamp_millis() % 1_000_000;
    let letters: String = format!("{run:06}").chars().map(|d| (b'A' + d.to_digit(10).unwrap() as u8) as char).collect();
    let new_client = |code: String, parent: Option<u64>| {
        let mut body = json!({"code": code, "name": format!("ZZ rust qa0445 {code}"), "typeCode": "BUS", "tokenValidityMinutes": 60, "localeCode": "en"});
        if let Some(p) = parent {
            body["parentClientId"] = json!(p);
        }
        body
    };
    let b = l.ok("POST", "/clients", &s, Some(new_client(format!("ZZQB{letters}"), None))).await["id"].as_u64().unwrap();
    let p = l.ok("POST", "/clients", &s, Some(new_client(format!("ZZQP{letters}"), Some(b)))).await["id"].as_u64().unwrap();
    let partner_code = format!("ZZQP{letters}");
    let mut users: Vec<u64> = Vec::new();
    let email = |t: &str| format!("zzqa{run}{t}@example.invalid");
    let checks = AssertUnwindSafe(async {
        for client in [b, p] {
            l.ok("POST", "/applications/2/access", &s, Some(json!({"clientId": client, "writeAccess": false}))).await;
        }
        let user = |client: u64, t: &str| json!({"clientId": client, "userName": format!("zzqa{run}{t}"), "emailId": email(t), "statusCode": "ACTIVE"});
        let staff = l.ok("POST", "/users", &s, Some(user(b, "a"))).await["id"].as_u64().unwrap();
        let partner_user = l.ok("POST", "/users", &s, Some(user(p, "d"))).await["id"].as_u64().unwrap();
        let taken = |e: &str| (StatusCode::CONFLICT, format!("User {e} already exists. Please try to login / reset your password."));

        // The business's staff cannot be invited into its partner, nor the partner's user as staff.
        let r = l.refused("POST", "/users/invite", &s, Some(json!({"clientId": p, "emailId": email("a")}))).await;
        assert_eq!(r, taken(&email("a")), "the business's staff into its partner");
        let r = l.refused("POST", "/users/invite", &s, Some(json!({"clientId": b, "emailId": email("d")}))).await;
        assert_eq!(r, taken(&email("d")), "the partner's user into the business");
        let written = format!("SELECT COUNT(*) FROM security_user_invite WHERE EMAIL_ID IN ('{}', '{}')", email("a"), email("d"));
        assert_eq!(l.count(&written).await, 0, "no invite written");

        // Accepting an invite whose email someone in the business took since: refused, invite kept.
        let late = l.ok("POST", "/users/invite", &s, Some(json!({"clientId": p, "emailId": email("l")}))).await["userRequest"]["inviteCode"].as_str().unwrap().to_string();
        let since = l.ok("POST", "/users", &s, Some(user(b, "l"))).await["id"].as_u64().unwrap();
        let r = l.refused("POST", "/users/acceptInvite", &anon(&partner_code), Some(json!({"inviteCode": late, "passType": "PASSWORD", "password": PASSWORD}))).await;
        assert_eq!(r, taken(&email("l")));
        assert_eq!(l.count(&format!("SELECT COUNT(*) FROM security_user_invite WHERE INVITE_CODE = '{late}'")).await, 1, "the invite is not consumed");
        assert_eq!(l.count(&format!("SELECT COUNT(*) FROM security_user WHERE CLIENT_ID = {p} AND EMAIL_ID = '{}'", email("l"))).await, 0);
        vec![staff, partner_user, since]
    })
    .catch_unwind()
    .await;
    if let Ok(made) = &checks {
        users.extend(made);
    }
    // Cleanup, through the routes, of what this run made only.
    let list = format!("{b},{p}");
    let codes: Vec<String> = sqlx::query_scalar(&format!("SELECT INVITE_CODE FROM security_user_invite WHERE CLIENT_ID IN ({list})")).fetch_all(&l.pool).await.unwrap();
    for code in codes {
        l.call("DELETE", &format!("/users/invite/{code}"), &s, None).await;
    }
    users.extend(ids(&l, &format!("SELECT ID FROM security_user WHERE CLIENT_ID IN ({list}) AND STATUS_CODE <> 'DELETED'")).await);
    users.dedup();
    for u in users {
        l.call("DELETE", &format!("/users/{u}"), &s, None).await;
    }
    for client in [p, b] {
        if let Some(access) = l.scalar(&format!("SELECT ID FROM security_app_access WHERE CLIENT_ID = {client} AND APP_ID = 2")).await {
            l.call("DELETE", &format!("/applications/2/access?accessId={access}"), &s, None).await;
        }
        l.call("DELETE", &format!("/clients/{client}"), &s, None).await;
    }
    if let Err(panic) = checks {
        std::panic::resume_unwind(panic);
    }
}

/// The binary's start-up path (`security::admin::run`) with the local configuration: it serves,
/// answers health, and refuses an anonymous admin read.
#[tokio::test]
async fn run_serves_with_the_local_configuration() {
    let (Ok(_), Ok(_), Ok(_)) =
        (std::env::var("SECURITY_AUTH_LIVE"), std::env::var("MODLIX__DATABASE__PASSWORD"), std::env::var("MODLIX__JWT__KEY"))
    else {
        return;
    };
    let port = 18133;
    std::env::set_var("CONFIG_FILE", concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/security-admin.toml"));
    std::env::set_var("MODLIX__SERVER__PORT", port.to_string());
    std::env::set_var("MODLIX__SERVER__SHUTDOWN_GRACE_SECONDS", "0");
    let server = tokio::spawn(security::admin::run());
    let base = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::new();
    let mut ready = false;
    for _ in 0..50 {
        if let Ok(r) = http.get(format!("{base}/readyz")).send().await {
            if r.status().is_success() {
                ready = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(ready, "security-admin did not become ready");
    let r = http.get(format!("{base}/api/security/users")).header("clientCode", "SYSTEM").send().await.unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::UNAUTHORIZED);
    server.abort();
}
