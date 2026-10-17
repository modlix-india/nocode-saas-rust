//! security-internal's routes against the local `security` schema, ported from the internal
//! cases of `ClientControllerTest`, `UserControllerTest`, `AppControllerTest`,
//! `SecurityCacheControllerTest`, `SSLCertificateControllerTest`, `ClientServiceTest`,
//! `ClientHierarchyServiceTest`, `ClientManagerServiceTest`, `UserSubOrganizationServiceTest`,
//! `ClientUrlServiceTest` and the DAO integration tests (`ClientDAOIntegrationTest`,
//! `AppDAOIntegrationTest`, `UserDAOIntegrationTest`, `ClientUserFilterIntegrationTest`,
//! `MultiTenantVisibilityIntegrationTest`), with the expected values read from the same schema.
//!
//! Gated: `SECURITY_AUTH_LIVE=1` with `config/local.env` sourced. Read-only: the billing routes
//! that charge are left out, and the one wallet read uses a client that has the wallet already.
//! Signed-in callers use Basic `<id>:Pass@1234` for users whose stored password is that text.

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
}

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
    let pool = platform::db::mysql_pool(&cfg.database).await.unwrap();
    // No Redis: this instance's caches only, so nothing here evicts anything elsewhere.
    let cache = CacheService::new("cmn", "evictionChannel", None).unwrap();
    let state = security::internal::build(&cfg, pool.clone(), cache);
    Some(Live { router: security::internal::routes::router(state), pool })
}

const P: &str = "/api/security";

fn basic(user: u64) -> String {
    use base64::Engine;
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:Pass@1234")))
}

impl Live {
    async fn call(&self, method: &str, path: &str, headers: &[(&str, String)], body: Option<Value>) -> (StatusCode, String, Option<String>) {
        let mut b = Request::builder().method(method).uri(format!("{P}{path}")).header("host", "localhost:8001");
        for (k, v) in headers {
            b = b.header(*k, v);
        }
        let req = match body {
            Some(v) => b.header("content-type", "application/json").body(Body::from(v.to_string())).unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let ct = resp.headers().get("content-type").map(|v| v.to_str().unwrap().to_string());
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned(), ct)
    }

    async fn get(&self, path: &str) -> Value {
        self.json("GET", path, &[], None).await
    }

    async fn json(&self, method: &str, path: &str, headers: &[(&str, String)], body: Option<Value>) -> Value {
        let (s, b, _) = self.call(method, path, headers, body).await;
        assert_eq!(s, StatusCode::OK, "{method} {path}: {b}");
        if b.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&b).unwrap_or(Value::String(b))
        }
    }

    async fn ids(&self, sql: &str) -> Vec<u64> {
        sqlx::query(sql).fetch_all(&self.pool).await.unwrap().iter().map(|r| r.try_get::<u64, _>(0).unwrap()).collect()
    }

    async fn strings(&self, sql: &str) -> Vec<String> {
        sqlx::query(sql).fetch_all(&self.pool).await.unwrap().iter().map(|r| r.try_get::<String, _>(0).unwrap()).collect()
    }
}

fn ids_of(v: &Value) -> Vec<u64> {
    v.as_array().unwrap().iter().map(|x| x.as_u64().or_else(|| x["id"].as_u64()).unwrap()).collect()
}

#[tokio::test]
async fn client_routes() {
    let Some(l) = live().await else { return };
    let sys = l.get("/clients/internal/getClientByCode?clientCode=SYSTEM").await;
    assert_eq!((sys["id"].as_u64(), sys["typeCode"].as_str(), sys["totalUsers"].as_i64()), (Some(1), Some("SYS"), Some(0)));
    assert_eq!(l.get("/clients/internal/getClientById?clientId=1").await["code"], "SYSTEM");
    assert_eq!(l.get("/clients/internal/getClientById?clientId=999999999").await, Value::Null);
    assert_eq!(l.get("/clients/internal/getClientByCode?clientCode=NOPE").await, Value::Null);
    assert_eq!(l.get("/clients/internal/validateClientCode?clientCode=SYSTEM").await, json!(true));
    assert_eq!(l.get("/clients/internal/validateClientCode?clientCode=NOPE").await, Value::Null);

    // A managed client and its hierarchy, read straight from the table.
    let row = sqlx::query(
        "SELECT h.CLIENT_ID, c.CODE, h.MANAGE_CLIENT_LEVEL_0 FROM security_client_hierarchy h JOIN security_client c ON c.ID = h.CLIENT_ID \
         WHERE h.MANAGE_CLIENT_LEVEL_1 IS NOT NULL ORDER BY h.CLIENT_ID LIMIT 1",
    )
    .fetch_one(&l.pool)
    .await
    .unwrap();
    let (cid, code, manager): (u64, String, u64) = (row.get(0), row.get(1), row.get(2));
    let hierarchy = ids_of(&l.get(&format!("/clients/internal/clientHierarchy?clientId={cid}")).await);
    assert_eq!(hierarchy[..2], [cid, manager]);
    assert_eq!(*hierarchy.last().unwrap(), 1);
    let codes = l.get(&format!("/clients/internal/clientHierarchyCodes?clientCode={code}")).await;
    assert_eq!((codes[0].as_str(), codes.as_array().unwrap().last().unwrap().as_str()), (Some(code.as_str()), Some("SYSTEM")));
    assert_eq!(l.get("/clients/internal/clientHierarchyCodes?clientCode=NOPE").await, json!([]));
    assert_eq!(l.get("/clients/internal/clientHierarchyCodes?clientCode=").await, json!([]));
    let managed = ids_of(&l.get(&format!("/clients/internal/managingClientIds?clientId={manager}")).await);
    let expected = l
        .ids(&format!(
            "SELECT CLIENT_ID FROM security_client_hierarchy WHERE CLIENT_ID = {manager} OR MANAGE_CLIENT_LEVEL_0 = {manager} \
             OR MANAGE_CLIENT_LEVEL_1 = {manager} OR MANAGE_CLIENT_LEVEL_2 = {manager} OR MANAGE_CLIENT_LEVEL_3 = {manager}"
        ))
        .await;
    assert_eq!(managed, expected);
    assert!(managed.contains(&cid));
    assert_eq!(l.get(&format!("/clients/internal/doesClientManageClient?managingClientId={manager}&clientId={cid}")).await, json!(true));
    assert_eq!(l.get(&format!("/clients/internal/doesClientManageClient?managingClientId={cid}&clientId={manager}")).await, json!(false));
    assert_eq!(l.get(&format!("/clients/internal/doesClientManageClient?managingClientId={cid}&clientId={cid}")).await, json!(true));
    assert_eq!(l.get(&format!("/clients/internal/doesClientManageClientCode?managingClientCode=SYSTEM&clientCode={code}")).await, json!(true));
    assert_eq!(l.get("/clients/internal/doesClientManageClientCode?managingClientCode=NOPE&clientCode=SYSTEM").await, Value::Null);
    let (s, b, _) = l.call("GET", "/clients/internal/doesClientManageClient", &[], None).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{b}");
    let filtered = l
        .json("POST", "/clients/internal/filterManagedClientCodes?managingClientCode=SYSTEM", &[], Some(json!([code, "NOPE", "SYSTEM", code])))
        .await;
    assert_eq!(filtered, json!([code, "SYSTEM"]));
    assert_eq!(l.json("POST", "/clients/internal/filterManagedClientCodes?managingClientCode=NOPE", &[], Some(json!(["SYSTEM"]))).await, json!([]));
    assert_eq!(l.json("POST", "/clients/internal/filterManagedClientCodes?managingClientCode=SYSTEM", &[], Some(json!([]))).await, json!([]));

    let active = l.json("POST", "/clients/internal/activeClientCodes", &[], Some(json!(["SYSTEM", code, "NOPE"]))).await;
    assert!(active.as_array().unwrap().contains(&json!("SYSTEM")));
    assert_eq!(l.json("POST", "/clients/internal/activeClientCodes", &[], Some(json!([]))).await, json!([]));

    // Managers.
    let manager_user = l.ids("SELECT MANAGER_ID FROM security_client_manager ORDER BY ID LIMIT 1").await;
    if let Some(m) = manager_user.first() {
        let expected = l.ids(&format!("SELECT CLIENT_ID FROM security_client_manager WHERE MANAGER_ID = {m}")).await;
        assert_eq!(ids_of(&l.get(&format!("/clients/internal/clientIdsOfManager?managerId={m}")).await), expected);
        let of_many = ids_of(&l.json("POST", "/clients/internal/clientIdsOfManagers", &[], Some(json!([m, 999999999]))).await);
        assert_eq!(of_many.len(), expected.iter().collect::<std::collections::HashSet<_>>().len());
    }
    assert_eq!(l.json("POST", "/clients/internal/clientIdsOfManagers", &[], Some(json!([]))).await, json!([]));

    // Denormalised data: names and statuses, keyed by id.
    let denorm = l.json("POST", "/clients/internal/clients/denorm/full", &[], Some(json!([1, cid, 999999999]))).await;
    assert_eq!(denorm["1"]["clientName"], sys["name"]);
    assert!(denorm.get("999999999").is_none());
    assert_eq!(l.json("POST", "/clients/internal/clients/denorm/full", &[], Some(json!([]))).await, json!({}));

    // Users and hierarchy membership.
    assert_eq!(l.get(&format!("/clients/internal/isUserPartOfHierarchy?userId=142&clientCode={code}")).await, json!(true));
    assert_eq!(l.get("/clients/internal/isUserPartOfHierarchy?userId=999999999&clientCode=SYSTEM").await, json!(false));
    assert_eq!(l.get("/clients/internal/isUserPartOfHierarchy?userId=142&clientCode=NOPE").await, json!(false));
    assert_eq!(l.get(&format!("/clients/internal/isUserClientManageClient?appCode=appbuilder&userId=142&userClientId=1&targetClientId={cid}")).await, json!(true));
    assert_eq!(l.get("/clients/internal/isUserClientManageClient?appCode=appbuilder&userId=142&userClientId=1&targetClientId=1").await, json!(true));
    assert_eq!(l.get(&format!("/clients/internal/isUserClientManageClient?appCode=appbuilder&userId=142&userClientId={cid}&targetClientId=1")).await, json!(false));
    // A non-owner of a managing client: the client-manager table decides (cached per pair).
    if let Some(row) = sqlx::query(
        "SELECT u.ID, u.CLIENT_ID, h.CLIENT_ID FROM security_user u JOIN security_client_hierarchy h ON h.MANAGE_CLIENT_LEVEL_0 = u.CLIENT_ID \
         WHERE u.CLIENT_ID <> 1 AND u.STATUS_CODE = 'ACTIVE' ORDER BY u.ID LIMIT 1",
    )
    .fetch_optional(&l.pool)
    .await
    .unwrap()
    {
        let (u, uc, t): (u64, u64, u64) = (row.get(0), row.get(1), row.get(2));
        let path = format!("/clients/internal/isUserClientManageClient?appCode=nope&userId={u}&userClientId={uc}&targetClientId={t}");
        let first = l.get(&path).await;
        assert_eq!(l.get(&path).await, first);
    }
    for (s, path) in [
        (StatusCode::INTERNAL_SERVER_ERROR, "/clients/internal/isUserClientManageClient"),
        (StatusCode::INTERNAL_SERVER_ERROR, "/clients/internal/isUserClientManageClient?userClientId=1"),
        (StatusCode::BAD_REQUEST, "/clients/internal/clientHierarchy"),
        (StatusCode::BAD_REQUEST, "/clients/internal/getClientById?clientId=abc"),
        (StatusCode::INTERNAL_SERVER_ERROR, "/clients/internal/clientHierarchy?clientId=999999999"),
    ] {
        assert_eq!(l.call("GET", path, &[], None).await.0, s, "{path}");
    }

    // URL patterns.
    let localhost = l.get("/clients/internal/getClientNAppCodeNType?scheme=http&host=localhost&port=8080").await;
    assert_eq!(localhost, json!(["SYSTEM", "nothing", "LIVE"]));
    assert_eq!(l.get("/clients/internal/getClientNAppCode?scheme=http&host=localhost&port=8080").await, json!(["SYSTEM", "nothing"]));
    let url = l.strings("SELECT URL_PATTERN FROM security_client_url WHERE URL_TYPE = 'LIVE' ORDER BY ID LIMIT 1").await;
    if let Some(u) = url.first() {
        let host = u.trim_start_matches("https://").trim_start_matches("http://").split([':', '/']).next().unwrap().to_string();
        let v = l.get(&format!("/clients/internal/getClientNAppCodeNType?scheme=https&host={host}&port=443")).await;
        assert_ne!(v[0], "SYSTEM", "{host}");
        assert_ne!(l.get(&format!("/clients/internal/getClientNAppCode?scheme=https&host={host}&port=443")).await[1], "nothing");
    }
}

#[tokio::test]
async fn client_reads_with_fills_and_queries() {
    let Some(l) = live().await else { return };
    let ids = l.ids("SELECT CLIENT_ID FROM security_client_hierarchy WHERE MANAGE_CLIENT_LEVEL_0 IS NOT NULL ORDER BY CLIENT_ID LIMIT 4").await;
    let mut all = ids.clone();
    all.push(1);
    let list = l.json("POST", "/clients/internal/batch", &[], Some(json!(all))).await;
    let mut got = ids_of(&list);
    got.sort();
    let mut want = all.clone();
    want.sort();
    assert_eq!(got, want);
    let q: String = all.iter().map(|i| format!("clientIds={i}")).collect::<Vec<_>>().join("&");
    assert_eq!(l.get(&format!("/clients/internal?{q}")).await.as_array().unwrap().len(), all.len());
    assert_eq!(l.get("/clients/internal?clientIds=").await, json!([]));
    assert_eq!(l.call("GET", "/clients/internal?clientIds=1,2", &[], None).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(l.call("GET", "/clients/internal", &[], None).await.0, StatusCode::BAD_REQUEST);

    let fills = "fetchUserCounts=true&fetchOwners=true&fetchManagingClient=true&fetchApps=true&fetchCreatedByUser=true&fetchClientManagers=true";
    let filled = l.get(&format!("/clients/internal?{q}&{fills}&appCode=appbuilder")).await;
    // The HashMap order of the ids, as Java returns a list that went through the counts.
    let order = ids_of(&filled);
    let expected_order = security::javamap::iteration_order(
        l.ids(&format!("SELECT ID FROM security_client WHERE ID IN ({})", all.iter().map(u64::to_string).collect::<Vec<_>>().join(",")))
            .await
            .into_iter()
            .map(|i| (security::javamap::long_hash(i), i))
            .collect(),
    );
    assert_eq!(order, expected_order);
    let one = l.get(&format!("/clients/internal/{}?{fills}", ids[0])).await;
    assert!(one.get("managagingClient").is_some(), "{one}");
    let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM security_user WHERE CLIENT_ID = {} AND STATUS_CODE = 'ACTIVE'", ids[0]))
        .fetch_one(&l.pool)
        .await
        .unwrap();
    assert_eq!(one["activeUsers"].as_i64(), Some(count));
    let sys = l.get("/clients/internal/1?fetchManagingClient=true&fetchCreatedByUser=true&fetchApps=true").await;
    assert!(sys.get("managagingClient").is_none() && sys.get("apps").is_some());
    assert_eq!(l.get("/clients/internal/999999999?fetchOwners=true").await, Value::Null);
    let (s, b, _) = l.call("GET", "/clients/internal/1?fetchOwners=true&appId=abc", &[], None).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{b}");

    // The query: filters on the client, its users and its apps; sort and page.
    let page = l
        .json("POST", "/clients/internal/query", &[], Some(json!({"size": 2, "page": 0, "sort": [{"property": "id"}],
            "condition": {"field": "id", "operator": "IN", "value": all.iter().map(u64::to_string).collect::<Vec<_>>().join(",")}})))
        .await;
    assert_eq!(page["totalElements"].as_u64(), Some(all.len() as u64));
    assert_eq!(page["content"].as_array().unwrap().len(), 2);
    assert_eq!(page["content"][0]["id"].as_u64(), Some(*want.first().unwrap()));
    for c in [
        json!({"field": "user.emailId", "operator": "STRING_LOOSE_EQUAL", "value": "@"}),
        json!({"field": "appCode", "value": "appbuilder"}),
        json!({"field": "appId", "operator": "IN", "value": "1,2", "negate": true}),
        json!({"field": "appCode", "operator": "LIKE", "value": "a%"}),
        json!({"operator": "OR", "conditions": [{"field": "code", "value": "SYSTEM"}, {"field": "user.nope", "value": 1}]}),
    ] {
        let v = l.json("POST", "/clients/internal/query?fetchUserCounts=true", &[], Some(json!({"size": 3, "condition": c}))).await;
        assert!(v["totalElements"].as_u64().is_some(), "{c}: {v}");
    }
    assert_eq!(l.call("POST", "/clients/internal/query", &[], Some(json!({"condition": {"field": "id", "value": "x"}}))).await.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(l.call("POST", "/clients/internal/query", &[], Some(json!({"condition": {"value": 1}}))).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(l.call("POST", "/clients/internal/query", &[], None).await.0, StatusCode::BAD_REQUEST);
}

/// The DAO restrictions by caller: a tenant's anonymous caller sees nothing of other clients;
/// a signed-in non-SYSTEM user sees what their client (or their reporting tree) manages.
#[tokio::test]
async fn reads_are_scoped_by_the_caller() {
    let Some(l) = live().await else { return };
    let host = l.strings(
        "SELECT u.URL_PATTERN FROM security_client_url u JOIN security_client c ON c.ID = u.CLIENT_ID \
         WHERE u.URL_TYPE = 'LIVE' AND c.TYPE_CODE <> 'SYS' ORDER BY u.ID LIMIT 1",
    )
    .await;
    if let Some(h) = host.first() {
        let h = h.trim_start_matches("https://").trim_start_matches("http://").split([':', '/']).next().unwrap().to_string();
        let headers = [("X-Forwarded-Host", h.clone()), ("X-Forwarded-Port", "443".to_string())];
        let v = l.json("POST", "/clients/internal/query", &headers, Some(json!({"size": 5}))).await;
        assert_eq!(v["totalElements"], 0, "{h}");
        let u = l.json("POST", "/users/internal/query", &headers, Some(json!({"size": 5}))).await;
        assert!(u["totalElements"].as_u64().is_some());
        assert_eq!(l.json("POST", "/clients/internal/batch", &headers, Some(json!([1]))).await, json!([]));
    }
    // Users with the local password in non-SYSTEM clients: owners and others.
    let signers = sqlx::query(
        "SELECT u.ID, c.CODE FROM security_user u JOIN security_client c ON c.ID = u.CLIENT_ID \
         WHERE u.STATUS_CODE = 'ACTIVE' AND u.PASSWORD = 'Pass@1234' AND u.PASSWORD_HASHED = 0 \
         AND COALESCE(u.NO_FAILED_ATTEMPT, 0) = 0 AND c.TYPE_CODE <> 'SYS' AND c.STATUS_CODE = 'ACTIVE' \
         AND u.ID IN (110, 8, 221) ORDER BY u.ID",
    )
    .fetch_all(&l.pool)
    .await
    .unwrap();
    for r in signers {
        let (id, code): (u64, String) = (r.get(0), r.get(1));
        let headers = [("Authorization", basic(id)), ("clientCode", code.clone()), ("appCode", "appbuilder".to_string())];
        let c = l.json("POST", "/clients/internal/query", &headers, Some(json!({"size": 50}))).await;
        assert!(c["totalElements"].as_u64().is_some(), "{id}: {c}");
        let u = l.json("POST", "/users/internal/query", &headers, Some(json!({"size": 50}))).await;
        assert!(u["totalElements"].as_u64().is_some());
        let ids = l.json("GET", "/users/internal?userIds=142&userIds=8", &headers, None).await;
        assert!(ids.as_array().is_some());
        let url = l.call("GET", "/clienturls/internal/applications/property/url?appCode=appbuilder&clientCode=SYSTEM", &headers, None).await;
        assert_eq!(url.0, StatusCode::OK);
        let own = l.call("GET", &format!("/clienturls/internal/applications/property/url?appCode=appbuilder&clientCode={code}"), &headers, None).await;
        assert_eq!(own.0, StatusCode::OK);
        // Only a SYSTEM caller may read the certificates.
        assert_eq!(l.call("GET", "/ssl/internal/certificates", &headers, None).await.0, StatusCode::INTERNAL_SERVER_ERROR);
    }
}

#[tokio::test]
async fn application_routes() {
    let Some(l) = live().await else { return };
    let app = l.get("/applications/internal/appCode/appbuilder").await;
    assert_eq!((app["appCode"].as_str(), app["clientId"].as_u64()), (Some("appbuilder"), Some(1)));
    assert_eq!(l.get("/applications/internal/appCode/nope").await, Value::Null);
    let (s, b, ct) = l.call("GET", "/applications/internal/appStatus/appbuilder", &[], None).await;
    assert_eq!((s, b.as_str(), ct.as_deref()), (StatusCode::OK, "ACTIVE", Some("text/plain;charset=UTF-8")));
    assert_eq!(l.call("GET", "/applications/internal/appStatus/nope", &[], None).await.1, "");
    let info = l.get("/applications/internal/explicitInfo/appbuilder").await;
    assert_eq!((info["clientCode"].as_str(), info["template"].as_bool()), (Some("SYSTEM"), Some(false)));
    assert_eq!(l.get("/applications/internal/explicitInfo/nope").await, Value::Null);
    let explicit = l.strings("SELECT APP_CODE FROM security_app WHERE APP_ACCESS_TYPE = 'EXPLICIT' ORDER BY ID LIMIT 1").await;
    if let Some(e) = explicit.first() {
        assert!(l.get(&format!("/applications/internal/explicitInfo/{e}")).await["clientCode"].is_string());
    }
    let with_deps = l.strings("SELECT a.APP_CODE FROM security_app_dependency d JOIN security_app a ON a.ID = d.APP_ID ORDER BY d.ID LIMIT 1").await;
    if let Some(a) = with_deps.first() {
        let deps = l.get(&format!("/applications/internal/dependencies?appCode={a}")).await;
        assert!(!deps.as_array().unwrap().is_empty());
        // Cached, empty or not.
        assert_eq!(l.get(&format!("/applications/internal/dependencies?appCode={a}")).await, deps);
    }
    assert_eq!(l.get("/applications/internal/dependencies?appCode=nope").await, Value::Null);
    let codes = l.get("/applications/internal/writeAccessClientCodes?appCode=appbuilder").await;
    assert!(codes.as_array().unwrap().contains(&json!("SYSTEM")));
    assert_eq!(l.get("/applications/internal/hasReadAccess?appCode=appbuilder&clientCode=SYSTEM").await, json!(true));
    assert_eq!(l.get("/applications/internal/hasWriteAccess?appCode=appbuilder&clientCode=SYSTEM").await, json!(true));
    assert_eq!(l.get("/applications/internal/hasWriteAccess?appCode=nope&clientCode=SYSTEM").await, json!(false));
    assert_eq!(l.get("/applications/internal/appInheritance?appCode=appbuilder&urlClientCode=SYSTEM&clientCode=SYSTEM").await, json!(["SYSTEM"]));
    assert_eq!(l.get("/applications/internal/appInheritance?appCode=appbuilder&urlClientCode=A&clientCode=B").await, json!(["SYSTEM", "A", "B"]));
    assert_eq!(l.get("/applications/internal/appInheritance?appCode=nope&urlClientCode=A&clientCode=B").await, Value::Null);
    assert_eq!(l.call("GET", "/applications/internal/appInheritance?appCode=a", &[], None).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn user_routes() {
    let Some(l) = live().await else { return };
    let u = l.get("/users/internal/142").await;
    assert_eq!((u["id"].as_u64(), u["clientId"].as_u64()), (Some(142), Some(1)));
    assert!(u.get("password").is_none());
    assert_eq!(l.get("/users/internal/999999999").await, Value::Null);
    let fills = "fetchClients=true&fetchManagingClients=true&fetchCreatedBy=true&fetchDesignation=true&fetchReportingTo=true";
    let with = l
        .ids("SELECT ID FROM security_user WHERE DESIGNATION_ID IS NOT NULL AND REPORTING_TO IS NOT NULL AND CREATED_BY IS NOT NULL ORDER BY ID LIMIT 1")
        .await;
    if let Some(id) = with.first() {
        let v = l.get(&format!("/users/internal/{id}?{fills}")).await;
        for k in ["client", "managingClient", "designation", "reportingUser"] {
            assert!(v.get(k).is_some(), "{k} of {id}: {v}");
        }
        // The designation is cached by id.
        assert_eq!(l.get(&format!("/users/internal/{id}?fetchDesignation=true")).await["designation"], v["designation"]);
    }
    // fetchProfiles came with admin piece 1 (the profile read with its arrangement merge).
    let (s, b, _) = l.call("GET", "/users/internal/142?fetchProfiles=true", &[], None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let with_profiles: Value = serde_json::from_str(&b).unwrap();
    assert!(with_profiles.get("profiles").is_some(), "profiles filled: {with_profiles}");
    let users = l.ids("SELECT ID FROM security_user WHERE CLIENT_ID = 1 ORDER BY ID LIMIT 4").await;
    let list = l.json("POST", "/users/internal/batch?fetchClients=true", &[], Some(json!(users))).await;
    assert_eq!(ids_of(&list), users);
    assert_eq!(list[0]["client"]["code"], "SYSTEM");
    let q: String = users.iter().map(|i| format!("userIds={i}")).collect::<Vec<_>>().join("&");
    assert_eq!(ids_of(&l.get(&format!("/users/internal?{q}")).await), users);
    let of_clients = l.json("POST", "/users/internal/clients/batch", &[], Some(json!([1]))).await;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_user WHERE CLIENT_ID = 1").fetch_one(&l.pool).await.unwrap();
    assert_eq!(of_clients.as_array().unwrap().len() as i64, n);
    let in_app = l.json("POST", "/users/internal/clients/batch?appCode=appbuilder", &[], Some(json!([1]))).await;
    assert!(in_app.as_array().unwrap().len() as i64 <= n);

    let note = l.json("POST", "/users/internal/notification", &[], Some(json!({"appCode": "appbuilder", "clientCode": "SYSTEM"}))).await;
    assert!(note.as_array().unwrap().iter().all(|x| x["clientId"] == 1));
    let by_id = l.json("POST", "/users/internal/notification", &[], Some(json!({"appCode": "appbuilder", "clientId": 1, "userIds": [142]}))).await;
    assert_eq!(by_id[0]["id"], 142);
    assert_eq!(l.json("POST", "/users/internal/notification", &[], Some(json!({"clientId": 1}))).await, json!([]));
    let proc = l.json("POST", "/users/internal/processor", &[], Some(json!({"appCode": "appbuilder", "clientId": 1, "userIds": [142]}))).await;
    assert_eq!(proc[0]["id"], 142);
    assert!(proc[0]["profileIds"].as_array().is_some());
    let proc = l.json("POST", "/users/internal/processor", &[], Some(json!({"appCode": "appbuilder", "clientCode": "SYSTEM"}))).await;
    assert!(proc.as_array().is_some());
    assert_eq!(l.json("POST", "/users/internal/processor", &[], Some(json!({}))).await, json!([]));
    assert_eq!(l.call("POST", "/users/internal/processor", &[], Some(json!({"userIds": "x"}))).await.0, StatusCode::BAD_REQUEST);

    let h = |app: &str, client: &str| vec![("appCode", app.to_string()), ("clientCode", client.to_string())];
    let admins = l.json("GET", "/users/internal/adminEmails", &h("appbuilder", "SYSTEM"), None).await;
    assert!(admins["emails"].as_array().is_some() && admins["addApp"].is_boolean());
    assert_eq!(l.json("GET", "/users/internal/adminEmails", &h("nope", "SYSTEM"), None).await, json!({"emails": [], "addApp": false}));
    // An unknown clientCode header fails the caller's context first, as JWTTokenFilter does.
    assert_eq!(l.call("GET", "/users/internal/adminEmails", &h("appbuilder", "NOPE"), None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(l.json("GET", "/users/internal/adminEmails", &[], None).await, json!({"emails": [], "addApp": false}));
    // A client without admin profile users falls back to its owners.
    let fallback = sqlx::query(
        "SELECT c.CODE FROM security_client c WHERE c.TYPE_CODE <> 'SYS' AND EXISTS (SELECT 1 FROM security_client_hierarchy h WHERE h.CLIENT_ID = c.ID) \
         ORDER BY c.ID DESC LIMIT 1",
    )
    .fetch_optional(&l.pool)
    .await
    .unwrap();
    if let Some(r) = fallback {
        let code: String = r.get(0);
        let v = l.json("GET", "/users/internal/adminEmails", &h("appbuilder", &code), None).await;
        assert!(v["emails"].as_array().is_some());
    }
    let owners = l.json("GET", "/users/internal/ownerEmails", &h("appbuilder", "SYSTEM"), None).await;
    assert!(owners["emails"].as_array().is_some());
    assert_eq!(l.json("GET", "/users/internal/ownerEmails", &h("nope", "SYSTEM"), None).await, json!({"emails": []}));

    assert_eq!(l.json("GET", "/users/internal/ownerEmails", &[], None).await, json!({"emails": []}));

    // Sub-org: an owner sees the whole client; anyone else themselves and their reports.
    let sub = ids_of(&l.get("/users/internal/142/sub-org?appCode=appbuilder&clientId=1").await);
    assert!(sub.contains(&142));
    let reporting = sqlx::query("SELECT REPORTING_TO, CLIENT_ID FROM security_user WHERE REPORTING_TO IS NOT NULL ORDER BY ID LIMIT 1")
        .fetch_optional(&l.pool)
        .await
        .unwrap();
    if let Some(r) = reporting {
        let (m, c): (u64, u64) = (r.get(0), r.get(1));
        let v = ids_of(&l.get(&format!("/users/internal/{m}/sub-org?appCode=nope&clientId={c}")).await);
        assert_eq!(v[0], m);
        assert_eq!(ids_of(&l.get(&format!("/users/internal/{m}/sub-org?appCode=nope&clientId={c}")).await), v);
    }
    let biz = l.ids("SELECT u.ID FROM security_user u JOIN security_client c ON c.ID = u.CLIENT_ID WHERE c.TYPE_CODE <> 'SYS' ORDER BY u.ID LIMIT 1").await;
    if let Some(u) = biz.first() {
        let cid: u64 = sqlx::query_scalar(&format!("SELECT CLIENT_ID FROM security_user WHERE ID = {u}")).fetch_one(&l.pool).await.unwrap();
        let v = l.get(&format!("/users/internal/{u}/sub-org?appCode=appbuilder&clientId={cid}")).await;
        assert!(v.as_array().is_some());
    }
    assert_eq!(l.call("GET", "/users/internal/142/sub-org?appCode=appbuilder", &[], None).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(l.call("GET", "/users/internal/abc", &[], None).await.0, StatusCode::BAD_REQUEST);

    // Profile users.
    let profiles = l.ids("SELECT p.ID FROM security_profile p JOIN security_app a ON a.ID = p.APP_ID WHERE a.APP_CODE = 'appbuilder' ORDER BY p.ID LIMIT 3").await;
    let q: String = profiles.iter().map(|i| format!("profileIds={i}")).collect::<Vec<_>>().join("&");
    let v = l.json("GET", &format!("/app/profiles/internal/users?{q}"), &[("appCode", "appbuilder".to_string())], None).await;
    assert!(v.as_array().is_some());
    assert_eq!(l.json("GET", "/app/profiles/internal/users?profileIds=", &[("appCode", "appbuilder".to_string())], None).await, json!([]));
    assert_eq!(l.json("GET", "/app/profiles/internal/users?profileIds=1", &[("appCode", "nope".to_string())], None).await, Value::Null);

    // The query, with a profile filter and an app filter.
    for c in [
        json!({"field": "profile.name", "operator": "STRING_LOOSE_EQUAL", "value": "a"}),
        json!({"field": "appCode", "operator": "IN", "value": "appbuilder,leadzump"}),
        json!({"field": "appId", "value": 2, "negate": true}),
        json!({"field": "appId", "operator": "IS_NULL"}),
        json!({"fieldExpr": {"function": "UPPER", "fields": ["userName"]}, "operator": "LIKE", "value": "%A%"}),
    ] {
        let v = l.json("POST", "/users/internal/query?fetchClients=true", &[], Some(json!({"size": 3, "condition": c, "sort": {"property": "id", "direction": "DESC"}}))).await;
        assert!(v["totalElements"].as_u64().is_some(), "{c}: {v}");
    }
}

#[tokio::test]
async fn url_billing_cache_and_certificate_routes() {
    let Some(l) = live().await else { return };
    let (s, url, ct) = l.call("GET", "/clienturls/internal/applications/property/url?appCode=appbuilder&clientCode=SYSTEM", &[], None).await;
    assert_eq!((s, ct.as_deref()), (StatusCode::OK, Some("text/plain;charset=UTF-8")));
    assert!(url.is_empty() || url.starts_with("https://"), "{url}");
    assert_eq!(l.call("GET", "/clienturls/internal/applications/property/url?appCode=nope&clientCode=SYSTEM", &[], None).await.1, "");
    assert_eq!(l.call("GET", "/clienturls/internal/applications/property/url?appCode=appbuilder&clientCode=NOPE", &[], None).await.1, "");
    assert_eq!(l.call("GET", "/clienturls/internal/applications/property/url?appCode=appbuilder", &[("clientCode", "SYSTEM".into())], None).await.0, StatusCode::OK);
    assert_eq!(l.call("GET", "/clienturls/internal/applications/property/url?appCode=appbuilder", &[], None).await.0, StatusCode::OK);
    assert_eq!(l.call("GET", "/clienturls/internal/applications/property/url?appCode=", &[], None).await.0, StatusCode::BAD_REQUEST);
    let denied = json!([false, "0", "", ""]);
    for host in ["t-0123456789abcdef0123456789abcdef.local.modlix.com", "app.local.modlix.com"] {
        assert_eq!(l.get(&format!("/clienturls/internal/draft/token/resolve?host={host}")).await, denied);
    }

    for a in ["security.app.rent", "security.site.rent", "security.user", "ai.llm.tokens", "nope"] {
        let v = l.get(&format!("/internal/billing/instructions?action={a}")).await;
        assert!(v.as_array().is_some());
    }
    assert_eq!(l.get("/internal/billing/ai-allowed?appCode=nope&clientCode=SYSTEM").await, json!(true));
    let suspended = sqlx::query(
        "SELECT cl.ID, cl.CODE, a.APP_CODE FROM security_wallet w JOIN security_client cl ON cl.ID = w.CLIENT_ID \
         JOIN security_app a ON a.ID = w.APP_ID WHERE w.STATUS = 'SUSPENDED' ORDER BY w.ID LIMIT 1",
    )
    .fetch_optional(&l.pool)
    .await
    .unwrap();
    if let Some(r) = suspended {
        let (id, code, app): (u64, String, String) = (r.get(0), r.get(1), r.get(2));
        let v = l.get(&format!("/internal/billing/ai-allowed?appCode={app}&clientCode={code}")).await;
        assert!(v.is_boolean());
        let h = l.get(&format!("/internal/billing/hosting?urlAppCode={app}&urlClientCode={code}")).await;
        assert!(h["suspended"].is_boolean());
        // Read-only here: the client already has a wallet for an app with a config.
        let configured = l.strings(&format!(
            "SELECT a.APP_CODE FROM security_app_billing_config c JOIN security_app a ON a.ID = c.APP_ID \
             JOIN security_wallet w ON w.APP_ID = c.APP_ID AND w.CLIENT_ID = {id} WHERE c.CLIENT_ID = 1 AND c.STATUS = 'ACTIVE' LIMIT 1"
        ))
        .await;
        if let Some(a) = configured.first() {
            let s = l.get(&format!("/internal/billing/serving-status?urlAppCode={a}&urlClientCode=SYSTEM&clientId={id}")).await;
            assert!(s["status"].is_string(), "{s}");
        }
    }
    assert_eq!(l.get("/internal/billing/hosting?urlAppCode=appbuilder&urlClientCode=SYSTEM").await["suspended"], false);
    assert_eq!(l.get("/internal/billing/serving-status?urlAppCode=nope&urlClientCode=SYSTEM&clientId=1").await["status"], "ACTIVE");
    assert_eq!(l.json("POST", "/internal/billing/charge", &[], Some(json!([]))).await, json!(true));
    let none = l.json("POST", "/internal/billing/charge-ai", &[], Some(json!({"appCode": "nope", "clientCode": "SYSTEM", "weightedTokens": 1}))).await;
    assert_eq!(none["charged"], false);
    assert_eq!(l.call("POST", "/internal/billing/charge", &[], Some(json!({"x": 1}))).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(l.call("POST", "/internal/billing/reconcile?date=yesterday", &[], None).await.0, StatusCode::INTERNAL_SERVER_ERROR);

    // Cache and certificates need a signed-in caller.
    assert_eq!(l.call("GET", "/internal/cache", &[], None).await.0, StatusCode::UNAUTHORIZED);
    // A Basic caller needs the appCode header, or the context refuses it (401, as in Java).
    assert_eq!(l.call("GET", "/internal/cache", &[("Authorization", basic(142)), ("clientCode", "SYSTEM".to_string())], None).await.0, StatusCode::UNAUTHORIZED);
    let sys = [("Authorization", basic(142)), ("clientCode", "SYSTEM".to_string()), ("appCode", "appbuilder".to_string())];
    assert!(l.json("GET", "/internal/cache", &sys, None).await.as_array().is_some());
    assert!(l.json("GET", "/internal/cache/stats", &sys, None).await.is_object());
    assert_eq!(l.json("DELETE", "/internal/cache/parityScratchCache", &sys, None).await, json!(true));
    // This instance has no Redis: evicting every cache only empties its own.
    assert_eq!(l.json("DELETE", "/internal/cache", &sys, None).await, json!(true));
    let (s, body, _) = l.call("GET", "/ssl/internal/certificates", &sys, None).await;
    assert_eq!(s, StatusCode::OK);
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM security_client_url LEFT JOIN security_ssl_certificate ON security_client_url.ID = security_ssl_certificate.URL_ID \
         WHERE security_ssl_certificate.CURRENT = 1 OR security_ssl_certificate.CURRENT IS NULL",
    )
    .fetch_one(&l.pool)
    .await
    .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap().as_array().unwrap().len() as i64, n);
    let etag = {
        let req = Request::builder()
            .uri(format!("{P}/ssl/internal/certificates"))
            .header("Authorization", basic(142))
            .header("clientCode", "SYSTEM")
            .header("appCode", "appbuilder")
            .body(Body::empty())
            .unwrap();
        let resp = l.router.clone().oneshot(req).await.unwrap();
        resp.headers().get("etag").unwrap().to_str().unwrap().trim_matches('"').to_string()
    };
    let mut with_etag = sys.to_vec();
    with_etag.push(("If-None-Match", etag));
    assert_eq!(l.call("GET", "/ssl/internal/certificates", &with_etag, None).await.0, StatusCode::NOT_MODIFIED);
    // A wrong method.
    assert_eq!(l.call("POST", "/clients/internal/getClientByCode", &[], Some(json!({}))).await.0, StatusCode::METHOD_NOT_ALLOWED);
}

/// The binary's start-up path (`security::internal::run`) with the local configuration.
#[tokio::test]
async fn run_serves_with_the_local_configuration() {
    let (Ok(_), Ok(_), Ok(_)) =
        (std::env::var("SECURITY_AUTH_LIVE"), std::env::var("MODLIX__DATABASE__PASSWORD"), std::env::var("MODLIX__JWT__KEY"))
    else {
        return;
    };
    let port = 18112;
    std::env::set_var("CONFIG_FILE", concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/security-internal.toml"));
    std::env::set_var("MODLIX__SERVER__PORT", port.to_string());
    std::env::set_var("MODLIX__SERVER__SHUTDOWN_GRACE_SECONDS", "0");
    let server = tokio::spawn(security::internal::run());
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
    assert!(ready, "security-internal did not become ready");
    let v: Value = http.get(format!("{base}{P}/clients/internal/getClientByCode?clientCode=SYSTEM")).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["id"], 1);
    server.abort();
}

/// `WalletDAOIntegrationTest` / `WalletTransactionDAOIntegrationTest` / `MeteringCountDAOIntegrationTest`:
/// every wallet statement against the real tables, inside a transaction that is rolled back, so
/// no wallet is ever created or changed.
#[tokio::test]
async fn wallet_statements_in_a_rolled_back_transaction() {
    use security::data::billing::{sql, BillingStore, Txn};
    use security::decimal::Dec;
    let Some(l) = live().await else { return };
    let free = sqlx::query(
        "SELECT c.ID, a.ID FROM security_client c JOIN security_app a ON a.CLIENT_ID = c.ID \
         WHERE NOT EXISTS (SELECT 1 FROM security_wallet w WHERE w.CLIENT_ID = c.ID AND w.APP_ID = a.ID) ORDER BY c.ID, a.ID LIMIT 1",
    )
    .fetch_one(&l.pool)
    .await
    .unwrap();
    let (client, app): (u64, u64) = (free.get(0), free.get(1));
    let mut tx = l.pool.begin().await.unwrap();
    let w = sql::create_seeded_wallet(&mut tx, client, app, Dec::ONE).await.unwrap().expect("seeded");
    assert_eq!((w.balance.to_string(), w.status.as_str(), w.low_balance_notified), ("1.0000".into(), "ACTIVE", Some(0)));
    // A second create finds the first.
    assert_eq!(sql::create_seeded_wallet(&mut tx, client, app, Dec::ONE).await.unwrap().map(|x| x.id), Some(w.id));
    let day = chrono::NaiveDate::from_ymd_opt(2026, 6, 15).unwrap();
    let txn = Txn {
        wallet_id: w.id,
        kind: "DEBIT",
        tokens: Dec::from_i64(3),
        balance_after: Dec::from_i64(-2),
        action_key: Some("security.app.rent".into()),
        app_id: Some(app),
        quantity: Some(Dec::parse("2.5").unwrap()),
        charge_date: Some(day),
        window_index: Some(4),
        idempotency_key: "live-test:rolled-back".into(),
        reason: "live test".into(),
        created_by: None,
    };
    assert!(sql::record_txn(&mut tx, &txn).await.unwrap());
    assert!(!sql::record_txn(&mut tx, &txn).await.unwrap(), "the idempotency key is unique");
    assert_eq!(sql::debit(&mut tx, w.id, Dec::from_i64(3)).await.unwrap(), 1);
    assert_eq!(sql::set_status(&mut tx, w.id, "SUSPENDED").await.unwrap(), 1);
    assert_eq!(sql::set_low_balance_notified(&mut tx, w.id, true).await.unwrap(), 1);
    let after = sql::wallet(&mut tx, client, app).await.unwrap().unwrap();
    assert_eq!((after.balance.to_string(), after.status.as_str(), after.low_balance_notified), ("-2.0000".into(), "SUSPENDED", Some(1)));
    let sum = sql::sum_quantity_between(&mut tx, w.id, "security.app.rent", day, day).await.unwrap();
    assert_eq!(sum.to_string(), "2.5000");
    assert_eq!(sql::sum_quantity_between(&mut tx, w.id, "nope", day, day).await.unwrap().to_string(), "0.0000");
    assert_eq!(sql::charged_windows(&mut tx, w.id, "security.app.rent", day).await.unwrap(), vec![4]);
    assert_eq!(sql::debit(&mut tx, u64::MAX, Dec::ONE).await.unwrap(), 0);
    tx.rollback().await.unwrap();
    let gone: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM security_wallet WHERE CLIENT_ID = {client} AND APP_ID = {app}"))
        .fetch_one(&l.pool)
        .await
        .unwrap();
    assert_eq!(gone, 0);

    // The reads the metering run makes, through the store.
    let db = security::data::Db::new(l.pool.clone());
    let apps: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_app WHERE CLIENT_ID = 1 AND APP_TYPE = 'APP'").fetch_one(&l.pool).await.unwrap();
    assert_eq!(db.count_apps(1, "APP").await.unwrap(), apps);
    assert!(db.count_users_with_profile(1, 2).await.unwrap() >= 0);
    assert!(db.wallet(u64::MAX, 1).await.unwrap().is_none());
    assert!(db.config_by_app_client(u64::MAX, 1).await.unwrap().is_none());
    let configured = sqlx::query("SELECT a.APP_CODE, c.CODE FROM security_app_billing_config b JOIN security_app a ON a.ID = b.APP_ID \
         JOIN security_client c ON c.ID = b.CLIENT_ID WHERE b.STATUS = 'ACTIVE' LIMIT 1")
        .fetch_optional(&l.pool)
        .await
        .unwrap();
    if let Some(r) = configured {
        let (a, c): (String, String) = (r.get(0), r.get(1));
        let cfg = db.config_by_codes(&a, &c).await.unwrap().expect("active config");
        assert!(cfg.is_active());
        assert_eq!(db.config_by_app_client(cfg.app_id, cfg.client_id).await.unwrap().map(|x| x.id), Some(cfg.id));
    }
}

/// The user-side DAO reads the routes reach only on some data, run directly
/// (`UserDAOIntegrationTest`, `DesignationDAOIntegrationTest`, `ProfileDAOIntegrationTest`).
#[tokio::test]
async fn user_dao_reads() {
    let Some(l) = live().await else { return };
    let db = security::data::Db::new(l.pool.clone());
    let owners = db.owners_of(1).await.unwrap();
    assert!(owners.iter().all(|u| u.client_id == 1 && u.status_code == "ACTIVE"));
    let expected: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT u.ID) FROM security_user u JOIN security_profile_user pu ON pu.USER_ID = u.ID \
         JOIN security_profile p ON p.ID = pu.PROFILE_ID JOIN security_profile_role pr ON pr.PROFILE_ID = p.ID \
         JOIN security_v2_role r ON r.ID = pr.ROLE_ID WHERE r.NAME = 'Owner' AND u.CLIENT_ID = 1 AND u.STATUS_CODE = 'ACTIVE'",
    )
    .fetch_one(&l.pool)
    .await
    .unwrap();
    assert_eq!(owners.len() as i64, expected);
    if let Some(id) = l.ids("SELECT ID FROM security_designation ORDER BY ID LIMIT 1").await.first() {
        let d = db.designation(*id).await.unwrap().expect("designation");
        assert_eq!(d.id, *id);
    }
    assert!(db.designation(u64::MAX).await.unwrap().is_none());
    let profiles = l.ids("SELECT PROFILE_ID FROM security_profile_user pu JOIN security_user u ON u.ID = pu.USER_ID WHERE u.CLIENT_ID = 1 LIMIT 3").await;
    let users = db.users_for_profiles(&profiles, 1).await.unwrap();
    assert!(!profiles.is_empty() == !users.is_empty());
    assert!(db.users_for_profiles(&[], 1).await.unwrap().is_empty());
    assert!(db.restricted_profiles(1, 2).await.unwrap().iter().all(|p| *p > 0));
    let roots = db.app_profiles(2, &[1]).await.unwrap();
    let distinct: std::collections::HashSet<_> = roots.iter().collect();
    assert_eq!(distinct.len(), roots.len());
    assert!(db.emails_of_users(&[]).await.unwrap().is_empty());
    assert!(db.user_ids_of_client(u64::MAX, false).await.unwrap().is_empty());
    assert!(!db.user_ids_of_client(1, true).await.unwrap().is_empty());
}
