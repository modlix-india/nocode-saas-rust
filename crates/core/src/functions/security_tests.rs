//! The Java tests of the security functions (`GetUserSubOrgTest`, `GetManagedClientIdsTest`,
//! `GetUsersByIdsTest`, `GetClientsByIdsTest`, `GetUsersForDistributionTest`,
//! `PartnerSecurityFunctionsTest`, `CallerSecurityFunctionsTest`), against [`World`].

use std::sync::Arc;

use axum::http::StatusCode;
use kirun::function::Function;
use platform::upstream::Upstream;
use serde_json::{json, Value};

use super::security_world::{anonymous, find, run, user, with_app, without_token, World};
use crate::clients::SecurityCalls;
use crate::error::CoreError;

const OWNER: &str = "Authorities.ROLE_Owner";
const PARTNER_MANAGER: &str = "Authorities.ROLE_Partner_Manager";

async fn world() -> (Arc<World>, Vec<Arc<dyn Function>>) {
    let w = World::new();
    let base = w.serve().await;
    let calls = Arc::new(SecurityCalls::new(Upstream::fixed(&[&base])).unwrap());
    let mut fns = super::security_fns::all(&calls);
    fns.extend(super::caller_security::all(&calls));
    (w, fns)
}

fn fin() -> crate::auth::Authentication {
    user(110, 7, "FIN", &[])
}

fn status(r: &Result<serde_json::Map<String, Value>, CoreError>) -> StatusCode {
    r.as_ref().map(|_| StatusCode::OK).unwrap_or_else(|e| e.status())
}

fn message(r: &Result<serde_json::Map<String, Value>, CoreError>) -> String {
    r.as_ref().err().map(|e| e.text()).unwrap_or_default()
}

// --- GetUserSubOrgTest ----------------------------------------------------------------------

#[tokio::test]
async fn sub_org() {
    let (w, fns) = world().await;
    let f = find(&fns, "GetUserSubOrg");
    let sig = f.get_signature();
    assert_eq!(sig.get_full_name(), "CoreServices.Security.GetUserSubOrg");

    // No userId: the current user, with their client and the URL app.
    w.answer("GET", "/api/security/users/internal/110/sub-org", 200, "[110,111,112]");
    let r = run(f.as_ref(), json!({}), fin(), true, true).await.unwrap();
    assert_eq!(r["userIds"], json!([110, 111, 112]));
    let c = w.last("/api/security/users/internal/110/sub-org");
    assert_eq!((c.query["appCode"].as_str(), c.query["clientId"].as_str()), ("leadzumptwo", "7"));

    // Their own id needs no lookup.
    let r = run(f.as_ref(), json!({"userId": "110"}), fin(), true, true).await.unwrap();
    assert_eq!(r["userIds"], json!([110, 111, 112]));
    assert_eq!(w.calls.lock().iter().filter(|c| c.path == "/api/security/users/internal/110").count(), 0);

    // Another user of the same client: their sub-org with their client.
    w.answer("GET", "/api/security/users/internal/111/sub-org", 200, "[111,121]");
    let r = run(f.as_ref(), json!({"userId": 111}), fin(), true, true).await.unwrap();
    assert_eq!(r["userIds"], json!([111, 121]));
    assert_eq!(w.last("/api/security/users/internal/111/sub-org").query["clientId"], "7");

    // A user of a managed client.
    w.answer("GET", "/api/security/users/internal/500/sub-org", 200, "[500]");
    let r = run(f.as_ref(), json!({"userId": 500}), fin(), true, true).await.unwrap();
    assert_eq!(r["userIds"], json!([500]));
    assert_eq!(w.last("/api/security/users/internal/500/sub-org").query["clientId"], "90");

    // Unrelated, SYSTEM's, unknown, not an id.
    let before = w.count("/api/security/users/internal/600/sub-org");
    assert_eq!(status(&run(f.as_ref(), json!({"userId": 600}), fin(), true, true).await), StatusCode::FORBIDDEN);
    assert_eq!(w.count("/api/security/users/internal/600/sub-org"), before);
    let bp = user(501, 90, "BP1", &[]);
    assert_eq!(status(&run(f.as_ref(), json!({"userId": 700}), bp.clone(), true, true).await), StatusCode::FORBIDDEN);
    let r = run(f.as_ref(), json!({"userId": 901}), fin(), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::BAD_REQUEST, "No user found with id : 901".into()));
    assert_eq!(status(&run(f.as_ref(), json!({"userId": "abc"}), fin(), true, true).await), StatusCode::BAD_REQUEST);

    // A partner may read its managing client's user.
    w.set_manages(|_, _| Some(false));
    let r = run(f.as_ref(), json!({"userId": 111}), bp, true, true).await.unwrap();
    assert_eq!(r["userIds"], json!([111, 121]));

    // An anonymous caller has none; outside a definition it is refused.
    let n = w.calls.lock().len();
    let r = run(f.as_ref(), json!({}), anonymous(7, "FIN"), true, true).await.unwrap();
    assert_eq!(r["userIds"], json!([]));
    let r = run(f.as_ref(), json!({}), fin(), false, true).await;
    assert_eq!(
        (status(&r), message(&r)),
        (StatusCode::FORBIDDEN, "CoreServices.Security.GetUserSubOrg can only be called from a server function".into())
    );
    assert_eq!(w.calls.lock().len(), n);
}

// --- GetManagedClientIdsTest ----------------------------------------------------------------

#[tokio::test]
async fn managed_client_ids() {
    let (w, fns) = world().await;
    let f = find(&fns, "GetManagedClientIds");
    w.answer("GET", "/api/security/clients/internal/managingClientIds", 200, "[7,90,91]");
    let r = run(f.as_ref(), json!({}), user(110, 7, "FIN", &[OWNER]), true, true).await.unwrap();
    assert_eq!(r["clientIds"], json!([7, 90, 91]));
    assert_eq!(w.last("/api/security/clients/internal/managingClientIds").query["clientId"], "7");

    // An owner who is also a partner manager takes the owner path.
    let r = run(f.as_ref(), json!({}), user(110, 7, "FIN", &[OWNER, PARTNER_MANAGER]), true, true).await.unwrap();
    assert_eq!(r["clientIds"], json!([7, 90, 91]));
    assert_eq!(w.count("/api/security/clients/internal/clientIdsOfManagers"), 0);

    // A partner manager: the clients they and their sub-org manage, the user asked once.
    w.answer("GET", "/api/security/users/internal/110/sub-org", 200, "[110,120,121]");
    w.answer("POST", "/api/security/clients/internal/clientIdsOfManagers", 200, "[90,92]");
    let r = run(f.as_ref(), json!({}), user(110, 7, "FIN", &[PARTNER_MANAGER]), true, true).await.unwrap();
    assert_eq!(r["clientIds"], json!([90, 92]));
    assert_eq!(w.last("/api/security/clients/internal/clientIdsOfManagers").body, "[110,120,121]");
    w.answer("GET", "/api/security/users/internal/110/sub-org", 200, "[]");
    run(f.as_ref(), json!({}), user(110, 7, "FIN", &[PARTNER_MANAGER]), true, true).await.unwrap();
    assert_eq!(w.last("/api/security/clients/internal/clientIdsOfManagers").body, "[110]");

    // Anyone else, and the anonymous caller: none, without asking.
    let n = w.calls.lock().len();
    let r = run(f.as_ref(), json!({}), user(110, 7, "FIN", &["Authorities.LEADZUMPTWO.ROLE_Deal_READ"]), true, true).await.unwrap();
    assert_eq!(r["clientIds"], json!([]));
    let r = run(f.as_ref(), json!({}), anonymous(7, "FIN"), true, true).await.unwrap();
    assert_eq!(r["clientIds"], json!([]));
    // Their own id is fine; another user's is refused.
    let r = run(f.as_ref(), json!({"userId": "110"}), user(110, 7, "FIN", &["X"]), true, true).await.unwrap();
    assert_eq!(r["clientIds"], json!([]));
    let r = run(f.as_ref(), json!({"userId": 120}), user(110, 7, "FIN", &[OWNER]), true, true).await;
    assert_eq!(status(&r), StatusCode::FORBIDDEN);
    assert!(message(&r).starts_with("GetManagedClientIds answers only for the current user"));
    assert_eq!(w.calls.lock().len(), n);
    assert_eq!(status(&run(f.as_ref(), json!({}), user(110, 7, "FIN", &[OWNER]), false, true).await), StatusCode::FORBIDDEN);
}

// --- GetUsersByIdsTest ----------------------------------------------------------------------

fn u(id: u64, client: u64, first: &str) -> Value {
    json!({"id": id, "clientId": client, "firstName": first, "lastName": format!("L{id}"), "emailId": format!("{first}@x.com"),
           "phoneNumber": format!("+91{id}"), "userName": first.to_lowercase(), "statusCode": "ACTIVE", "middleName": null,
           "profiles": []})
}

#[tokio::test]
async fn users_by_ids() {
    let (w, fns) = world().await;
    let f = find(&fns, "GetUsersByIds");
    let batch = "/api/security/users/internal/batch";
    w.answer("POST", batch, 200, &json!([u(110, 7, "Asha"), u(111, 7, "Ravi")]).to_string());
    let r = run(f.as_ref(), json!({"ids": [110, "111", 110, ""]}), fin(), true, true).await.unwrap();
    assert_eq!(w.last(batch).body, "[110,111]");
    let users = r["users"].as_object().unwrap();
    assert_eq!(users.len(), 2);
    assert_eq!(
        users["110"],
        json!({"id": 110, "clientId": 7, "userName": "asha", "emailId": "Asha@x.com", "phoneNumber": "+91110",
               "firstName": "Asha", "lastName": "L110", "statusCode": "ACTIVE"})
    );
    assert_eq!(w.count("/api/security/clients/internal/doesClientManageClient"), 0);

    // Unrelated clients' users are left out; 55 is checked once for its two users.
    w.set_manages(|m, c| Some(m == 7 && c == 90));
    w.answer("POST", batch, 200, &json!([u(110, 7, "A"), u(500, 90, "P"), u(900, 55, "S"), u(901, 55, "S2")]).to_string());
    let r = run(f.as_ref(), json!({"ids": [110, 500, 900, 901]}), fin(), true, true).await.unwrap();
    let keys: Vec<&String> = r["users"].as_object().unwrap().keys().collect();
    assert_eq!(keys, ["110", "500"]);
    assert_eq!(w.calls.lock().iter().filter(|c| c.path.ends_with("doesClientManageClient") && c.raw_query.contains("=55")).count(), 1);
    assert_eq!(w.count("/api/security/applications/internal/hasWriteAccess"), 0);

    // SYSTEM's users are never visible upward.
    w.set_manages(|_, _| Some(false));
    w.answer("POST", batch, 200, &json!([u(1, 1, "Root"), u(2, 1, "Root2"), u(110, 7, "Asha")]).to_string());
    for caller in [user(500, 90, "BP1", &[]), fin()] {
        let r = run(f.as_ref(), json!({"ids": [1, 2, 110]}), caller, true, true).await.unwrap();
        let keys: Vec<&String> = r["users"].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["110"]);
    }

    // A partner sees its managing client's users only for an app the managing client edits.
    w.answer("POST", batch, 200, &json!([u(110, 7, "Asha")]).to_string());
    let r = run(f.as_ref(), json!({"ids": [110]}), with_app(user(500, 90, "BP1", &[]), "someOtherApp"), true, true).await.unwrap();
    assert_eq!(r["users"], json!({}));
    let r = run(f.as_ref(), json!({"ids": [110]}), user(500, 90, "BP1", &[]), true, true).await.unwrap();
    assert!(r["users"].as_object().unwrap().contains_key("110"));

    // No ids: nothing asked; outside a definition: refused.
    let n = w.calls.lock().len();
    let r = run(f.as_ref(), json!({}), fin(), true, true).await.unwrap();
    assert_eq!(r["users"], json!({}));
    assert_eq!(w.calls.lock().len(), n);
    assert_eq!(status(&run(f.as_ref(), json!({"ids": [110]}), fin(), false, true).await), StatusCode::FORBIDDEN);
    // A user without an id is skipped; one whose client security cannot place is not related.
    w.answer("POST", batch, 200, r#"[{"clientId":7},{"id":3,"clientId":99999}]"#);
    w.set_manages(|_, c| if c == 99999 { None } else { Some(false) });
    let r = run(f.as_ref(), json!({"ids": [3]}), fin(), true, true).await.unwrap();
    assert_eq!(r["users"], json!({}));
}

// --- GetClientsByIdsTest / PartnerSecurityFunctionsTest -------------------------------------

fn c(id: u64, code: &str, name: &str) -> Value {
    json!({"id": id, "code": code, "name": name, "typeCode": "BUS", "levelType": "CUSTOMER", "statusCode": "ACTIVE",
           "tokenValidityMinutes": 0, "activeUsers": 0, "totalUsers": 0})
}

#[tokio::test]
async fn clients_by_ids() {
    let (w, fns) = world().await;
    let f = find(&fns, "GetClientsByIds");
    let batch = "/api/security/clients/internal/batch";
    let mut bp = c(90, "BP1", "Partner One");
    bp["owners"] = json!([{"id": 500, "clientId": 90, "firstName": "O500", "lastName": "L", "emailId": "o500@x.com", "statusCode": "ACTIVE"}, {"firstName": "no id"}]);
    w.answer("POST", batch, 200, &json!([c(7, "FIN", "Fincity"), bp]).to_string());
    w.set_manages(|m, c| Some(m == 7 && c == 90));
    let r = run(f.as_ref(), json!({"ids": [7, "90", 55, ""], "fetchOwners": true}), fin(), true, true).await.unwrap();
    let call = w.last(batch);
    assert_eq!((call.body.as_str(), call.query.get("fetchOwners").map(String::as_str)), ("[7,90]", Some("true")));
    let clients = r["clients"].as_object().unwrap();
    assert_eq!(clients.len(), 2);
    assert!(!clients.contains_key("55"));
    assert_eq!(
        clients["90"],
        json!({"id": 90, "code": "BP1", "name": "Partner One", "typeCode": "BUS", "levelType": "CUSTOMER", "statusCode": "ACTIVE",
               "tokenValidityMinutes": 0,
               "owners": [{"id": 500, "clientId": 90, "emailId": "o500@x.com", "firstName": "O500", "lastName": "L", "statusCode": "ACTIVE"}]})
    );
    assert_eq!(clients["7"]["owners"], json!([]));

    // No owners key unless asked; SYSTEM never visible upward; only unrelated ids: no batch.
    w.set_manages(|_, _| Some(false));
    w.answer("POST", batch, 200, &json!([c(7, "FIN", "Fincity")]).to_string());
    let r = run(f.as_ref(), json!({"ids": [7, 1]}), fin(), true, true).await.unwrap();
    assert!(w.last(batch).raw_query.is_empty());
    let clients = r["clients"].as_object().unwrap();
    assert_eq!(clients.len(), 1);
    assert!(!clients["7"].as_object().unwrap().contains_key("owners"));
    let n = w.count(batch);
    let r = run(f.as_ref(), json!({"ids": [55]}), fin(), true, true).await.unwrap();
    assert_eq!(r["clients"], json!({}));
    assert_eq!(w.count(batch), n);

    // The managing client when asked.
    let mut bp = c(90, "BP1", "Partner One");
    bp["managagingClient"] = c(7, "FIN", "Fincity");
    w.answer("POST", batch, 200, &json!([bp]).to_string());
    let r = run(f.as_ref(), json!({"ids": [90], "fetchManagingClient": true}), user(500, 90, "BP1", &[]), true, true).await.unwrap();
    assert_eq!(w.last(batch).query["fetchManagingClient"], "true");
    assert_eq!(r["clients"]["90"]["managingClient"]["code"], "FIN");
    assert!(r["clients"]["90"].get("owners").is_none());

    // Client managers and counts (PartnerSecurityFunctionsTest).
    w.set_manages(|_, _| Some(true));
    let mut bp = json!({"id": 90, "code": "BP1", "createdBy": "3", "clientManagers": [{"id": 114, "clientId": 7}]});
    w.answer("POST", batch, 200, &json!([bp.take()]).to_string());
    let r = run(f.as_ref(), json!({"ids": [90], "fetchClientManagers": true, "withCounts": true}), fin(), true, true).await.unwrap();
    assert_eq!(w.last(batch).query["fetchClientManagers"], "true");
    let got = &r["clients"]["90"];
    assert_eq!(got["clientManagers"][0]["id"], 114);
    assert_eq!((got["activeUsers"].clone(), got["totalUsers"].clone(), got["createdBy"].clone()), (json!(0), json!(0), json!(3)));
    assert!(got.get("owners").is_none());

    // An unknown client id is left out instead of failing the call.
    w.set_manages(|_, c| if c == 99999999 { None } else { Some(true) });
    w.answer("POST", batch, 200, r#"[{"id":90,"code":"BP1"},null,{"code":"no id"}]"#);
    let r = run(f.as_ref(), json!({"ids": [90, 99999999]}), fin(), true, true).await.unwrap();
    assert_eq!(w.last(batch).body, "[90]");
    assert_eq!(r["clients"].as_object().unwrap().keys().collect::<Vec<_>>(), ["90"]);

    assert_eq!(status(&run(f.as_ref(), json!({"ids": [7]}), fin(), false, true).await), StatusCode::FORBIDDEN);
    let r = run(f.as_ref(), json!({"ids": [7]}), anonymous_without_user(), true, true).await.unwrap();
    assert_eq!(r["clients"], json!({}));
}

fn anonymous_without_user() -> crate::auth::Authentication {
    crate::testing::auth(json!({"authenticated": false, "clientCode": "FIN"}), Some("SYSTEM"), Some("leadzumptwo"))
}

#[tokio::test]
async fn clients_denorm() {
    let (w, fns) = world().await;
    let f = find(&fns, "GetClientsDenorm");
    let path = "/api/security/clients/internal/clients/denorm/full";
    w.set_manages(|_, c| Some(c == 90));
    w.answer(
        "POST",
        path,
        200,
        r#"{"90":{"clientName":"BP One","statusCode":"ACTIVE","activeUsers":3,"userNames":"A, B","clientManagerIds":",114,"},"55":{"clientName":"x"}}"#,
    );
    let r = run(f.as_ref(), json!({"ids": [90, 55]}), fin(), true, true).await.unwrap();
    assert_eq!(w.last(path).body, "[90]");
    assert_eq!(
        r["denorm"],
        json!({"90": {"clientId": 90, "clientName": "BP One", "statusCode": "ACTIVE", "activeUsers": 3, "userNames": "A, B", "clientManagerIds": ",114,"}})
    );
    // Nothing for a visible id security has no data for; nothing asked for none visible.
    w.answer("POST", path, 200, "");
    let r = run(f.as_ref(), json!({"ids": [90]}), fin(), true, true).await.unwrap();
    assert_eq!(r["denorm"], json!({}));
    let n = w.count(path);
    run(f.as_ref(), json!({"ids": [55]}), fin(), true, true).await.unwrap();
    assert_eq!(w.count(path), n);
    assert_eq!(status(&run(f.as_ref(), json!({"ids": [90]}), fin(), false, true).await), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn client_users_page() {
    let (w, fns) = world().await;
    let f = find(&fns, "GetClientUsersPage");
    let path = "/api/security/users/internal/query";
    w.set_manages(|_, _| Some(true));
    w.answer("POST", path, 200, r#"{"content":[{"id":500,"clientId":90,"firstName":"F500"},{"id":501,"clientId":90},{"clientId":90}],"totalElements":5}"#);
    let r = run(
        f.as_ref(),
        json!({"clientId": "90", "condition": {"field": "statusCode", "value": "ACTIVE"}, "page": 1, "size": 2,
               "sort": {"property": "id", "direction": "DESC"}}),
        fin(),
        true,
        true,
    )
    .await
    .unwrap();
    let q: Value = serde_json::from_str(&w.last(path).body).unwrap();
    assert_eq!((q["page"].clone(), q["size"].clone()), (json!(1), json!(2)));
    assert_eq!(q["sort"], json!([{"direction": "DESC", "property": "id", "ignoreCase": false, "nullHandling": "NATIVE"}]));
    assert_eq!(q["condition"]["operator"], "AND");
    assert_eq!(q["condition"]["conditions"][1], json!({"field": "clientId", "operator": "EQUALS", "value": 90, "negate": false}));
    assert_eq!(r["users"].as_array().unwrap().len(), 2);
    assert_eq!((r["totalElements"].clone(), r["totalPages"].clone(), r["number"].clone(), r["size"].clone()), (json!(5), json!(3), json!(1), json!(2)));

    // Defaults: page 0, size 10, the default sort, the client filter alone.
    run(f.as_ref(), json!({"clientId": 90, "size": 0, "page": -3, "sort": [{"direction": "asc"}, 5]}), fin(), true, true).await.unwrap();
    let q: Value = serde_json::from_str(&w.last(path).body).unwrap();
    assert_eq!((q["page"].clone(), q["size"].clone(), q["sort"].clone()), (json!(0), json!(10), json!([])));
    assert_eq!(q["condition"]["field"], "clientId");
    run(f.as_ref(), json!({"clientId": 90, "condition": {"operator": "OR", "conditions": []}, "sort": "x"}), fin(), true, true).await.unwrap();
    let q: Value = serde_json::from_str(&w.last(path).body).unwrap();
    assert_eq!(q["condition"]["field"], "clientId");
    assert_eq!(q["sort"][0]["property"], "updatedAt");

    // Bad conditions, a missing client, an unrelated client, outside a definition.
    let r = run(f.as_ref(), json!({"clientId": 90, "condition": {"value": 1}}), fin(), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::BAD_REQUEST, "Invalid condition".into()));
    let r = run(f.as_ref(), json!({"clientId": 90, "condition": {"operator": "AND", "conditions": [{"value": 1}]}}), fin(), true, true).await;
    assert_eq!(status(&r), StatusCode::INTERNAL_SERVER_ERROR);
    let r = run(f.as_ref(), json!({}), fin(), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::BAD_REQUEST, "clientId is required".into()));
    w.set_manages(|_, _| Some(false));
    let n = w.count(path);
    let r = run(f.as_ref(), json!({"clientId": 55}), fin(), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::FORBIDDEN, "Not allowed to list the users of client 55".into()));
    assert_eq!(w.count(path), n);
    assert_eq!(status(&run(f.as_ref(), json!({"clientId": 90}), fin(), false, true).await), StatusCode::FORBIDDEN);
    // Security answering nothing: Java's chain completes empty.
    w.set_manages(|_, _| Some(true));
    w.answer("POST", path, 200, "");
    let r = run(f.as_ref(), json!({"clientId": 90}), fin(), true, true).await;
    assert_eq!(status(&r), StatusCode::NOT_FOUND);
    // Other condition kinds are passed on as given.
    w.answer("POST", path, 200, r#"{"content":[]}"#);
    for cond in [json!({"havingConditions": []}), json!({"aggregateFunction": "SUM"}), json!({"fieldExpr": {"a": 1}})] {
        run(f.as_ref(), json!({"clientId": 90, "condition": cond.clone()}), fin(), true, true).await.unwrap();
        let q: Value = serde_json::from_str(&w.last(path).body).unwrap();
        assert_eq!(q["condition"]["conditions"][0], cond);
    }
    let r = run(f.as_ref(), json!({"clientId": 90, "condition": {"operator": "AND", "conditions": 5}}), fin(), true, true).await;
    assert_eq!(status(&r), StatusCode::INTERNAL_SERVER_ERROR);
}

// --- GetUsersForDistributionTest -------------------------------------------------------------

#[tokio::test]
async fn users_for_distribution() {
    let (w, fns) = world().await;
    let f = find(&fns, "GetUsersForDistribution");
    let path = "/api/security/users/internal/processor";
    w.answer(
        "POST",
        path,
        200,
        r#"[{"id":1,"roleId":10,"designationId":30,"departmentId":40,"profileIds":[20]},
            {"id":2,"roleId":11,"designationId":31,"departmentId":41,"profileIds":[21,22]},
            {"id":3,"roleId":12,"designationId":32,"departmentId":42,"profileIds":[]},
            {"id":4,"roleId":null,"designationId":null,"departmentId":null,"profileIds":null},
            {"id":5,"roleId":13,"designationId":33,"departmentId":43,"profileIds":[23]},
            {"roleId":10}]"#,
    );
    w.set_manages_code(|m, c| (m == "FIN" && c == "BP1") || (m == "BP1" && c == "BP1"));

    // SYSTEM is never a pool for another client.
    for caller in [user(500, 90, "BP1", &[]), fin()] {
        let r = run(f.as_ref(), json!({"roleIds": [10], "clientCode": "SYSTEM"}), caller, true, true).await;
        assert_eq!(status(&r), StatusCode::FORBIDDEN);
    }
    assert_eq!(w.count(path), 0);

    let r = run(
        f.as_ref(),
        json!({"userIds": [5, 999], "roleIds": ["11"], "profileIds": [20], "designationIds": [32], "departmentIds": [77]}),
        fin(),
        true,
        true,
    )
    .await
    .unwrap();
    assert_eq!(r["userIds"], json!([1, 2, 3, 5]));
    let body: Value = serde_json::from_str(&w.last(path).body).unwrap();
    assert_eq!((body["clientCode"].clone(), body["appCode"].clone()), (json!("FIN"), json!("leadzumptwo")));
    let r = run(f.as_ref(), json!({"profileIds": [22]}), fin(), true, true).await.unwrap();
    assert_eq!(r["userIds"], json!([2]));
    let r = run(f.as_ref(), json!({"departmentIds": [41]}), fin(), true, true).await.unwrap();
    assert_eq!(r["userIds"], json!([2]));

    // An empty distribution asks nothing.
    let n = w.calls.lock().len();
    let r = run(f.as_ref(), json!({}), fin(), true, true).await.unwrap();
    assert_eq!(r["userIds"], json!([]));
    assert_eq!(w.calls.lock().len(), n);

    // A partner may draw from its managing client; not from an unrelated one.
    let r = run(f.as_ref(), json!({"roleIds": [10], "clientCode": "FIN"}), user(500, 90, "BP1", &[]), true, true).await.unwrap();
    assert_eq!(r["userIds"], json!([1]));
    let body: Value = serde_json::from_str(&w.last(path).body).unwrap();
    assert_eq!(body["clientCode"], "FIN");
    let n = w.count(path);
    let r = run(f.as_ref(), json!({"roleIds": [10], "clientCode": "OTHER"}), user(500, 90, "BP1", &[]), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::FORBIDDEN, "Client OTHER is not related to the current user's client".into()));
    assert_eq!(w.count(path), n);
    // FIN manages BP1: allowed downward; the caller's own code is its own.
    run(f.as_ref(), json!({"roleIds": [10], "clientCode": "BP1"}), fin(), true, true).await.unwrap();
    run(f.as_ref(), json!({"roleIds": [10], "clientCode": "FIN"}), fin(), true, true).await.unwrap();

    assert_eq!(status(&run(f.as_ref(), json!({"roleIds": ["ten"]}), fin(), true, true).await), StatusCode::BAD_REQUEST);
    assert_eq!(status(&run(f.as_ref(), json!({"roleIds": [10]}), fin(), false, true).await), StatusCode::FORBIDDEN);
    assert_eq!(status(&run(f.as_ref(), json!({"roleIds": ["99999999999999999999"]}), fin(), true, true).await), StatusCode::BAD_REQUEST);

    let params = f.get_signature().get_parameters();
    for name in ["userIds", "roleIds", "profileIds", "designationIds", "departmentIds"] {
        assert_eq!(params[name].get_schema().get_default_value(), Some(&json!([])), "{name}");
    }
    assert_eq!(params["clientCode"].get_schema().get_default_value(), Some(&json!("")));
}

// --- IsBeingManagedBy*, GetClient, the e-mail lists -------------------------------------------

#[tokio::test]
async fn managed_by_client_and_emails() {
    let (w, fns) = world().await;
    let by_code = find(&fns, "IsBeingManagedByCode");
    let by_id = find(&fns, "IsBeingManagedById");
    let get_client = find(&fns, "GetClient");
    w.set_manages_code(|m, c| m == "FIN" && c == "BP1");

    // Outside a definition Java's `ContextView.get` throws.
    let r = run(by_code.as_ref(), json!({"clientCode": "BP1", "managingClientCode": "FIN"}), fin(), false, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::INTERNAL_SERVER_ERROR, "Context does not contain key: KIRun Runtime".into()));
    let r = run(by_code.as_ref(), json!({"clientCode": "BP1", "managingClientCode": "FIN"}), fin(), true, true).await.unwrap();
    assert_eq!(r["result"], json!(true));
    let r = run(by_id.as_ref(), json!({"clientId": 90, "managingClientId": 7}), fin(), true, true).await.unwrap();
    assert_eq!(r["result"], json!(true));
    assert_eq!(status(&run(by_id.as_ref(), json!({"clientId": 90, "managingClientId": 7}), fin(), false, true).await), StatusCode::INTERNAL_SERVER_ERROR);
    w.answer("GET", "/api/security/clients/internal/doesClientManageClientCode", 200, "");
    let r = run(by_code.as_ref(), json!({"clientCode": "X", "managingClientCode": "Y"}), fin(), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::NOT_FOUND, "Function with id CoreServices.Security.IsBeingManagedByCode not found".into()));
    w.answer("GET", "/api/security/clients/internal/doesClientManageClient", 200, "");
    assert_eq!(status(&run(by_id.as_ref(), json!({"clientId": 1, "managingClientId": 2}), fin(), true, true).await), StatusCode::NOT_FOUND);

    // GetClient: by code or id, written as the Client DTO.
    w.answer(
        "GET",
        "/api/security/clients/internal/getClientByCode",
        200,
        r#"{"code":"FIN","id":7,"name":"Fin","tokenValidityMinutes":"30","totalUsers":4,"unknown":1,"activeUsers":4,
            "owners":[{"id":110,"profiles":[{"id":1,"name":"P","arrangement":{"a":null,"b":1}}],"client":{"id":7}}],
            "apps":[{"id":3,"appCode":"x","template":true}],"createdByUser":{"id":1}}"#,
    );
    let r = run(get_client.as_ref(), json!({"idOrCode": "FIN"}), fin(), true, true).await.unwrap();
    assert_eq!(
        r["client"],
        json!({"id": 7, "code": "FIN", "name": "Fin", "tokenValidityMinutes": 30, "activeUsers": 4, "inactiveUsers": 0, "deletedUsers": 0,
               "lockedUsers": 0, "passwordExpiredUsers": 0,
               "owners": [{"id": 110, "profiles": [{"id": 1, "name": "P", "defaultProfile": false, "arrangement": {"b": 1}}],
                           "client": {"id": 7, "tokenValidityMinutes": 0, "activeUsers": 0, "inactiveUsers": 0, "deletedUsers": 0, "lockedUsers": 0, "passwordExpiredUsers": 0}}],
               "apps": [{"id": 3, "appCode": "x", "isTemplate": true}], "createdByUser": {"id": 1}})
    );
    let r = run(get_client.as_ref(), json!({"idOrCode": 7}), fin(), true, true).await.unwrap();
    assert_eq!(r["client"]["code"], "FIN");
    assert_eq!(w.last("/api/security/clients/internal/getClientById").query["clientId"], "7");
    assert_eq!(status(&run(get_client.as_ref(), json!({"idOrCode": 12345}), fin(), true, true).await), StatusCode::NOT_FOUND);
    assert_eq!(status(&run(get_client.as_ref(), json!({"idOrCode": "FIN"}), fin(), false, true).await), StatusCode::INTERNAL_SERVER_ERROR);

    // GetUserAdminEmails / GetOwnersEmails: no definition gate, the codes as headers.
    let admin = find(&fns, "GetUserAdminEmails");
    let owners = find(&fns, "GetOwnersEmails");
    w.answer("GET", "/api/security/users/internal/adminEmails", 200, r#"{"emails":["a@x.com"],"addApp":true}"#);
    let r = run(admin.as_ref(), json!({"appCode": "leadzumptwo", "clientCode": "FIN"}), fin(), false, true).await.unwrap();
    assert_eq!((r["adminEmails"].clone(), r["addApp"].clone()), (json!(["a@x.com"]), json!(true)));
    let call = w.last("/api/security/users/internal/adminEmails");
    assert_eq!(call.headers.get("clientCode").unwrap(), "FIN");
    assert_eq!(call.headers.get("appCode").unwrap(), "leadzumptwo");
    w.answer("GET", "/api/security/users/internal/adminEmails", 200, "");
    let r = run(admin.as_ref(), json!({"appCode": "a", "clientCode": "b"}), fin(), false, true).await.unwrap();
    assert_eq!((r["adminEmails"].clone(), r["addApp"].clone()), (json!([]), json!(false)));
    w.answer("GET", "/api/security/users/internal/adminEmails", 200, r#"{"addApp":null}"#);
    assert_eq!(status(&run(admin.as_ref(), json!({"appCode": "a", "clientCode": "b"}), fin(), false, true).await), StatusCode::INTERNAL_SERVER_ERROR);
    w.answer("GET", "/api/security/users/internal/adminEmails", 200, r#"{"addApp":"yes"}"#);
    assert_eq!(status(&run(admin.as_ref(), json!({"appCode": "a", "clientCode": "b"}), fin(), false, true).await), StatusCode::INTERNAL_SERVER_ERROR);
    w.answer("GET", "/api/security/users/internal/ownerEmails", 200, r#"{"emails":["o@x.com",null]}"#);
    let r = run(owners.as_ref(), json!({"appCode": "a", "clientCode": "b"}), fin(), false, true).await.unwrap();
    assert_eq!(r["ownerEmails"], json!(["o@x.com", null]));
    w.answer("GET", "/api/security/users/internal/ownerEmails", 200, "");
    let r = run(owners.as_ref(), json!({"appCode": "a", "clientCode": "b"}), fin(), false, true).await.unwrap();
    assert_eq!(r["ownerEmails"], json!([]));
    w.answer("GET", "/api/security/users/internal/ownerEmails", 500, r#"{"message":"down"}"#);
    let r = run(owners.as_ref(), json!({"appCode": "a", "clientCode": "b"}), fin(), false, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::INTERNAL_SERVER_ERROR, "down".into()));
}

// --- CallerSecurityFunctionsTest --------------------------------------------------------------

fn assert_forwarded(call: &super::security_world::Call) {
    let h = |n: &str| call.headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    assert_eq!(h("authorization"), "tok-110");
    assert_eq!(h("x-forwarded-host"), "leadzumptwo.local.modlix.com");
    assert_eq!(h("x-forwarded-port"), "443");
    assert_eq!(h("clientcode"), "SYSTEM");
    assert_eq!(h("appcode"), "leadzumptwo");
}

/// Security's `GET users/{id}` for the world's users, its 404 for the others.
fn users_by_id(w: &World) {
    for (id, client) in &w.user_client {
        w.answer("GET", &format!("/api/security/users/{id}"), 200, &json!({"id": id, "clientId": client}).to_string());
    }
    w.answer("GET", "/api/security/users/999", 404, r#"{"message":"User with id 999 not found"}"#);
}

#[tokio::test]
async fn caller_gate() {
    let (w, fns) = world().await;
    let r = run(find(&fns, "GetUser").as_ref(), json!({"userId": 111}), fin(), false, true).await;
    assert_eq!(status(&r), StatusCode::FORBIDDEN);
    let r = run(find(&fns, "QueryUsers").as_ref(), json!({}), fin(), true, false).await;
    assert_eq!(status(&r), StatusCode::FORBIDDEN);
    assert!(message(&r).contains("no request to act as"));
    let r = run(find(&fns, "QueryUsers").as_ref(), json!({}), anonymous(7, "FIN"), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::FORBIDDEN, "CoreServices.Security.QueryUsers needs a signed in user".into()));
    let r = run(find(&fns, "QueryUsers").as_ref(), json!({}), without_token(fin()), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::FORBIDDEN, "CoreServices.Security.QueryUsers has no caller token to act with".into()));
    assert!(w.as_caller_calls().is_empty());
}

#[tokio::test]
async fn query_users() {
    let (w, fns) = world().await;
    let f = find(&fns, "QueryUsers");
    let page = json!({"content": [{"id": 111, "clientId": 7}], "totalElements": 1, "number": 0});
    w.answer("POST", "/api/security/users/query", 200, &page.to_string());
    let r = run(
        f.as_ref(),
        json!({"query": {"page": 0, "size": 50, "condition": {"field": "statusCode", "value": "ACTIVE"}},
               "fetchDesignation": true, "fetchReportingTo": true, "fetchProfiles": false, "appCode": " app ", "appId": "5"}),
        fin(),
        true,
        true,
    )
    .await
    .unwrap();
    assert_eq!(r["page"], page);
    let call = w.last("/api/security/users/query");
    assert_forwarded(&call);
    assert_eq!(call.raw_query, "fetchDesignation=true&fetchReportingTo=true&appCode=app&appId=5");
    let body: Value = serde_json::from_str(&call.body).unwrap();
    assert_eq!((body["size"].clone(), body["condition"]["field"].clone()), (json!(50), json!("statusCode")));

    // A condition naming an ancestor or an unrelated client: security answered first, then refused.
    for cond in [
        json!({"field": "clientId", "value": 1}),
        json!({"operator": "AND", "conditions": [{"field": "statusCode", "value": "ACTIVE"}, {"field": "clientId", "operator": "IN", "multiValue": [90, 55]}]}),
        json!({"field": "clientId", "operator": "IN", "value": "7, 55"}),
        json!({"field": "client_id", "toValue": 55}),
    ] {
        let n = w.as_caller_calls().len();
        let r = run(f.as_ref(), json!({"query": {"condition": cond}}), fin(), true, true).await;
        assert_eq!(status(&r), StatusCode::FORBIDDEN, "{cond}");
        assert!(message(&r).contains("is neither the caller's client nor one it manages"));
        assert_eq!(w.as_caller_calls().len(), n + 1);
    }
    // Own and managed clients, negated conditions and field values are fine.
    w.answer("POST", "/api/security/users/query", 200, r#"{"content":[]}"#);
    for cond in [
        json!({"field": "clientId", "value": "7"}),
        json!({"field": "clientId", "operator": "IN", "multiValue": ["7", 90]}),
        json!({"field": "clientId", "value": 55, "negate": true}),
        json!({"field": "clientId", "value": "createdBy", "isValueField": true}),
        json!({"operator": "OR", "negate": "true", "conditions": [{"field": "clientId", "value": 55}]}),
        json!({"field": 5, "value": 55}),
        json!("not an object"),
    ] {
        let r = run(f.as_ref(), json!({"query": {"condition": cond}}), fin(), true, true).await.unwrap();
        assert!(r["page"].is_object(), "{cond}");
    }
    // A bad id in a condition is a bad request.
    let r = run(f.as_ref(), json!({"query": {"condition": {"field": "clientId", "value": {"x": 1}}}}), fin(), true, true).await;
    assert_eq!(status(&r), StatusCode::BAD_REQUEST);

    // The clientId argument is ANDed in; an unrelated one refused.
    run(f.as_ref(), json!({"query": {"size": 5, "condition": {"field": "statusCode", "value": "ACTIVE"}}, "clientId": "90"}), fin(), true, true)
        .await
        .unwrap();
    let body: Value = serde_json::from_str(&w.last("/api/security/users/query").body).unwrap();
    assert_eq!(body["condition"]["operator"], "AND");
    assert_eq!(body["condition"]["conditions"][0]["field"], "statusCode");
    assert_eq!(body["condition"]["conditions"][1], json!({"field": "clientId", "operator": "EQUALS", "value": 90}));
    run(f.as_ref(), json!({"clientId": 90}), fin(), true, true).await.unwrap();
    let body: Value = serde_json::from_str(&w.last("/api/security/users/query").body).unwrap();
    assert_eq!(body["condition"]["field"], "clientId");
    run(f.as_ref(), json!({"clientId": 90, "query": {"condition": {}}}), fin(), true, true).await.unwrap();
    let body: Value = serde_json::from_str(&w.last("/api/security/users/query").body).unwrap();
    assert_eq!(body["condition"]["field"], "clientId");
    assert_eq!(status(&run(f.as_ref(), json!({"clientId": 55}), fin(), true, true).await), StatusCode::FORBIDDEN);

    // A partner cannot reach its managing client in a list or a write.
    let bp = user(501, 90, "BP1", &[]);
    let n = w.as_caller_calls().len();
    let r = run(f.as_ref(), json!({"query": {"condition": {"field": "clientId", "value": 7}}}), bp.clone(), true, true).await;
    assert_eq!(status(&r), StatusCode::FORBIDDEN);
    let r = run(find(&fns, "LogClientActivity").as_ref(), json!({"activity": {"clientId": 7, "activityName": "x"}}), bp.clone(), true, true).await;
    assert_eq!(status(&r), StatusCode::FORBIDDEN);
    let r = run(find(&fns, "SetUserStatus").as_ref(), json!({"userId": 111, "status": "ACTIVE"}), bp, true, true).await;
    assert_eq!(status(&r), StatusCode::FORBIDDEN);
    assert_eq!(w.as_caller_calls().len(), n + 1, "no write reached security");
}

#[tokio::test]
async fn get_user() {
    let (w, fns) = world().await;
    let f = find(&fns, "GetUser");
    users_by_id(&w);
    // A partner reads its managing client's user by id, but no other ancestor or partner.
    let bp = user(501, 90, "BP1", &[]);
    let r = run(f.as_ref(), json!({"userId": 111}), bp.clone(), true, true).await.unwrap();
    assert_eq!(r["user"]["clientId"], 7);
    for other in [700, 600] {
        assert_eq!(status(&run(f.as_ref(), json!({"userId": other}), bp.clone(), true, true).await), StatusCode::FORBIDDEN);
    }
    assert_eq!(status(&run(f.as_ref(), json!({"userId": 111}), user(601, 55, "OTHER", &[]), true, true).await), StatusCode::FORBIDDEN);
    for other in [600, 700] {
        let r = run(f.as_ref(), json!({"userId": other}), fin(), true, true).await;
        assert_eq!(status(&r), StatusCode::FORBIDDEN);
        assert!(message(&r).contains("is not the caller's client, one it manages or the client that manages it"));
    }
    let r = run(f.as_ref(), json!({"userId": 999}), fin(), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::NOT_FOUND, "User with id 999 not found".into()));

    // A user answered without its client is placed through the internal route.
    w.answer("GET", "/api/security/users/500", 200, r#"{"id":500,"firstName":"F"}"#);
    let r = run(f.as_ref(), json!({"userId": "500"}), fin(), true, true).await.unwrap();
    assert_eq!(r["user"]["id"], 500);
    assert_forwarded(&w.last("/api/security/users/500"));
    let n = w.count("/api/security/users/internal/");
    run(f.as_ref(), json!({"userId": 110}), fin(), true, true).await.unwrap();
    assert_eq!(w.count("/api/security/users/internal/"), n, "the caller themself needs no placing");
    // Placing a user security does not know internally, or cannot answer for.
    w.answer("GET", "/api/security/users/123", 200, r#"{"id":123}"#);
    assert_eq!(status(&run(f.as_ref(), json!({"userId": 123}), fin(), true, true).await), StatusCode::NOT_FOUND);
    w.answer("GET", "/api/security/users/124", 200, r#"{"id":124}"#);
    w.answer("GET", "/api/security/users/internal/124", 500, r#"{"message":"broken"}"#);
    let r = run(f.as_ref(), json!({"userId": 124}), fin(), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::INTERNAL_SERVER_ERROR, "broken".into()));
    w.answer("GET", "/api/security/users/internal/124", 404, "");
    assert_eq!(status(&run(f.as_ref(), json!({"userId": 124}), fin(), true, true).await), StatusCode::NOT_FOUND);
    // An empty answer is a null user.
    w.answer("GET", "/api/security/users/125", 200, "");
    let r = run(f.as_ref(), json!({"userId": 125}), fin(), true, true).await.unwrap();
    assert_eq!(r["user"], Value::Null);

    // Security's own refusal keeps its text.
    w.answer("GET", "/api/security/users/600", 403, r#"{"message":"Permission/Role User READ is required to use this operation"}"#);
    let r = run(f.as_ref(), json!({"userId": 600}), fin(), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::FORBIDDEN, "Permission/Role User READ is required to use this operation".into()));
    let n = w.as_caller_calls().len();
    assert_eq!(status(&run(f.as_ref(), json!({}), fin(), true, true).await), StatusCode::BAD_REQUEST);
    assert_eq!(w.as_caller_calls().len(), n);
}

#[tokio::test]
async fn user_writes() {
    let (w, fns) = world().await;
    let create = find(&fns, "CreateUser");
    w.answer("POST", "/api/security/users", 200, r#"{"id":800,"clientId":90}"#);
    let r = run(create.as_ref(), json!({"user": {"firstName": "A", "emailId": "a@x.com"}}), fin(), true, true).await.unwrap();
    assert_eq!(r["user"]["id"], 800);
    let call = w.last("/api/security/users");
    assert_forwarded(&call);
    assert_eq!(serde_json::from_str::<Value>(&call.body).unwrap()["emailId"], "a@x.com");
    run(create.as_ref(), json!({"user": {"firstName": "A", "clientId": "90"}}), fin(), true, true).await.unwrap();
    let n = w.as_caller_calls().len();
    assert_eq!(status(&run(create.as_ref(), json!({"user": {"clientId": 55}}), fin(), true, true).await), StatusCode::FORBIDDEN);
    assert_eq!(status(&run(create.as_ref(), json!({"user": "x"}), fin(), true, true).await), StatusCode::INTERNAL_SERVER_ERROR, "the signature refuses a non-object");
    assert_eq!(w.as_caller_calls().len(), n);

    let update = find(&fns, "UpdateUser");
    w.answer("PATCH", "/api/security/users/500", 200, r#"{"id":500,"firstName":"P"}"#);
    w.answer("PUT", "/api/security/users/500", 200, r#"{"id":500,"firstName":"Q"}"#);
    let r = run(update.as_ref(), json!({"userId": 500, "user": {"firstName": "P"}}), fin(), true, true).await.unwrap();
    assert_eq!(r["user"]["firstName"], "P");
    let call = w.last("/api/security/users/500");
    assert_forwarded(&call);
    assert_eq!(call.method, "PATCH");
    assert_eq!(call.body, r#"{"firstName":"P"}"#);
    let r = run(update.as_ref(), json!({"user": {"id": 500, "clientId": 90, "firstName": "Q"}, "partial": false}), fin(), true, true).await.unwrap();
    assert_eq!(r["user"]["firstName"], "Q");
    assert_eq!(w.last("/api/security/users/500").method, "PUT");
    let n = w.as_caller_calls().len();
    assert_eq!(status(&run(update.as_ref(), json!({"userId": 600, "user": {"firstName": "x"}}), fin(), true, true).await), StatusCode::FORBIDDEN);
    assert_eq!(status(&run(update.as_ref(), json!({"userId": 500, "user": {"clientId": 55}}), fin(), true, true).await), StatusCode::FORBIDDEN);
    assert_eq!(status(&run(update.as_ref(), json!({"user": {"firstName": "x"}}), fin(), true, true).await), StatusCode::BAD_REQUEST);
    assert_eq!(w.as_caller_calls().len(), n);

    let delete = find(&fns, "DeleteUser");
    w.answer("DELETE", "/api/security/users/500", 200, "");
    let r = run(delete.as_ref(), json!({"userId": 500}), fin(), true, true).await.unwrap();
    assert_eq!(r["deleted"], json!(true));
    assert_forwarded(&w.last("/api/security/users/500"));
    for (body, expected) in [("0", false), ("2", true), ("false", false), (r#"{"x":1}"#, true)] {
        w.answer("DELETE", "/api/security/users/500", 200, body);
        let r = run(delete.as_ref(), json!({"userId": 500}), fin(), true, true).await.unwrap();
        assert_eq!(r["deleted"], json!(expected), "{body}");
    }

    let status_fn = find(&fns, "SetUserStatus");
    w.answer("PATCH", "/api/security/users/makeUserActive", 200, "true");
    w.answer("PATCH", "/api/security/users/makeUserInActive", 200, "true");
    let r = run(status_fn.as_ref(), json!({"userId": 500, "status": "ACTIVE"}), fin(), true, true).await.unwrap();
    assert_eq!(r["result"], json!(true));
    assert_eq!(w.last("/api/security/users/makeUserActive").query["userId"], "500");
    run(status_fn.as_ref(), json!({"userId": 111, "status": "in_active"}), fin(), true, true).await.unwrap();
    assert_forwarded(&w.last("/api/security/users/makeUserInActive"));
    assert_eq!(status(&run(status_fn.as_ref(), json!({"userId": 500, "status": "DELETED"}), fin(), true, true).await), StatusCode::BAD_REQUEST);

    let assign = find(&fns, "AssignProfile");
    let remove = find(&fns, "RemoveProfile");
    w.answer("GET", "/api/security/users/500/assignProfile/207", 200, "true");
    w.answer("GET", "/api/security/users/500/removeProfile/207", 200, "false");
    let r = run(assign.as_ref(), json!({"userId": 500, "profileId": "207"}), fin(), true, true).await.unwrap();
    assert_eq!(r["result"], json!(true));
    assert_forwarded(&w.last("/api/security/users/500/assignProfile/207"));
    let r = run(remove.as_ref(), json!({"userId": 500, "profileId": 207}), fin(), true, true).await.unwrap();
    assert_eq!(r["result"], json!(false));
    assert_eq!(status(&run(assign.as_ref(), json!({"userId": 500}), fin(), true, true).await), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn client_writes_and_managers() {
    let (w, fns) = world().await;
    let set_status = find(&fns, "SetClientStatus");
    let delete = find(&fns, "DeleteClient");
    w.answer("GET", "/api/security/clients/makeClientInActive", 200, "true");
    w.answer("GET", "/api/security/clients/makeClientActive", 200, "true");
    w.answer("DELETE", "/api/security/clients/90", 200, "");
    let r = run(set_status.as_ref(), json!({"clientId": 90, "status": "INACTIVE"}), fin(), true, true).await.unwrap();
    assert_eq!(r["result"], json!(true));
    assert_forwarded(&w.last("/api/security/clients/makeClientInActive"));
    let r = run(delete.as_ref(), json!({"clientId": 90}), fin(), true, true).await.unwrap();
    assert_eq!(r["deleted"], json!(true));
    let n = w.as_caller_calls().len();
    for client in [7, 1, 55] {
        assert_eq!(status(&run(delete.as_ref(), json!({"clientId": client}), fin(), true, true).await), StatusCode::FORBIDDEN);
        assert_eq!(
            status(&run(set_status.as_ref(), json!({"clientId": client, "status": "ACTIVE"}), fin(), true, true).await),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(w.as_caller_calls().len(), n);

    let update = find(&fns, "UpdateClient");
    w.answer("PATCH", "/api/security/clients/90", 200, r#"{"id":90,"name":"N"}"#);
    w.answer("PUT", "/api/security/clients/90", 200, r#"{"id":90,"name":"M"}"#);
    let r = run(update.as_ref(), json!({"clientId": 90, "client": {"name": "N"}}), fin(), true, true).await.unwrap();
    assert_eq!(r["client"]["name"], "N");
    run(update.as_ref(), json!({"client": {"id": "90", "name": "M"}, "partial": false}), fin(), true, true).await.unwrap();
    let call = w.last("/api/security/clients/90");
    assert_forwarded(&call);
    assert_eq!(call.method, "PUT");
    assert_eq!(status(&run(update.as_ref(), json!({"clientId": 1, "client": {"name": "x"}}), fin(), true, true).await), StatusCode::FORBIDDEN);
    assert_eq!(status(&run(update.as_ref(), json!({"client": {"name": "x"}}), fin(), true, true).await), StatusCode::BAD_REQUEST);

    w.answer("POST", "/api/security/client-managers/111/90", 200, "true");
    w.answer("DELETE", "/api/security/client-managers/111/90", 200, "true");
    w.answer("POST", "/api/security/client-managers/90", 200, "true");
    w.answer("PUT", "/api/security/client-managers/90/managers", 200, "true");
    w.answer("POST", "/api/security/client-managers/migrateTo/111", 200, "3");
    let r = run(find(&fns, "AddClientManager").as_ref(), json!({"userId": 111, "clientId": 90}), fin(), true, true).await.unwrap();
    assert_eq!(r["result"], json!(true));
    assert_eq!(w.last("/api/security/client-managers/111/90").method, "POST");
    run(find(&fns, "RemoveClientManager").as_ref(), json!({"userId": 111, "clientId": 90}), fin(), true, true).await.unwrap();
    let call = w.last("/api/security/client-managers/111/90");
    assert_forwarded(&call);
    assert_eq!(call.method, "DELETE");
    let replace = find(&fns, "ReplaceClientManager");
    run(replace.as_ref(), json!({"clientId": 90, "newManagerId": 111}), fin(), true, true).await.unwrap();
    assert_eq!(w.last("/api/security/client-managers/90").raw_query, "newManagerId=111");
    run(replace.as_ref(), json!({"clientId": 90, "newManagerId": 111, "oldManagerId": "110"}), fin(), true, true).await.unwrap();
    assert_eq!(w.last("/api/security/client-managers/90").raw_query, "oldManagerId=110&newManagerId=111");
    run(find(&fns, "SetClientManagers").as_ref(), json!({"clientId": 90, "managerIds": [110, "111"]}), fin(), true, true).await.unwrap();
    assert_eq!(w.last("/api/security/client-managers/90/managers").body, "[110,111]");
    let r = run(find(&fns, "MigrateClientManagers").as_ref(), json!({"fromUserId": 110, "toUserId": 111}), fin(), true, true).await.unwrap();
    assert_eq!(r["count"], json!(3));
    let call = w.last("/api/security/client-managers/migrateTo/111");
    assert_forwarded(&call);
    assert_eq!(call.raw_query, "fromUid=110&removeManager=true");

    // Out-of-scope users and clients: nothing sent.
    let n = w.as_caller_calls().len();
    let cases = [
        ("SetClientManagers", json!({"clientId": 90, "managerIds": [110, 600]})),
        ("AddClientManager", json!({"userId": 111, "clientId": 55})),
        ("MigrateClientManagers", json!({"fromUserId": 700, "toUserId": 111})),
        ("ReplaceClientManager", json!({"clientId": 90, "newManagerId": 111, "oldManagerId": 600})),
    ];
    for (name, args) in cases {
        assert_eq!(status(&run(find(&fns, name).as_ref(), args, fin(), true, true).await), StatusCode::FORBIDDEN, "{name}");
    }
    assert_eq!(w.as_caller_calls().len(), n);
}

#[tokio::test]
async fn activities_and_app_profiles() {
    let (w, fns) = world().await;
    let log = find(&fns, "LogClientActivity");
    let query = find(&fns, "QueryClientActivities");
    w.answer("POST", "/api/security/client-activities", 200, r#"{"id":1,"clientId":7,"activityName":"T"}"#);
    w.answer("POST", "/api/security/client-activities/90/query", 200, r#"{"content":[],"totalElements":0}"#);
    let r = run(log.as_ref(), json!({"activity": {"activityName": "T", "description": "d"}}), fin(), true, true).await.unwrap();
    assert_eq!(r["activity"]["activityName"], "T");
    let call = w.last("/api/security/client-activities");
    assert_forwarded(&call);
    assert_eq!(serde_json::from_str::<Value>(&call.body).unwrap()["description"], "d");
    run(log.as_ref(), json!({"activity": {"activityName": 5, "clientId": 90}}), fin(), true, true).await.unwrap();
    let r = run(query.as_ref(), json!({"clientId": 90, "query": {"page": 0, "size": 20}}), fin(), true, true).await.unwrap();
    assert_eq!(r["page"]["totalElements"], 0);
    assert_eq!(serde_json::from_str::<Value>(&w.last("/api/security/client-activities/90/query").body).unwrap()["size"], 20);
    run(query.as_ref(), json!({"clientId": 90}), fin(), true, true).await.unwrap();
    assert_eq!(w.last("/api/security/client-activities/90/query").body, "{}");
    w.answer("POST", "/api/security/client-activities/55/query", 200, r#"{"content":[]}"#);
    assert_eq!(status(&run(query.as_ref(), json!({"clientId": 55}), fin(), true, true).await), StatusCode::FORBIDDEN);
    w.answer("POST", "/api/security/client-activities/55/query", 403, r#"{"message":"Permission/Role Client Activity is required to use this operation"}"#);
    let r = run(query.as_ref(), json!({"clientId": 55}), fin(), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::FORBIDDEN, "Permission/Role Client Activity is required to use this operation".into()));
    let n = w.as_caller_calls().len();
    let r = run(log.as_ref(), json!({"activity": {"clientId": 55, "activityName": " "}}), fin(), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::BAD_REQUEST, "Activity name is required".into()));
    assert_eq!(w.as_caller_calls().len(), n);

    let profiles = find(&fns, "GetAppProfiles");
    w.answer("GET", "/api/security/applications/appCode/leadzumptwo", 200, r#"{"id":848,"appCode":"leadzumptwo"}"#);
    w.answer("GET", "/api/security/app/848/profiles", 200, r#"{"content":[{"id":207}],"totalElements":1}"#);
    w.answer("GET", "/api/security/app/9/profiles", 200, r#"{"content":[]}"#);
    let r = run(profiles.as_ref(), json!({}), fin(), true, true).await.unwrap();
    assert_eq!(r["page"]["content"][0]["id"], 207);
    let call = w.last("/api/security/app/848/profiles");
    assert_forwarded(&call);
    assert!(call.raw_query.is_empty());
    run(profiles.as_ref(), json!({"appId": 9, "size": 100, "sort": "name,asc", "page": 2}), fin(), true, true).await.unwrap();
    assert_eq!(w.last("/api/security/app/9/profiles").raw_query, "page=2&size=100&sort=name%2Casc");
    w.answer("GET", "/api/security/applications/appCode/x", 200, "");
    let r = run(profiles.as_ref(), json!({"appCode": "x"}), fin(), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::NOT_FOUND, "No app found with code : x".into()));
    w.answer("GET", "/api/security/applications/appCode/y", 200, r#"{"appCode":"y"}"#);
    assert_eq!(status(&run(profiles.as_ref(), json!({"appCode": "y"}), fin(), true, true).await), StatusCode::NOT_FOUND);
    let r = run(profiles.as_ref(), json!({}), with_app(fin(), " "), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::BAD_REQUEST, "appId or appCode is required".into()));
}

#[tokio::test]
async fn security_refusals_and_scope_wording() {
    let (w, fns) = world().await;
    let update = find(&fns, "UpdateUser");
    w.answer("PATCH", "/api/security/users/500", 403, r#"{"message":"Forbidden to update user"}"#);
    let r = run(update.as_ref(), json!({"userId": 500, "user": {"firstName": "x"}}), fin(), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::FORBIDDEN, "Forbidden to update user".into()));

    let set_status = find(&fns, "SetUserStatus");
    let args = json!({"userId": 111, "status": "ACTIVE"});
    for (code, body, expected_status, expected) in [
        (403, "Access Denied", StatusCode::FORBIDDEN, "Access Denied".to_string()),
        (502, "", StatusCode::BAD_GATEWAY, "CoreServices.Security.SetUserStatus: security answered 502".to_string()),
        (500, "<html>x</html>", StatusCode::INTERNAL_SERVER_ERROR, "CoreServices.Security.SetUserStatus: security answered 500 (<html>x</html>)".to_string()),
        (409, r#"{"message":null}"#, StatusCode::CONFLICT, "CoreServices.Security.SetUserStatus: security answered 409".to_string()),
        (400, r#"{"message":5}"#, StatusCode::BAD_REQUEST, "5".to_string()),
        (599, "odd", StatusCode::BAD_GATEWAY, "odd".to_string()),
    ] {
        w.answer("PATCH", "/api/security/users/makeUserActive", code, body);
        let r = run(set_status.as_ref(), args.clone(), fin(), true, true).await;
        assert_eq!((status(&r), message(&r)), (expected_status, expected), "{code} {body}");
    }
    w.answer("PATCH", "/api/security/users/makeUserActive", 200, "not json at all");
    assert_eq!(status(&run(set_status.as_ref(), args.clone(), fin(), true, true).await), StatusCode::INTERNAL_SERVER_ERROR);
    w.answer("PATCH", "/api/security/users/makeUserActive", 200, "word");
    assert_eq!(run(set_status.as_ref(), args.clone(), fin(), true, true).await.unwrap()["result"], json!("word"));
    w.answer("PATCH", "/api/security/users/makeUserActive", 200, " ");
    assert_eq!(run(set_status.as_ref(), args.clone(), fin(), true, true).await.unwrap()["result"], Value::Null);

    // A tenant refusal of a write is worded as security would, and sends nothing.
    let n = w.as_caller_calls().len();
    let r = run(set_status.as_ref(), json!({"userId": 600, "status": "ACTIVE"}), fin(), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::FORBIDDEN, "Access Denied".into()));
    let admin = user(
        110,
        7,
        "FIN",
        &[
            "Authorities.User_UPDATE",
            "Authorities.User_DELETE",
            "Authorities.Profile_READ",
            "Authorities.Client_UPDATE",
            "Authorities.Client_DELETE",
            "Authorities.User_CREATE",
        ],
    );
    let cases = [
        ("SetUserStatus", json!({"userId": 600, "status": "INACTIVE"}), "selected user doesn't have access to change status code"),
        ("UpdateUser", json!({"userId": 600, "user": {"firstName": "x"}}), "Cannot update user for the selected client"),
        ("DeleteUser", json!({"userId": 600}), "Cannot update user for the selected client"),
        ("CreateUser", json!({"user": {"clientId": 55}}), "Cannot create User for the selected client"),
        ("AssignProfile", json!({"userId": 600, "profileId": 206}), "206 profile forbidden for the 600 user"),
        ("SetClientStatus", json!({"clientId": 55, "status": "ACTIVE"}), "selected client doesn't have access to change status code"),
        ("UpdateClient", json!({"clientId": 55, "client": {"name": "x"}}), "Permission/Role Client UPDATE is required to use this operation"),
        ("DeleteClient", json!({"clientId": 55}), "Permission/Role Client READ is required to use this operation"),
        ("AddClientManager", json!({"userId": 111, "clientId": 55}), "Permission/Role Client Manager CREATE is required to use this operation"),
        ("RemoveClientManager", json!({"userId": 600, "clientId": 90}), "Permission/Role Client Manager DELETE is required to use this operation"),
        ("ReplaceClientManager", json!({"clientId": 55, "newManagerId": 111}), "Permission/Role Client Manager UPDATE is required to use this operation"),
        ("SetClientManagers", json!({"clientId": 90, "managerIds": [600]}), "Permission/Role Client Manager SYNC is required to use this operation"),
        ("MigrateClientManagers", json!({"fromUserId": 600, "toUserId": 111}), "Permission/Role Client Manager MIGRATE is required to use this operation"),
        ("LogClientActivity", json!({"activity": {"clientId": 55, "activityName": "x"}}), "Permission/Role Client Activity is required to use this operation"),
        ("GetUser", json!({"userId": 600}), "CoreServices.Security.GetUser: client 55 is not the caller's client, one it manages or the client that manages it"),
    ];
    w.answer("GET", "/api/security/users/600", 200, r#"{"id":600,"clientId":55}"#);
    for (name, args, expected) in cases {
        let r = run(find(&fns, name).as_ref(), args, admin.clone(), true, true).await;
        assert_eq!((status(&r), message(&r)), (StatusCode::FORBIDDEN, expected.to_string()), "{name}");
    }
    let r = run(find(&fns, "SetClientStatus").as_ref(), json!({"clientId": 7, "status": "ACTIVE"}), admin.clone(), true, true).await;
    assert_eq!(status(&r), StatusCode::FORBIDDEN);
    assert!(message(&r).contains("own client"));
    assert_eq!(w.as_caller_calls().len(), n + 1, "only GetUser's read reached security");

    // An unknown user is answered as security would on that route.
    let cases = [
        ("DeleteUser", json!({"userId": 999}), StatusCode::NOT_FOUND, "User with id 999 not found"),
        ("UpdateUser", json!({"userId": 999, "user": {"id": 999}, "partial": false}), StatusCode::NOT_FOUND, "User with id 999 not found"),
        ("UpdateUser", json!({"userId": 999, "user": {"firstName": "x"}}), StatusCode::FORBIDDEN, "Cannot update user for the selected client"),
        ("SetUserStatus", json!({"userId": 999, "status": "ACTIVE"}), StatusCode::FORBIDDEN, "selected user doesn't have access to change status code"),
        ("AssignProfile", json!({"userId": 999, "profileId": 206}), StatusCode::NOT_FOUND, "User with id 999 not found"),
        ("MigrateClientManagers", json!({"fromUserId": 999, "toUserId": 111}), StatusCode::FORBIDDEN, "Permission/Role Client Manager MIGRATE is required to use this operation"),
        ("AddClientManager", json!({"userId": 999, "clientId": 90}), StatusCode::FORBIDDEN, "Permission/Role Client Manager CREATE is required to use this operation"),
        ("RemoveClientManager", json!({"userId": 999, "clientId": 90}), StatusCode::FORBIDDEN, "Permission/Role Client Manager DELETE is required to use this operation"),
        ("ReplaceClientManager", json!({"clientId": 90, "newManagerId": 999}), StatusCode::FORBIDDEN, "Permission/Role Client Manager UPDATE is required to use this operation"),
        ("SetClientManagers", json!({"clientId": 90, "managerIds": [999]}), StatusCode::FORBIDDEN, "Permission/Role Client Manager SYNC is required to use this operation"),
    ];
    for (name, args, s, m) in cases {
        let r = run(find(&fns, name).as_ref(), args, admin.clone(), true, true).await;
        assert_eq!((status(&r), message(&r)), (s, m.to_string()), "{name}");
    }
    let r = run(find(&fns, "DeleteUser").as_ref(), json!({"userId": 999}), fin(), true, true).await;
    assert_eq!((status(&r), message(&r)), (StatusCode::FORBIDDEN, "Access Denied".into()));
}

#[tokio::test]
async fn registered_in_java_order() {
    let storage = crate::testing::offline_storage_service().await;
    let deps = crate::testing::offline_deps("http://127.0.0.1:1", storage).await;
    let core = crate::repos::core_functions::CoreFunctions::new(&deps);
    use crate::repos::FunctionSource;
    for name in [
        "QueryUsers", "GetUser", "CreateUser", "UpdateUser", "DeleteUser", "SetUserStatus", "AssignProfile", "RemoveProfile",
        "SetClientStatus", "UpdateClient", "DeleteClient", "AddClientManager", "RemoveClientManager", "ReplaceClientManager",
        "SetClientManagers", "MigrateClientManagers", "LogClientActivity", "QueryClientActivities", "GetAppProfiles", "GetClient",
        "IsBeingManagedByCode", "IsBeingManagedById", "GetUserAdminEmails", "GetOwnersEmails", "GetUserSubOrg",
        "GetManagedClientIds", "GetUsersForDistribution", "GetUsersByIds", "GetClientsByIds", "GetClientUsersPage", "GetClientsDenorm",
    ] {
        assert!(core.find(Some("CoreServices.Security"), name).await.unwrap().is_some(), "{name}");
    }
}
