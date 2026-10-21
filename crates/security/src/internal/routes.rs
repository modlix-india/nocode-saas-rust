//! The routes of security-internal: request parsing as Spring does it, the response shapes the
//! Java controllers return.
//!
//! | Route group | Open to anonymous |
//! |---|---|
//! | `clients/internal/**`, `applications/internal/**`, `clienturls/internal/**` | yes |
//! | `users/internal/**`, `app/profiles/internal/**`, `internal/billing/**` | yes |
//! | `internal/cache/**`, `ssl/internal/certificates` | no |

use std::sync::Arc;

use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware;
use axum::routing::{delete, get, post};
use axum::Router;
use chrono::{Duration, NaiveDate};
use serde_json::Value;

use super::billing::{AiChargeRequest, ChargeRequest};
use super::clients::ClientFill;
use super::users::UserFill;
use super::Internal;
use crate::data::users::UsersListRequest;
use crate::errors::{AuthError, AuthResult, ONLY_SYS_USER_CERTS};
use crate::handlers::{body, security_headers};
use crate::jackson::{empty, json};
use crate::spring::Params;
use crate::web::*;

pub type State_ = Arc<Internal>;

pub fn router(state: State_) -> Router {
    Router::new()
        // ProfileController
        .route("/api/security/app/profiles/internal/users", get(profile_users))
        // AppController
        .route("/api/security/applications/internal/appCode/{appCode}", get(app_by_code))
        .route("/api/security/applications/internal/appInheritance", get(app_inheritance))
        .route("/api/security/applications/internal/appStatus/{appCode}", get(app_status))
        .route("/api/security/applications/internal/dependencies", get(app_dependencies))
        .route("/api/security/applications/internal/explicitInfo/{appCode}", get(app_explicit_info))
        .route("/api/security/applications/internal/hasReadAccess", get(has_read_access))
        .route("/api/security/applications/internal/hasWriteAccess", get(has_write_access))
        .route("/api/security/applications/internal/writeAccessClientCodes", get(write_access_client_codes))
        // ClientController
        .route("/api/security/clients/internal", get(clients_by_ids))
        .route("/api/security/clients/internal/activeClientCodes", post(active_client_codes))
        .route("/api/security/clients/internal/batch", post(clients_batch))
        .route("/api/security/clients/internal/clientHierarchy", get(client_hierarchy))
        .route("/api/security/clients/internal/clientHierarchyCodes", get(client_hierarchy_codes))
        .route("/api/security/clients/internal/clientIdsOfManager", get(client_ids_of_manager))
        .route("/api/security/clients/internal/clientIdsOfManagers", post(client_ids_of_managers))
        .route("/api/security/clients/internal/clients/denorm/full", post(clients_denorm))
        .route("/api/security/clients/internal/doesClientManageClient", get(does_client_manage_client))
        .route("/api/security/clients/internal/doesClientManageClientCode", get(does_client_manage_client_code))
        .route("/api/security/clients/internal/filterManagedClientCodes", post(filter_managed_client_codes))
        .route("/api/security/clients/internal/getClientByCode", get(client_by_code))
        .route("/api/security/clients/internal/getClientById", get(client_by_id))
        .route("/api/security/clients/internal/getClientNAppCode", get(client_n_app_code))
        .route("/api/security/clients/internal/getClientNAppCodeNType", get(client_n_app_code_n_type))
        .route("/api/security/clients/internal/isUserClientManageClient", get(is_user_client_manage_client))
        .route("/api/security/clients/internal/isUserPartOfHierarchy", get(is_user_part_of_hierarchy))
        .route("/api/security/clients/internal/managingClientIds", get(managing_client_ids))
        .route("/api/security/clients/internal/query", post(clients_query))
        .route("/api/security/clients/internal/validateClientCode", get(validate_client_code))
        .route("/api/security/clients/internal/{id}", get(client_internal))
        // ClientUrlController
        .route("/api/security/clienturls/internal/applications/property/url", get(app_url))
        .route("/api/security/clienturls/internal/draft/token/resolve", get(draft_token_resolve))
        // InternalBillingController
        .route("/api/security/internal/billing/ai-allowed", get(ai_allowed))
        .route("/api/security/internal/billing/charge", post(charge))
        .route("/api/security/internal/billing/charge-ai", post(charge_ai))
        .route("/api/security/internal/billing/hosting", get(hosting))
        .route("/api/security/internal/billing/instructions", get(instructions))
        .route("/api/security/internal/billing/meter/security", post(meter_security))
        .route("/api/security/internal/billing/reconcile", post(reconcile))
        .route("/api/security/internal/billing/serving-status", get(serving_status))
        // SecurityCacheController
        .route("/api/security/internal/cache", get(cache_names).delete(cache_evict_all))
        .route("/api/security/internal/cache/stats", get(cache_stats))
        .route("/api/security/internal/cache/{cacheName}", delete(cache_evict))
        // SSLCertificateController
        .route("/api/security/ssl/internal/certificates", get(certificates))
        // UserController
        .route("/api/security/users/internal", get(users_by_ids))
        .route("/api/security/users/internal/adminEmails", get(admin_emails))
        .route("/api/security/users/internal/batch", post(users_batch))
        .route("/api/security/users/internal/clients/batch", post(users_of_clients_batch))
        .route("/api/security/users/internal/notification", post(users_for_notification))
        .route("/api/security/users/internal/ownerEmails", get(owner_emails))
        .route("/api/security/users/internal/processor", post(users_for_processor))
        .route("/api/security/users/internal/query", post(users_query))
        .route("/api/security/users/internal/{id}", get(user_internal))
        .route("/api/security/users/internal/{userId}/sub-org", get(user_sub_org))
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// `UsersListRequest`.
fn users_list_body(bytes: &[u8]) -> AuthResult<UsersListRequest> {
    let v: Value = body(bytes)?;
    let user_ids = match v.get("userIds") {
        None | Some(Value::Null) => None,
        Some(Value::Array(a)) => Some(a.iter().map(|x| opt_i64(Some(x)).and_then(|n| n.ok_or_else(unreadable))).collect::<AuthResult<_>>()?),
        Some(_) => return Err(unreadable()),
    };
    Ok(UsersListRequest {
        user_ids,
        client_code: opt_text(v.get("clientCode"))?,
        client_id: opt_i64(v.get("clientId"))?,
        app_code: opt_text(v.get("appCode"))?,
    })
}

fn charge_body(bytes: &[u8]) -> AuthResult<Vec<ChargeRequest>> {
    let list: Vec<Value> = body(bytes)?;
    list.iter()
        .map(|v| {
            Ok(ChargeRequest {
                config_client_id: opt_u64_json(v.get("configClientId"))?,
                billed_client_id: opt_u64_json(v.get("billedClientId"))?,
                app_id: opt_u64_json(v.get("appId"))?,
                action_key: opt_text(v.get("actionKey"))?,
                quantity: dec_json(v.get("quantity"))?,
                date: epoch_date(v.get("date"))?,
                window_index: opt_i64(v.get("windowIndex"))?.map(|w| w as i32),
            })
        })
        .collect()
}

fn ai_charge_body(bytes: &[u8]) -> AuthResult<AiChargeRequest> {
    let v: Value = body(bytes)?;
    Ok(AiChargeRequest {
        client_code: opt_text(v.get("clientCode"))?,
        app_code: opt_text(v.get("appCode"))?,
        model: opt_text(v.get("model"))?,
        weighted_tokens: dec_json(v.get("weightedTokens"))?,
        request_id: opt_text(v.get("requestId"))?,
        session_id: opt_text(v.get("sessionId"))?,
    })
}


macro_rules! route {
    ($name:ident, $path:expr, $protected:expr, |$s:ident, $r:ident, $ca:ident| $body:block) => {
        $crate::web_route!($name, State_, $path, $protected, |$s, $r, $ca| $body);
    };
}

macro_rules! route_path {
    ($name:ident, $path:expr, $protected:expr, |$s:ident, $r:ident, $ca:ident, $p:ident| $body:block) => {
        $crate::web_route_path!($name, State_, $path, $protected, |$s, $r, $ca, $p| $body);
    };
}

// ---- ProfileController ----

route!(profile_users, "/app/profiles/internal/users", false, |s, r, ca| {
    let ids = req_u64_list(&r.params, "profileIds")?;
    let app = r.info.app_code();
    Ok(match s.profile_users(app.as_deref(), &ids).await? {
        Some(users) => ids_json(&users),
        None => nothing(),
    })
});

// ---- AppController ----

route_path!(app_by_code, "/applications/internal/appCode/{appCode}", false, |s, r, ca, code| {
    Ok(match s.dir().app_by_code(&code).await? {
        Some(a) => json(&a.to_json()),
        None => nothing(),
    })
});

route!(app_inheritance, "/applications/internal/appInheritance", false, |s, r, ca| {
    let app = req_str(&r.params, "appCode")?;
    let url_client = req_str(&r.params, "urlClientCode")?;
    let client = req_str(&r.params, "clientCode")?;
    Ok(match s.app_inheritance(app, url_client, client).await? {
        Some(l) => json(&Value::from((*l).clone())),
        None => nothing(),
    })
});

route_path!(app_status, "/applications/internal/appStatus/{appCode}", false, |s, r, ca, code| {
    Ok(match s.app_status(&code).await? {
        Some(st) => text(&st),
        None => nothing(),
    })
});

route!(app_dependencies, "/applications/internal/dependencies", false, |s, r, ca| {
    let app = req_str(&r.params, "appCode")?;
    Ok(match s.app_dependencies(app).await? {
        Some(deps) => json(&Value::from(deps.iter().map(|d| crate::jackson::opt(d.dependent_app_code.clone())).collect::<Vec<_>>())),
        None => nothing(),
    })
});

route_path!(app_explicit_info, "/applications/internal/explicitInfo/{appCode}", false, |s, r, ca, code| {
    Ok(match s.app_explicit_info(&code).await? {
        Some(a) => json(&a.to_json()),
        None => nothing(),
    })
});

route!(has_read_access, "/applications/internal/hasReadAccess", false, |s, r, ca| {
    let app = req_str(&r.params, "appCode")?;
    let client = req_str(&r.params, "clientCode")?;
    Ok(json(&Value::Bool(s.dir().has_read_access(app, Some(client)).await?)))
});

route!(has_write_access, "/applications/internal/hasWriteAccess", false, |s, r, ca| {
    let app = req_str(&r.params, "appCode")?;
    let client = req_str(&r.params, "clientCode")?;
    Ok(json(&Value::Bool(s.db.has_write_access(app, client).await?)))
});

route!(write_access_client_codes, "/applications/internal/writeAccessClientCodes", false, |s, r, ca| {
    let app = req_str(&r.params, "appCode")?;
    Ok(json(&Value::from(s.db.write_access_client_codes(app).await?)))
});

// ---- ClientController ----

route!(clients_by_ids, "/clients/internal", false, |s, r, ca| {
    let ids = req_u64_list(&r.params, "clientIds")?;
    Ok(json(&Value::Array(s.clients_by_ids(&ca, &ids, &ClientFill::from_params(&r.params)).await?)))
});

route!(active_client_codes, "/clients/internal/activeClientCodes", false, |s, r, ca| {
    let codes = string_list_body(&r.body)?;
    Ok(json(&Value::from(s.db.active_client_codes(&codes).await?)))
});

route!(clients_batch, "/clients/internal/batch", false, |s, r, ca| {
    let ids = id_list_body(&r.body)?;
    Ok(json(&Value::Array(s.clients_by_ids(&ca, &ids, &ClientFill::from_params(&r.params)).await?)))
});

route!(client_hierarchy, "/clients/internal/clientHierarchy", false, |s, r, ca| {
    let id = req_u64(&r.params, "clientId")?;
    Ok(ids_json(&s.client_hierarchy_ids(id).await?))
});

route!(client_hierarchy_codes, "/clients/internal/clientHierarchyCodes", false, |s, r, ca| {
    let code = req_str(&r.params, "clientCode")?;
    Ok(json(&Value::from(s.client_hierarchy_codes(code).await?)))
});

route!(client_ids_of_manager, "/clients/internal/clientIdsOfManager", false, |s, r, ca| {
    let id = req_u64(&r.params, "managerId")?;
    Ok(ids_json(&s.db.client_ids_of_manager(id).await?))
});

route!(client_ids_of_managers, "/clients/internal/clientIdsOfManagers", false, |s, r, ca| {
    let ids = id_list_body(&r.body)?;
    Ok(ids_json(&s.db.client_ids_of_managers(&ids).await?))
});

route!(clients_denorm, "/clients/internal/clients/denorm/full", false, |s, r, ca| {
    let ids = id_list_body(&r.body)?;
    let mut m = serde_json::Map::new();
    for (id, d) in s.clients_denorm(&ids).await? {
        m.insert(id.to_string(), d.to_json());
    }
    Ok(json(&Value::Object(m)))
});

route!(does_client_manage_client, "/clients/internal/doesClientManageClient", false, |s, r, ca| {
    let managing = opt_u64(&r.params, "managingClientId")?;
    let client = opt_u64(&r.params, "clientId")?;
    let (Some(m), Some(c)) = (managing, client) else {
        return Err(AuthError::internal("Cannot invoke \"org.jooq.types.ULong.equals(Object)\" because \"managingClientId\" is null"));
    };
    Ok(json(&Value::Bool(s.is_client_being_managed_by(m, c).await?)))
});

route!(does_client_manage_client_code, "/clients/internal/doesClientManageClientCode", false, |s, r, ca| {
    let (Some(m), Some(c)) = (r.params.get("managingClientCode"), r.params.get("clientCode")) else { return Ok(nothing()) };
    let (Some(m), Some(c)) = (s.client_by_code(m).await?, s.client_by_code(c).await?) else { return Ok(nothing()) };
    Ok(json(&Value::Bool(s.is_client_being_managed_by(m.id(), c.id()).await?)))
});

route!(filter_managed_client_codes, "/clients/internal/filterManagedClientCodes", false, |s, r, ca| {
    let managing = req_str(&r.params, "managingClientCode")?.to_string();
    let codes = string_list_body(&r.body)?;
    Ok(json(&Value::from(s.filter_managed_client_codes(&managing, &codes).await?)))
});

route!(client_by_code, "/clients/internal/getClientByCode", false, |s, r, ca| {
    let code = req_str(&r.params, "clientCode")?;
    Ok(match s.client_by_code(code).await? {
        Some(c) => json(&crate::dto::client_json(&c, &Default::default())),
        None => nothing(),
    })
});

route!(client_by_id, "/clients/internal/getClientById", false, |s, r, ca| {
    let id = req_u64(&r.params, "clientId")?;
    Ok(match s.dir().client(id).await? {
        Some(c) => json(&crate::dto::client_json(&c, &Default::default())),
        None => nothing(),
    })
});

/// `getClientPattern(scheme, host, port)` for the two tuple routes.
async fn client_pattern(s: &Internal, p: &Params) -> AuthResult<Option<Arc<crate::model::UrlPattern>>> {
    let scheme = req_str(p, "scheme")?;
    let host = req_str(p, "host")?;
    let port = req_str(p, "port")?;
    s.dir().client_pattern(scheme, host, port).await
}

route!(client_n_app_code, "/clients/internal/getClientNAppCode", false, |s, r, ca| {
    let v = match client_pattern(&s, &r.params).await? {
        Some(p) => vec![crate::jackson::opt(p.client_code.clone()), crate::jackson::opt(p.app_code.clone())],
        None => vec![Value::from("SYSTEM"), Value::from("nothing")],
    };
    Ok(json(&Value::Array(v)))
});

route!(client_n_app_code_n_type, "/clients/internal/getClientNAppCodeNType", false, |s, r, ca| {
    let v = match client_pattern(&s, &r.params).await? {
        Some(p) => vec![
            crate::jackson::opt(p.client_code.clone()),
            crate::jackson::opt(p.app_code.clone()),
            Value::from(p.url_type.clone().unwrap_or_else(|| "LIVE".into())),
        ],
        None => vec![Value::from("SYSTEM"), Value::from("nothing"), Value::from("LIVE")],
    };
    Ok(json(&Value::Array(v)))
});

route!(is_user_client_manage_client, "/clients/internal/isUserClientManageClient", false, |s, r, ca| {
    let app = r.params.get("appCode");
    let user = opt_u64(&r.params, "userId")?;
    let user_client = opt_u64(&r.params, "userClientId")?;
    let target = opt_u64(&r.params, "targetClientId")?;
    let Some(user_client) = user_client else {
        return Err(AuthError::internal("Cannot invoke \"org.jooq.types.ULong.equals(Object)\" because \"userClientId\" is null"));
    };
    let (Some(user), Some(target)) = (user, target) else {
        return Err(AuthError::internal("Cannot invoke \"org.jooq.types.ULong.equals(Object)\" because \"managingClientId\" is null"));
    };
    Ok(json(&Value::Bool(s.is_user_client_manage_client(app, user, user_client, target).await?)))
});

route!(is_user_part_of_hierarchy, "/clients/internal/isUserPartOfHierarchy", false, |s, r, ca| {
    let user = req_u64(&r.params, "userId")?;
    let code = req_str(&r.params, "clientCode")?;
    Ok(json(&Value::Bool(s.is_user_part_of_hierarchy(code, user).await?)))
});

route!(managing_client_ids, "/clients/internal/managingClientIds", false, |s, r, ca| {
    let id = req_u64(&r.params, "clientId")?;
    Ok(ids_json(&s.db.managing_client_ids(id).await?))
});

route!(clients_query, "/clients/internal/query", false, |s, r, ca| {
    let (page, cond) = query_body(&r.body)?;
    Ok(json(&s.clients_page(&ca, &page, cond.as_ref(), &ClientFill::from_params(&r.params)).await?))
});

route!(validate_client_code, "/clients/internal/validateClientCode", false, |s, r, ca| {
    let code = req_str(&r.params, "clientCode")?;
    Ok(match s.client_by_code(code).await? {
        Some(_) => json(&Value::Bool(true)),
        None => nothing(),
    })
});

route_path!(client_internal, "/clients/internal/{id}", false, |s, r, ca, id| {
    let id = to_u64(&id)?;
    Ok(match s.client_by_id_filled(id, &ClientFill::from_params(&r.params)).await? {
        Some(v) => json(&v),
        None => nothing(),
    })
});

// ---- ClientUrlController ----

route!(app_url, "/clienturls/internal/applications/property/url", false, |s, r, ca| {
    let app = req_str(&r.params, "appCode")?;
    Ok(text(&s.app_url(&ca, Some(app), r.params.get("clientCode")).await?))
});

route!(draft_token_resolve, "/clienturls/internal/draft/token/resolve", false, |s, r, ca| {
    let host = req_str(&r.params, "host")?;
    let app = r.params.get("appCode").unwrap_or("");
    let client = r.params.get("clientCode").unwrap_or("");
    Ok(json(&s.resolve_draft_token(host, app, client).await))
});

// ---- InternalBillingController ----

route!(instructions, "/internal/billing/instructions", false, |s, r, ca| {
    let action = req_str(&r.params, "action")?;
    let list = s.billing.charge_instructions(action).await?;
    Ok(json(&Value::Array(list.iter().map(|i| i.to_json()).collect())))
});

route!(meter_security, "/internal/billing/meter/security", false, |s, r, ca| {
    s.meter_current_window(&ca).await?;
    Ok(json(&Value::Bool(true)))
});

route!(reconcile, "/internal/billing/reconcile", false, |s, r, ca| {
    let day = match r.params.get("date") {
        None => s.auth.clock.local().date() - Duration::days(1),
        Some(d) => NaiveDate::parse_from_str(d, "%Y-%m-%d")
            .map_err(|_| AuthError::internal(format!("Text '{d}' could not be parsed at index 0")))?,
    };
    s.reconcile_day(&ca, day).await?;
    Ok(json(&Value::Bool(true)))
});

route!(charge, "/internal/billing/charge", false, |s, r, ca| {
    let requests = charge_body(&r.body)?;
    s.charge_bulk(&ca, &requests).await;
    Ok(json(&Value::Bool(true)))
});

route!(charge_ai, "/internal/billing/charge-ai", false, |s, r, ca| {
    let req = ai_charge_body(&r.body)?;
    Ok(json(&s.charge_ai(&ca, &req).await?.to_json()))
});

route!(ai_allowed, "/internal/billing/ai-allowed", false, |s, r, ca| {
    let app = req_str(&r.params, "appCode")?;
    let client = req_str(&r.params, "clientCode")?;
    Ok(json(&Value::Bool(s.is_ai_allowed(app, client).await?)))
});

// Java can never answer this one: `InternalBillingController` has no `ULong` binder, so every
// `clientId` is a "Type mismatch." 400. Served here (DIFFERENCES.md); nothing calls it yet.
route!(serving_status, "/internal/billing/serving-status", false, |s, r, ca| {
    let app = req_str(&r.params, "urlAppCode")?;
    let client = req_str(&r.params, "urlClientCode")?;
    let id = req_u64(&r.params, "clientId")?;
    Ok(json(&s.serving_status(app, client, id).await?))
});

route!(hosting, "/internal/billing/hosting", false, |s, r, ca| {
    let app = req_str(&r.params, "urlAppCode")?;
    let client = req_str(&r.params, "urlClientCode")?;
    Ok(json(&s.hosting(app, client).await?))
});

// ---- SecurityCacheController ----

route!(cache_names, "/internal/cache", true, |s, r, ca| {
    let names: Vec<String> = s.caches().service.local_cache_names().into_iter().map(|(n, _)| n).collect();
    Ok(json(&Value::from(names)))
});

route!(cache_stats, "/internal/cache/stats", true, |s, r, ca| {
    let mut out = serde_json::Map::new();
    for (name, st) in s.caches().service.local_cache_stats() {
        let requests = st.hits + st.misses;
        let rate = if requests == 0 { 1.0 } else { st.hits as f64 / requests as f64 };
        let one = crate::jackson::Obj::new()
            .put("entries", st.entries)
            .put("weightedBytes", -1)
            .put("hitCount", st.hits)
            .put("missCount", st.misses)
            .put("hitRate", rate)
            .put("evictionCount", st.evictions)
            .build();
        out.insert(name, one);
    }
    Ok(json(&Value::Object(out)))
});

route!(cache_evict_all, "/internal/cache", true, |s, r, ca| {
    Ok(match s.caches().service.evict_all_caches().await {
        Some(b) => json(&Value::Bool(b)),
        None => nothing(),
    })
});

route_path!(cache_evict, "/internal/cache/{cacheName}", true, |s, r, ca, name| {
    s.caches().service.evict_all_everywhere(&name).await;
    Ok(json(&Value::Bool(true)))
});

// ---- SSLCertificateController ----

route!(certificates, "/ssl/internal/certificates", true, |s, r, ca| {
    if !ca.is_system_client() {
        return Err(AuthError::msg(StatusCode::INTERNAL_SERVER_ERROR, ONLY_SYS_USER_CERTS, &[]));
    }
    let updated = s.certificates_last_updated().await?;
    // The ETag goes out quoted, as HTTP has it, and nginxconf.js sends it back as it came, so compare
    // the tag inside the quotes (a weak `W/` prefix too). Comparing the raw header never matched, so
    // every LB run got a 200 and restarted nginx: a refused connection every 5 minutes (QA-0469).
    let sent = r.info.header("If-None-Match");
    let sent = sent.as_deref().map(|v| v.trim().trim_start_matches("W/").trim_matches('"'));
    if sent == Some(updated.as_str()) {
        return Ok(empty(StatusCode::NOT_MODIFIED));
    }
    let list = s.certificates().await?;
    let mut resp = json(&Value::Array(list.iter().map(|c| c.to_json()).collect()));
    if let Ok(v) = HeaderValue::from_str(&format!("\"{updated}\"")) {
        resp.headers_mut().insert(header::ETAG, v);
    }
    Ok(resp)
});

// ---- UserController ----

route!(users_by_ids, "/users/internal", false, |s, r, ca| {
    let ids = req_u64_list(&r.params, "userIds")?;
    Ok(json(&Value::Array(s.users_by_ids(&ca, &ids, &UserFill::from_params(&r.params)).await?)))
});

route!(admin_emails, "/users/internal/adminEmails", false, |s, r, ca| {
    Ok(json(&s.admin_emails(r.info.app_code().as_deref(), r.info.client_code().as_deref()).await?))
});

route!(owner_emails, "/users/internal/ownerEmails", false, |s, r, ca| {
    Ok(json(&s.owner_emails(r.info.app_code().as_deref(), r.info.client_code().as_deref()).await?))
});

route!(users_batch, "/users/internal/batch", false, |s, r, ca| {
    let ids = id_list_body(&r.body)?;
    Ok(json(&Value::Array(s.users_by_ids(&ca, &ids, &UserFill::from_params(&r.params)).await?)))
});

route!(users_of_clients_batch, "/users/internal/clients/batch", false, |s, r, ca| {
    let ids = id_list_body(&r.body)?;
    Ok(json(&Value::Array(s.users_by_client_ids(&ca, &ids, &r.params, &UserFill::from_params(&r.params)).await?)))
});

route!(users_for_notification, "/users/internal/notification", false, |s, r, ca| {
    let req = users_list_body(&r.body)?;
    Ok(json(&Value::Array(s.users_for_notification(&req).await?)))
});

route!(users_for_processor, "/users/internal/processor", false, |s, r, ca| {
    let req = users_list_body(&r.body)?;
    Ok(json(&Value::Array(s.users_for_processor(&req).await?)))
});

route!(users_query, "/users/internal/query", false, |s, r, ca| {
    let (page, cond) = query_body(&r.body)?;
    Ok(json(&s.users_page(&ca, &page, cond.as_ref(), &UserFill::from_params(&r.params)).await?))
});

route_path!(user_internal, "/users/internal/{id}", false, |s, r, ca, id| {
    let id = to_u64(&id)?;
    Ok(match s.user_by_id_filled(&ca, id, &UserFill::from_params(&r.params)).await? {
        Some(v) => json(&v),
        None => nothing(),
    })
});

route_path!(user_sub_org, "/users/internal/{userId}/sub-org", false, |s, r, ca, user| {
    let user = to_u64(&user)?;
    let app = req_str(&r.params, "appCode")?;
    let client = req_u64(&r.params, "clientId")?;
    Ok(ids_json(&s.user_sub_org(app, client, user).await?))
});

#[cfg(test)]
mod tests {
    use super::*;

    fn params(q: &str) -> Params {
        Params::from_query(Some(q))
    }

    #[test]
    fn spring_parameter_conversion() {
        assert_eq!(req_u64(&params("a=5"), "a").unwrap(), 5);
        assert!(req_u64(&params("a=-5"), "a").is_err());
        assert_eq!(req_u64(&params("a=%2B7"), "a").unwrap(), 7);
        assert_eq!(req_u64(&params("a=-0"), "a").unwrap(), 0);
        assert!(req_u64(&params("a=%2B"), "a").is_err());
        assert!(req_u64(&params("a=99999999999999999999"), "a").is_err());
        assert!(req_u64(&params("a="), "a").is_err());
        let e = req_u64(&params(""), "a").unwrap_err();
        assert_eq!(e.to_string(), "400 Bad Request: 400 BAD_REQUEST \"Required query parameter 'a' is not present.\"");
        assert_eq!(opt_u64(&params(""), "a").unwrap(), None);
        assert_eq!(req_u64_list(&params("ids=4&ids=1"), "ids").unwrap(), vec![4, 1]);
        assert_eq!(req_u64_list(&params("ids="), "ids").unwrap(), Vec::<u64>::new());
        assert!(req_u64_list(&params("ids=4,1"), "ids").is_err());
        assert!(req_u64_list(&params("ids=1&ids="), "ids").is_err());
        assert!(req_u64_list(&params(""), "ids").is_err());
    }

    #[test]
    fn bodies() {
        assert_eq!(id_list_body(b"[1, \"2\"]").unwrap(), vec![1, 2]);
        assert!(id_list_body(b"[-1]").is_err());
        assert!(id_list_body(b"[null]").is_err());
        assert!(id_list_body(b"[true]").is_err());
        assert!(id_list_body(b"").is_err());
        assert_eq!(string_list_body(b"[\"A\", 1, true]").unwrap(), vec!["A", "1", "true"]);
        assert!(string_list_body(b"[{}]").is_err());
        let u = users_list_body(br#"{"userIds": [1, "2"], "clientId": "3", "appCode": "a", "x": 1}"#).unwrap();
        assert_eq!(u.user_ids, Some(vec![1, 2]));
        assert_eq!(u.client_id, Some(3));
        assert!(users_list_body(br#"{"userIds": 5}"#).is_err());
        assert!(users_list_body(br#"{"clientCode": {}}"#).is_err());
        let (p, c) = query_body(br#"{"size": 5, "condition": {"field": "id", "value": 1}}"#).unwrap();
        assert_eq!((p.page, p.size, p.sort[0].property.as_str()), (0, 5, "updatedAt"));
        assert!(c.is_some());
        let (p, _) = query_body(br#"{"sort": {"property": "code", "direction": "DESC"}}"#).unwrap();
        assert!(!p.sort[0].ascending);
        let (p, _) = query_body(br#"{"sort": [{"property": "code"}]}"#).unwrap();
        assert!(p.sort[0].ascending);
        assert!(query_body(br#"{"page": -1}"#).is_err());
        assert!(query_body(br#"{"size": 0}"#).is_err());
        assert!(query_body(br#"{"sort": [{"direction": "UP", "property": "a"}]}"#).is_err());
        assert!(query_body(br#"{"condition": {"value": 1}}"#).is_err());
        assert!(query_body(br#"{"sort": 5}"#).unwrap().0.sort.is_empty());
        let c = charge_body(br#"[{"configClientId": 1, "billedClientId": "2", "appId": 3, "actionKey": "k", "quantity": 4.5, "date": 1792108800, "windowIndex": 7}]"#).unwrap();
        assert_eq!(c[0].date, NaiveDate::from_ymd_opt(2026, 10, 16));
        assert_eq!(c[0].quantity.unwrap().to_string(), "4.5");
        assert!(charge_body(br#"[{"date": "2026-10-16"}]"#).is_err());
        assert!(charge_body(br#"[{"quantity": "x"}]"#).is_err());
        let a = ai_charge_body(br#"{"clientCode": "C", "appCode": "a", "weightedTokens": 1200, "requestId": "r"}"#).unwrap();
        assert_eq!(a.weighted_tokens.unwrap().to_string(), "1200");
        assert_eq!(opt_u64_json(Some(&serde_json::json!(-1))).unwrap_err().status(), StatusCode::BAD_REQUEST);
        assert_eq!(opt_text(Some(&serde_json::json!(false))).unwrap(), Some("false".into()));
        assert_eq!(epoch_date(Some(&serde_json::json!(null))).unwrap(), None);
    }
}
