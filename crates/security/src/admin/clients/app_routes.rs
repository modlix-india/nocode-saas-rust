//! `AppController`'s routes (the `internal` ones are security-internal's).
//!
//! | Route | Who |
//! |---|---|
//! | `GET applications/dependencies`, `GET applyAppCodeSuffix` / `applyAppCodePrefix` | anyone |
//! | `GET`, `POST query`, `POST accessible/query`, `GET {id}` | `Application_READ` |
//! | `POST` | `Application_CREATE` |
//! | `PUT`/`PATCH {id}`, `POST property` | `Application_UPDATE` |
//! | `DELETE {id}`, `DELETE everything/{id}`, `DELETE property`, `DELETE property/{id}` | `Application_DELETE` |
//! | the rest (access, dependencies, clients, lookups) | signed in, checked by the service |

use axum::http::{header, HeaderValue};
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::Router;
use serde_json::Value;

use super::apps::{self, APP};
use super::common::{bool_json, no_content, object_body, pre_authorize, prop_bool, prop_str, prop_u64};
use crate::admin::AdminState;
use crate::errors::AuthResult;
use crate::jackson::json as json_resp;
use crate::spring::{Pageable, Params};
use crate::web::{self, opt_u64, query_body, req_str, req_u64, to_u64, type_mismatch};
use crate::{web_route, web_route_path};

/// `@RequestParam(required = false) Boolean`: Spring's `StringToBooleanConverter`.
pub fn opt_bool(p: &Params, name: &str) -> AuthResult<Option<bool>> {
    let Some(v) = p.get(name) else { return Ok(None) };
    match v.trim().to_ascii_lowercase().as_str() {
        "" => Ok(None),
        "true" | "on" | "yes" | "1" => Ok(Some(true)),
        "false" | "off" | "no" | "0" => Ok(Some(false)),
        _ => Err(type_mismatch()),
    }
}

/// `@RequestParam String[]`: one value is split on commas (each trimmed), several are taken as
/// they are.
pub fn string_array(p: &Params, name: &str) -> AuthResult<Vec<String>> {
    let values = p.all(name);
    match values.as_slice() {
        [] => Err(web::missing(name)),
        [one] if one.is_empty() => Ok(vec![]),
        [one] => Ok(one.split(',').map(|s| s.trim().to_string()).collect()),
        many => Ok(many.iter().map(|s| s.to_string()).collect()),
    }
}

/// `security.resourceCacheAge`'s default.
const RESOURCE_CACHE_AGE: i64 = 604_800;

/// `applyAppCodeSuffix` / `applyAppCodePrefix`: the text with a weak ETag, a week's caching and
/// `SAMEORIGIN` framing.
fn cached_text(app_code: &str, body: String) -> Response {
    let mut resp = web::text(&body);
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&format!("W/{app_code}")) {
        h.insert(header::ETAG, v);
    }
    if let Ok(v) = HeaderValue::from_str(&format!("max-age={RESOURCE_CACHE_AGE}")) {
        h.insert(header::CACHE_CONTROL, v);
    }
    h.append("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
    h.append("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
    resp
}

/// The environment marker in front instead of behind: `.local` becomes `local.`.
pub fn app_code_prefix(suffix: &str) -> String {
    match suffix.strip_prefix('.') {
        Some(rest) if !suffix.is_empty() => format!("{rest}."),
        _ => suffix.to_string(),
    }
}

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/applications", get(read_page).post(create))
        .route("/api/security/applications/query", post(query))
        .route("/api/security/applications/accessible/query", post(accessible_query))
        .route("/api/security/applications/applyAppCodeSuffix", get(apply_suffix))
        .route("/api/security/applications/applyAppCodePrefix", get(apply_prefix))
        .route("/api/security/applications/appCode/{appCode}", get(by_code))
        .route("/api/security/applications/clientHasReadAccess", get(client_has_read_access))
        .route("/api/security/applications/clients/{appCode}", get(app_clients))
        .route("/api/security/applications/dependencies", get(dependencies))
        .route("/api/security/applications/dependency", post(add_dependency).delete(remove_dependency))
        .route("/api/security/applications/everything/{id}", delete(delete_everything))
        .route("/api/security/applications/findAnyApps", get(find_any_apps))
        .route("/api/security/applications/findBaseClientCode/{applicationCode}", get(find_base_client_code))
        .route("/api/security/applications/hasDeleteAccess", get(has_delete_access))
        .route("/api/security/applications/property", get(get_property).post(post_property).delete(delete_property))
        .route("/api/security/applications/property/{propertyId}", delete(delete_property_by_id))
        .route("/api/security/applications/{id}", get(read).put(put).patch(patch).delete(delete_app))
        .route("/api/security/applications/{id}/access", post(add_access).patch(update_access).delete(remove_access))
}

web_route!(read_page, AdminState, "/applications", true, |s, r, ca| {
    let pageable = Pageable::from_params(&r.params);
    let cond = crate::condition::from_params(&r.params.0);
    pre_authorize(&ca, "Authorities.Application_READ")?;
    Ok(json_resp(&apps::page(&s, &ca, &pageable, cond.as_ref(), false).await?))
});

web_route!(query, AdminState, "/applications/query", true, |s, r, ca| {
    let (pageable, cond) = query_body(&r.body)?;
    pre_authorize(&ca, "Authorities.Application_READ")?;
    Ok(json_resp(&apps::page(&s, &ca, &pageable, cond.as_ref(), false).await?))
});

web_route!(accessible_query, AdminState, "/applications/accessible/query", true, |s, r, ca| {
    let (pageable, cond) = query_body(&r.body)?;
    pre_authorize(&ca, "Authorities.Application_READ")?;
    Ok(json_resp(&apps::page(&s, &ca, &pageable, cond.as_ref(), true).await?))
});

web_route!(create, AdminState, "/applications", true, |s, r, ca| {
    let body = object_body(&r.body)?;
    let entity = APP.from_body(&body, apps::initial())?;
    pre_authorize(&ca, "Authorities.Application_CREATE")?;
    Ok(json_resp(&apps::json_of(&apps::create(&s, &ca, entity).await?)))
});

web_route_path!(read, AdminState, "/applications/{id}", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    pre_authorize(&ca, "Authorities.Application_READ")?;
    Ok(json_resp(&apps::json_of(&apps::read(&s, id).await?)))
});

web_route_path!(put, AdminState, "/applications/{id}", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    let body = object_body(&r.body)?;
    let mut entity = APP.from_body(&body, apps::initial())?;
    entity.insert("id".into(), Value::from(id));
    pre_authorize(&ca, "Authorities.Application_UPDATE")?;
    Ok(json_resp(&apps::json_of(&apps::update(&s, &ca, &entity).await?)))
});

web_route_path!(patch, AdminState, "/applications/{id}", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    let body = object_body(&r.body)?;
    pre_authorize(&ca, "Authorities.Application_UPDATE")?;
    let fields = body.as_object().cloned().unwrap_or_default();
    Ok(json_resp(&apps::json_of(&apps::patch(&s, &ca, id, &fields).await?)))
});

web_route_path!(delete_app, AdminState, "/applications/{id}", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    pre_authorize(&ca, "Authorities.Application_DELETE")?;
    apps::delete(&s, &ca, id).await?;
    Ok(no_content())
});

web_route_path!(delete_everything, AdminState, "/applications/everything/{id}", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    let force = opt_bool(&r.params, "forceDelete")?.unwrap_or(false);
    pre_authorize(&ca, "Authorities.Application_DELETE")?;
    Ok(bool_json(apps::delete_everything(&s, &ca, id, force).await?))
});

web_route!(has_delete_access, AdminState, "/applications/hasDeleteAccess", true, |s, r, ca| {
    let app = req_str(&r.params, "deleteAppCode")?;
    let client = req_str(&r.params, "deleteClientCode")?;
    Ok(bool_json(apps::has_delete_access(&s, &ca, app, client).await?))
});

web_route_path!(by_code, AdminState, "/applications/appCode/{appCode}", true, |s, r, ca, code| {
    Ok(match apps::by_code_check_access(&s, &ca, &code).await? {
        Some(v) => json_resp(&v),
        None => web::nothing(),
    })
});

web_route_path!(app_clients, AdminState, "/applications/clients/{appCode}", true, |s, r, ca, code| {
    let only_write = opt_bool(&r.params, "onlyWriteAccess")?;
    let pageable = Pageable::from_params(&r.params);
    Ok(json_resp(&apps::app_clients(&s, &ca, &code, only_write, r.params.get("name"), &pageable).await?))
});

web_route!(get_property, AdminState, "/applications/property", true, |s, r, ca| {
    let client = opt_u64(&r.params, "clientId")?;
    let app = opt_u64(&r.params, "appId")?;
    let v = apps::properties_with_clients(&s, &ca, client, app, r.params.get("appCode"), r.params.get("propName")).await?;
    Ok(json_resp(&v))
});

web_route!(post_property, AdminState, "/applications/property", true, |s, r, ca| {
    let body = object_body(&r.body)?;
    let (client, app) = (prop_u64(&body, "clientId")?, prop_u64(&body, "appId")?);
    let (name, value) = (prop_str(&body, "name")?, prop_str(&body, "value")?);
    pre_authorize(&ca, "Authorities.Application_UPDATE")?;
    Ok(match apps::update_property(&s, &ca, app, client, name.as_deref(), value.as_deref()).await? {
        Some(b) => bool_json(b),
        None => web::nothing(),
    })
});

web_route!(delete_property, AdminState, "/applications/property", true, |s, r, ca| {
    let client = req_u64(&r.params, "clientId")?;
    let app = req_u64(&r.params, "appId")?;
    let name = req_str(&r.params, "name")?;
    pre_authorize(&ca, "Authorities.Application_DELETE")?;
    Ok(match apps::delete_property(&s, &ca, client, app, name).await? {
        Some(b) => bool_json(b),
        None => web::nothing(),
    })
});

web_route_path!(delete_property_by_id, AdminState, "/applications/property/{propertyId}", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    pre_authorize(&ca, "Authorities.Application_DELETE")?;
    Ok(match apps::delete_property_by_id(&s, &ca, id).await? {
        Some(b) => bool_json(b),
        None => web::nothing(),
    })
});

web_route_path!(find_base_client_code, AdminState, "/applications/findBaseClientCode/{applicationCode}", true, |s, r, ca, code| {
    Ok(match apps::base_client_code(&s, &ca, &code).await? {
        Some(v) => json_resp(&v),
        None => web::nothing(),
    })
});

web_route!(find_any_apps, AdminState, "/applications/findAnyApps", true, |s, r, ca| {
    let pageable = Pageable::from_params(&r.params);
    let cond = crate::condition::from_params(&r.params.0);
    Ok(json_resp(&apps::find_any_apps(&s, &ca, &pageable, cond.as_ref()).await?))
});

web_route!(dependencies, AdminState, "/applications/dependencies", false, |s, r, ca| {
    let app = req_str(&r.params, "appCode")?;
    Ok(match s.app_dependencies(app).await? {
        Some(list) => json_resp(&Value::Array(list.iter().map(apps::dependency_json).collect())),
        None => web::nothing(),
    })
});

web_route!(add_dependency, AdminState, "/applications/dependency", true, |s, r, ca| {
    let body = object_body(&r.body)?;
    let (app, dep) = (prop_str(&body, "appCode")?, prop_str(&body, "dependentAppCode")?);
    Ok(json_resp(&apps::add_dependency(&s, &ca, app.as_deref(), dep.as_deref()).await?))
});

web_route!(remove_dependency, AdminState, "/applications/dependency", true, |s, r, ca| {
    let app = req_str(&r.params, "appCode")?;
    let dep = req_str(&r.params, "dependencyCode")?;
    Ok(bool_json(apps::remove_dependency(&s, &ca, app, dep).await?))
});

web_route!(client_has_read_access, AdminState, "/applications/clientHasReadAccess", true, |s, r, ca| {
    let codes = string_array(&r.params, "appCodes")?;
    Ok(json_resp(&apps::read_access_map(&s, &ca, &codes).await?))
});

web_route!(apply_suffix, AdminState, "/applications/applyAppCodeSuffix", false, |s, r, ca| {
    let code = req_str(&r.params, "appCode")?;
    Ok(cached_text(code, format!("{code}{}", s.auth.settings.app_code_suffix)))
});

web_route!(apply_prefix, AdminState, "/applications/applyAppCodePrefix", false, |s, r, ca| {
    let code = req_str(&r.params, "appCode")?;
    Ok(cached_text(code, format!("{}{code}", app_code_prefix(&s.auth.settings.app_code_suffix))))
});

web_route_path!(add_access, AdminState, "/applications/{id}/access", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    let body = object_body(&r.body)?;
    let (client, write) = (prop_u64(&body, "clientId")?, prop_bool(&body, "writeAccess")?);
    Ok(bool_json(apps::add_client_access(&s, &ca, id, client, write).await?))
});

web_route_path!(update_access, AdminState, "/applications/{id}/access", true, |s, r, ca, _id| {
    let body = object_body(&r.body)?;
    let (access, write) = (prop_u64(&body, "id")?, prop_bool(&body, "writeAccess")?);
    Ok(bool_json(apps::update_client_access(&s, &ca, access, write).await?))
});

web_route_path!(remove_access, AdminState, "/applications/{id}/access", true, |s, r, ca, id| {
    let id = to_u64(&id)?;
    let access = req_u64(&r.params, "accessId")?;
    Ok(bool_json(apps::remove_client_access(&s, &ca, id, access).await?))
});

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    fn params(q: &str) -> Params {
        Params::from_query(Some(q))
    }

    #[test]
    fn spring_conversions() {
        assert_eq!(opt_bool(&params("a=Yes"), "a").unwrap(), Some(true));
        assert_eq!(opt_bool(&params("a=0"), "a").unwrap(), Some(false));
        assert_eq!(opt_bool(&params("a="), "a").unwrap(), None);
        assert_eq!(opt_bool(&params(""), "a").unwrap(), None);
        assert!(opt_bool(&params("a=maybe"), "a").is_err());
        assert_eq!(string_array(&params("c=a,%20b"), "c").unwrap(), vec!["a", "b"]);
        assert_eq!(string_array(&params("c=a,b&c=d"), "c").unwrap(), vec!["a,b", "d"]);
        assert!(string_array(&params("c="), "c").unwrap().is_empty());
        assert!(string_array(&params(""), "c").is_err());
        assert_eq!(app_code_prefix(".local"), "local.");
        assert_eq!(app_code_prefix(""), "");
        assert_eq!(app_code_prefix("x"), "x");
    }

    #[test]
    fn cached_text_headers() {
        let r = cached_text("abc", "abc.local".into());
        assert_eq!(r.headers()[header::ETAG], "W/abc");
        assert_eq!(r.headers()[header::CACHE_CONTROL], "max-age=604800");
        assert_eq!(r.headers().get_all("x-frame-options").iter().count(), 2);
        assert_eq!(r.status(), StatusCode::OK);
    }
}
