//! Security's endpoints the core functions call, beyond `getAppUrl`:
//!
//! - [`SecurityCalls`]' internal ones (`IFeignSecurityService`): no caller token, answers
//!   read into Java's DTOs. Feign semantics as in [`crate::clients`]: an empty 2xx body is an
//!   empty `Mono` (`None`), a non-2xx answer is the other service's status and message.
//! - [`SecurityAsCaller`] (`IFeignSecurityAsCaller`): the user and org routes, called with the
//!   caller's own token, forwarded host and codes, so security applies its own authorities and
//!   scope rules. Answers come back as text; a refusal keeps the status and body for the
//!   function to map (`CallerSecurityFunctions.fromFeign`).
//!
//! Security ids are `BigInteger`s in Java and `BIGINT UNSIGNED` in its tables; they are `u64`
//! here.

use anyhow::anyhow;
use serde_json::{json, Map, Value};

use crate::clients::{text, trace_headers, SecurityCalls, PATH_SEGMENT};
use crate::error::CoreError;

pub type Id = u64;

fn parse(body: Option<String>) -> Result<Option<Value>, CoreError> {
    match body {
        None => Ok(None),
        Some(s) => serde_json::from_str(&s).map(Some).map_err(|e| CoreError::from(anyhow!("Error decoding the answer: {e}"))),
    }
}

/// Jackson reading a `Boolean`: `true`/`false`, or a string of either.
fn as_bool(v: Option<Value>) -> Result<Option<bool>, CoreError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(b)),
        Some(Value::String(s)) if s == "true" || s == "false" => Ok(Some(s == "true")),
        Some(other) => Err(CoreError::from(anyhow!("Cannot deserialize value of type `java.lang.Boolean` from {other}"))),
    }
}

/// One id as Jackson reads a `BigInteger`: a whole number, or a numeric string.
pub fn id_value(v: &Value) -> Option<Id> {
    match v {
        Value::Number(n) => n.as_u64().or_else(|| n.as_f64().filter(|f| f.fract() == 0.0 && *f >= 0.0).map(|f| f as u64)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn as_ids(v: Option<Value>) -> Result<Option<Vec<Id>>, CoreError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(a)) => Ok(Some(a.iter().filter_map(id_value).collect())),
        Some(other) => Err(CoreError::from(anyhow!("Cannot deserialize a list of ids from {other}"))),
    }
}

/// Jackson reading a `List<String>`: scalars as their text; a null element is kept out of
/// nothing in Java either, and `Set.copyOf` then refuses it.
fn as_codes(v: Option<Value>) -> Result<Option<Vec<String>>, CoreError> {
    let Some(list) = as_list(v)? else { return Ok(None) };
    list.into_iter()
        .map(|c| match c {
            Value::String(s) => Ok(s),
            Value::Number(n) => Ok(n.to_string()),
            Value::Bool(b) => Ok(b.to_string()),
            Value::Null => Err(CoreError::unknown("NullPointerException")),
            other => Err(CoreError::from(anyhow!("Cannot deserialize value of type `java.lang.String` from {other}"))),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn as_list(v: Option<Value>) -> Result<Option<Vec<Value>>, CoreError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(a)) => Ok(Some(a)),
        Some(other) => Err(CoreError::from(anyhow!("Cannot deserialize a list from {other}"))),
    }
}

fn ids_body(ids: &[Id]) -> Value {
    Value::Array(ids.iter().map(|i| Value::from(*i)).collect())
}

impl SecurityCalls {
    async fn get_value(&self, path: &str, query: &[(&str, String)]) -> Result<Option<Value>, CoreError> {
        let base = self.upstream.base_for(path).await.map_err(CoreError::from)?;
        parse(text(self.http.get(format!("{base}{path}")).query(query)).await?)
    }

    async fn post_value(&self, path: &str, query: &[(&str, String)], body: &Value) -> Result<Option<Value>, CoreError> {
        let base = self.upstream.base_for(path).await.map_err(CoreError::from)?;
        let rb = self
            .http
            .post(format!("{base}{path}"))
            .query(query)
            .header("Content-Type", "application/json")
            .body(body.to_string());
        parse(text(rb).await?)
    }

    async fn get_with_codes(&self, path: &str, client_code: &str, app_code: &str) -> Result<Option<Value>, CoreError> {
        let base = self.upstream.base_for(path).await.map_err(CoreError::from)?;
        let rb = self.http.get(format!("{base}{path}")).header("clientCode", client_code).header("appCode", app_code);
        parse(text(rb).await?)
    }

    /// Rust only: security-internal's contact codes, `POST /api/security/internal/contactCodes`
    /// (issue) or `.../contactCodes/verify`. The answer is `{ok, reason, message, ...}`.
    pub async fn contact_code(&self, verify: bool, body: &Value) -> Result<Option<Value>, CoreError> {
        let path = if verify { "/api/security/internal/contactCodes/verify" } else { "/api/security/internal/contactCodes" };
        self.post_value(path, &[], body).await
    }

    /// `getClientById`: security's `Client`.
    pub async fn client_by_id(&self, client_id: Id) -> Result<Option<Value>, CoreError> {
        self.client_by_id_text(&client_id.to_string()).await
    }

    /// `getClientById` with the id as the caller gave it.
    pub async fn client_by_id_text(&self, client_id: &str) -> Result<Option<Value>, CoreError> {
        self.get_value("/api/security/clients/internal/getClientById", &[("clientId", client_id.to_string())]).await
    }

    /// `getClientByCode`.
    pub async fn client_by_code(&self, client_code: &str) -> Result<Option<Value>, CoreError> {
        self.get_value("/api/security/clients/internal/getClientByCode", &[("clientCode", client_code.to_string())]).await
    }

    /// `doesClientManageClient(managingClientId, clientId)`.
    pub async fn does_client_manage_client(&self, managing_client_id: Id, client_id: Id) -> Result<Option<bool>, CoreError> {
        self.does_client_manage_client_text(&managing_client_id.to_string(), &client_id.to_string()).await
    }

    /// `doesClientManageClient` with the ids as the caller gave them.
    pub async fn does_client_manage_client_text(&self, managing_client_id: &str, client_id: &str) -> Result<Option<bool>, CoreError> {
        as_bool(
            self.get_value(
                "/api/security/clients/internal/doesClientManageClient",
                &[("managingClientId", managing_client_id.to_string()), ("clientId", client_id.to_string())],
            )
            .await?,
        )
    }

    /// `doesClientManageClientCode(managingClientCode, clientCode)`.
    pub async fn does_client_manage_client_code(&self, managing_client_code: &str, client_code: &str) -> Result<Option<bool>, CoreError> {
        as_bool(
            self.get_value(
                "/api/security/clients/internal/doesClientManageClientCode",
                &[("managingClientCode", managing_client_code.to_string()), ("clientCode", client_code.to_string())],
            )
            .await?,
        )
    }

    /// `isUserPartOfHierarchy(userId, clientCode)`.
    pub async fn is_user_part_of_hierarchy(&self, user_id: &str, client_code: &str) -> Result<Option<bool>, CoreError> {
        as_bool(
            self.get_value(
                "/api/security/clients/internal/isUserPartOfHierarchy",
                &[("userId", user_id.to_string()), ("clientCode", client_code.to_string())],
            )
            .await?,
        )
    }

    /// `hasReadAccess(appCode, clientCode)`.
    pub async fn has_read_access(&self, app_code: &str, client_code: &str) -> Result<Option<bool>, CoreError> {
        as_bool(
            self.get_value(
                "/api/security/applications/internal/hasReadAccess",
                &[("appCode", app_code.to_string()), ("clientCode", client_code.to_string())],
            )
            .await?,
        )
    }

    /// `hasWriteAccess(appCode, clientCode)`.
    pub async fn has_write_access(&self, app_code: &str, client_code: &str) -> Result<Option<bool>, CoreError> {
        as_bool(
            self.get_value(
                "/api/security/applications/internal/hasWriteAccess",
                &[("appCode", app_code.to_string()), ("clientCode", client_code.to_string())],
            )
            .await?,
        )
    }

    /// `filterManagedClientCodes(managingClientCode, clientCodes)`: of `client_codes`, the ones
    /// `managing_client_code` manages, in one call (a JSON list body).
    pub async fn filter_managed_client_codes(&self, managing_client_code: &str, client_codes: &[String]) -> Result<Option<Vec<String>>, CoreError> {
        let body = Value::Array(client_codes.iter().map(|c| Value::String(c.clone())).collect());
        let answer = self
            .post_value(
                "/api/security/clients/internal/filterManagedClientCodes",
                &[("managingClientCode", managing_client_code.to_string())],
                &body,
            )
            .await?;
        // Jackson reading a `List<String>`: scalars as their text; a null element is dropped.
        Ok(as_list(answer)?.map(|items| {
            items
                .into_iter()
                .filter_map(|v| match v {
                    Value::String(s) => Some(s),
                    Value::Number(n) => Some(n.to_string()),
                    Value::Bool(b) => Some(b.to_string()),
                    _ => None,
                })
                .collect()
        }))
    }

    /// `getClientHierarchy(clientId)`: `[client, level 0, level 1, ...]`.
    pub async fn client_hierarchy(&self, client_id: Id) -> Result<Option<Vec<Id>>, CoreError> {
        as_ids(self.get_value("/api/security/clients/internal/clientHierarchy", &[("clientId", client_id.to_string())]).await?)
    }

    /// `getUserInternal(id, {})`: security's `User`.
    pub async fn user_internal(&self, user_id: Id) -> Result<Option<Value>, CoreError> {
        self.get_value(&format!("/api/security/users/internal/{user_id}"), &[]).await
    }

    /// `getUserInternal(id, {})` keeping a refusal's status and body (the caller-security
    /// functions map a 404 to "user not found" and anything else as security answered it).
    pub async fn user_internal_raw(&self, user_id: Id) -> Result<Option<Value>, FeignFailure> {
        let fail = |status: Option<u16>, body: String| FeignFailure { status, body };
        let path = format!("/api/security/users/internal/{user_id}");
        let base = self.upstream.base_for(&path).await.map_err(|e| fail(None, e.to_string()))?;
        let rb = self.http.get(format!("{base}{path}")).headers(trace_headers());
        let resp = platform::meter::send_to_service(rb).await.map_err(|e| fail(None, e.to_string()))?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| fail(Some(status.as_u16()), e.to_string()))?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if !status.is_success() {
            return Err(fail(Some(status.as_u16()), text));
        }
        if bytes.is_empty() {
            return Ok(None);
        }
        serde_json::from_str(&text).map(Some).map_err(|e| fail(None, e.to_string()))
    }

    /// `getUsersInternalBatch(ids, {})`.
    pub async fn users_internal_batch(&self, ids: &[Id]) -> Result<Option<Vec<Value>>, CoreError> {
        as_list(self.post_value("/api/security/users/internal/batch", &[], &ids_body(ids)).await?)
    }

    /// `getClientInternalBatch(ids, params)`.
    pub async fn clients_internal_batch(&self, ids: &[Id], params: &[(&str, String)]) -> Result<Option<Vec<Value>>, CoreError> {
        as_list(self.post_value("/api/security/clients/internal/batch", params, &ids_body(ids)).await?)
    }

    /// `getUserSubOrgInternal(userId, appCode, clientId)`.
    pub async fn user_sub_org(&self, user_id: Id, app_code: Option<&str>, client_id: Id) -> Result<Option<Vec<Id>>, CoreError> {
        let mut q = Vec::new();
        if let Some(a) = app_code {
            q.push(("appCode", a.to_string()));
        }
        q.push(("clientId", client_id.to_string()));
        as_ids(self.get_value(&format!("/api/security/users/internal/{user_id}/sub-org"), &q).await?)
    }

    /// `getManagingClientIds(clientId)`.
    pub async fn managing_client_ids(&self, client_id: Id) -> Result<Option<Vec<Id>>, CoreError> {
        as_ids(self.get_value("/api/security/clients/internal/managingClientIds", &[("clientId", client_id.to_string())]).await?)
    }

    /// `getClientIdsOfManagers(managerIds)`.
    pub async fn client_ids_of_managers(&self, manager_ids: &[Id]) -> Result<Option<Vec<Id>>, CoreError> {
        as_ids(self.post_value("/api/security/clients/internal/clientIdsOfManagers", &[], &ids_body(manager_ids)).await?)
    }

    /// `getUserAdminEmailsInternal(clientCode, appCode)`: the codes travel as headers.
    pub async fn user_admin_emails(&self, client_code: &str, app_code: &str) -> Result<Option<Value>, CoreError> {
        self.get_with_codes("/api/security/users/internal/adminEmails", client_code, app_code).await
    }

    /// `getOwnersEmailsInternal(clientCode, appCode)`.
    pub async fn owner_emails(&self, client_code: &str, app_code: &str) -> Result<Option<Value>, CoreError> {
        self.get_with_codes("/api/security/users/internal/ownerEmails", client_code, app_code).await
    }

    /// `getUsersForEntityProcessor(UsersListRequest)`.
    pub async fn users_for_entity_processor(&self, client_code: Option<&str>, app_code: Option<&str>) -> Result<Option<Vec<Value>>, CoreError> {
        // Jackson writes the request's four fields, nulls included.
        let body = json!({"userIds": null, "clientCode": client_code, "clientId": null, "appCode": app_code});
        as_list(self.post_value("/api/security/users/internal/processor", &[], &body).await?)
    }

    /// `readUserPageFilterInternal(query, {})`: a Spring `Page` of `User`.
    pub async fn read_user_page(&self, query: &Value) -> Result<Option<Value>, CoreError> {
        self.post_value("/api/security/users/internal/query", &[], query).await
    }

    /// `getWriteAccessClientCodes(appCode)`: the app's owner and every client with EDIT access,
    /// which a per-client schedule fans out over.
    pub async fn write_access_client_codes(&self, app_code: &str) -> Result<Option<Vec<String>>, CoreError> {
        as_codes(
            self.get_value("/api/security/applications/internal/writeAccessClientCodes", &[("appCode", app_code.to_string())])
                .await?,
        )
    }

    /// `getActiveClientCodes(clientCodes)`: the codes among these whose client, and every client
    /// managing it, is active.
    pub async fn active_client_codes(&self, codes: &[String]) -> Result<Option<Vec<String>>, CoreError> {
        as_codes(self.post_value("/api/security/clients/internal/activeClientCodes", &[], &json!(codes)).await?)
    }

    /// `getClientsDenormFull(clientIds)`: `{clientId: ClientDenormData}`.
    pub async fn clients_denorm_full(&self, ids: &[Id]) -> Result<Option<Map<String, Value>>, CoreError> {
        match self.post_value("/api/security/clients/internal/clients/denorm/full", &[], &ids_body(ids)).await? {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Object(m)) => Ok(Some(m)),
            Some(other) => Err(CoreError::from(anyhow!("Cannot deserialize a map from {other}"))),
        }
    }
}

/// The caller a [`SecurityAsCaller`] call acts for (`CallerSecurityFunctions.Caller`'s header
/// part).
#[derive(Debug, Clone)]
pub struct CallerHeaders {
    pub authorization: String,
    pub forwarded_host: String,
    pub forwarded_port: String,
    pub client_code: String,
    pub app_code: String,
}

/// A refused or failed as-caller call: Feign's status (`None` without an answer) and body.
#[derive(Debug, Clone, PartialEq)]
pub struct FeignFailure {
    pub status: Option<u16>,
    pub body: String,
}

/// `IFeignSecurityAsCaller`.
pub struct SecurityAsCaller {
    calls: std::sync::Arc<SecurityCalls>,
}

pub const USERS: &str = "/api/security/users";
pub const CLIENTS: &str = "/api/security/clients";
pub const CLIENT_MANAGERS: &str = "/api/security/client-managers";
pub const CLIENT_ACTIVITIES: &str = "/api/security/client-activities";

/// A path segment as Feign expands a `@PathVariable`.
pub fn segment(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, PATH_SEGMENT).to_string()
}

impl SecurityAsCaller {
    pub fn new(calls: std::sync::Arc<SecurityCalls>) -> Self {
        Self { calls }
    }

    /// One call: `Ok(None)` for an empty 2xx body.
    pub async fn call(
        &self,
        c: &CallerHeaders,
        method: reqwest::Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<Option<String>, FeignFailure> {
        let base = self.calls.upstream.base_for(path).await.map_err(|e| FeignFailure { status: None, body: e.to_string() })?;
        let mut rb = self
            .calls
            .http
            .request(method, format!("{base}{path}"))
            .query(query)
            .headers(trace_headers())
            .header("Authorization", &c.authorization)
            .header("X-Forwarded-Host", &c.forwarded_host)
            .header("X-Forwarded-Port", &c.forwarded_port)
            .header("clientCode", &c.client_code)
            .header("appCode", &c.app_code);
        if let Some(b) = body {
            rb = rb.header("Content-Type", "application/json").body(b.to_string());
        }
        let resp = platform::meter::send_to_service(rb).await.map_err(|e| FeignFailure { status: None, body: e.to_string() })?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| FeignFailure { status: Some(status.as_u16()), body: e.to_string() })?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if !status.is_success() {
            return Err(FeignFailure { status: Some(status.as_u16()), body: text });
        }
        Ok(if bytes.is_empty() { None } else { Some(text) })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testing::serve;
    use axum::extract::{Path, RawQuery};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::Router;
    use platform::upstream::Upstream;

    fn q(raw: Option<String>) -> std::collections::HashMap<String, String> {
        crate::exec::parse_query(raw.as_deref()).into_iter().collect()
    }

    async fn stub() -> String {
        let router = Router::new()
            .route("/api/security/clients/internal/getClientById", get(|RawQuery(r): RawQuery| async move {
                match q(r).get("clientId").map(String::as_str) {
                    Some("1") => r#"{"id":1,"code":"SYSTEM"}"#.into_response(),
                    Some("9") => (StatusCode::NOT_FOUND, r#"{"message":"no client"}"#).into_response(),
                    _ => StatusCode::OK.into_response(),
                }
            }))
            .route("/api/security/clients/internal/doesClientManageClient", get(|| async { "true" }))
            .route("/api/security/clients/internal/doesClientManageClientCode", get(|| async { "\"false\"" }))
            .route("/api/security/applications/internal/hasReadAccess", get(|| async { "5" }))
            .route("/api/security/clients/internal/clientHierarchy", get(|| async { r#"[3,"2",1,"x"]"# }))
            .route("/api/security/clients/internal/managingClientIds", get(|| async { r#"{"a":1}"# }))
            .route("/api/security/users/internal/batch", post(|body: String| async move { format!("[{body}]") }))
            .route("/api/security/clients/internal/batch", post(|| async { "{}" }))
            .route("/api/security/users/internal/adminEmails", get(|h: HeaderMap| async move {
                format!(r#"{{"c":"{}"}}"#, h.get("clientCode").and_then(|v| v.to_str().ok()).unwrap_or(""))
            }))
            .route("/api/security/clients/internal/clients/denorm/full", post(|| async { "[]" }))
            .route("/api/security/users/internal/{id}/sub-org", get(|Path(id): Path<String>, RawQuery(r): RawQuery| async move {
                let p = q(r);
                format!("[{id},{}]", p.get("clientId").cloned().unwrap_or_default())
            }))
            .route("/api/security/users/{id}", get(|Path(id): Path<String>, h: HeaderMap| async move {
                match id.as_str() {
                    "1" => format!(r#"{{"id":1,"auth":"{}"}}"#, h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("")).into_response(),
                    "2" => StatusCode::OK.into_response(),
                    _ => (StatusCode::FORBIDDEN, "nope").into_response(),
                }
            }))
            .route("/api/security/users/internal/processor", post(|body: String| async move { format!("[{body}]") }))
            .route("/api/security/clients/internal/filterManagedClientCodes", post(|RawQuery(r): RawQuery, body: String| async move {
                let managing = q(r).get("managingClientCode").cloned().unwrap_or_default();
                let asked: Vec<String> = serde_json::from_str(&body).unwrap_or_default();
                match managing.as_str() {
                    "NONE" => StatusCode::OK.into_response(),
                    _ => format!(r#"["{}", null, 7, {}]"#, asked.join("\", \""), serde_json::json!(managing)).into_response(),
                }
            }))
            .route("/api/security/applications/internal/writeAccessClientCodes", get(|RawQuery(r): RawQuery| async move {
                match q(r).get("appCode").map(String::as_str) {
                    Some("leadzumptwo") => r#"["FIN", 7, true]"#.into_response(),
                    Some("nulls") => r#"["FIN", null]"#.into_response(),
                    Some("odd") => r#"[{"a": 1}]"#.into_response(),
                    Some("object") => r#"{"a": 1}"#.into_response(),
                    _ => StatusCode::OK.into_response(),
                }
            }))
            .route("/api/security/clients/internal/activeClientCodes", post(|body: String| async move {
                let asked: Vec<String> = serde_json::from_str(&body).unwrap_or_default();
                serde_json::to_string(&asked.into_iter().filter(|c| c != "GONE").collect::<Vec<_>>()).unwrap()
            }));
        serve(router).await
    }

    #[tokio::test]
    async fn internal_answers_read_as_feign_reads_them() {
        let base = stub().await;
        let s = SecurityCalls::new(Upstream::fixed(&[&base])).unwrap();
        assert_eq!(s.client_by_id(1).await.unwrap().unwrap()["code"], "SYSTEM");
        assert_eq!(s.client_by_id(2).await.unwrap(), None);
        assert_eq!(s.client_by_id(9).await.unwrap_err().text(), "no client");
        assert_eq!(s.does_client_manage_client(1, 2).await.unwrap(), Some(true));
        assert_eq!(s.does_client_manage_client_code("A", "B").await.unwrap(), Some(false));
        assert_eq!(
            s.filter_managed_client_codes("SYSTEM", &["FIN".into(), "FIN2".into()]).await.unwrap(),
            Some(vec!["FIN".to_string(), "FIN2".into(), "7".into(), "SYSTEM".into()])
        );
        assert_eq!(s.filter_managed_client_codes("NONE", &[]).await.unwrap(), None);
        // Jackson reading a List<String>: scalars as text; a null is refused by Set.copyOf.
        assert_eq!(s.write_access_client_codes("leadzumptwo").await.unwrap(), Some(vec!["FIN".to_string(), "7".into(), "true".into()]));
        assert_eq!(s.write_access_client_codes("none").await.unwrap(), None);
        assert!(s.write_access_client_codes("nulls").await.is_err());
        assert!(s.write_access_client_codes("odd").await.is_err());
        assert!(s.write_access_client_codes("object").await.is_err());
        assert_eq!(s.active_client_codes(&["FIN".into(), "GONE".into()]).await.unwrap(), Some(vec!["FIN".to_string()]));
        assert!(s.has_read_access("a", "b").await.is_err());
        assert!(s.has_write_access("a", "b").await.is_err());
        assert_eq!(s.client_hierarchy(3).await.unwrap(), Some(vec![3, 2, 1]));
        assert!(s.managing_client_ids(1).await.is_err());
        assert_eq!(s.users_internal_batch(&[5, 6]).await.unwrap().unwrap(), vec![json!([5, 6])]);
        assert!(s.clients_internal_batch(&[1], &[]).await.is_err());
        assert_eq!(s.user_admin_emails("C1", "app").await.unwrap().unwrap()["c"], "C1");
        assert!(s.clients_denorm_full(&[1]).await.is_err());
        assert_eq!(s.user_sub_org(7, Some("app"), 3).await.unwrap(), Some(vec![7, 3]));
        assert_eq!(
            s.users_for_entity_processor(Some("C"), None).await.unwrap().unwrap()[0],
            json!({"userIds": null, "clientCode": "C", "clientId": null, "appCode": null})
        );
        assert_eq!(id_value(&json!(4.0)), Some(4));
        assert_eq!(id_value(&json!(-1)), None);
        assert_eq!(id_value(&json!(true)), None);
        assert!(as_bool(Some(json!("true"))).unwrap().unwrap());
        assert_eq!(as_bool(Some(Value::Null)).unwrap(), None);
        assert_eq!(as_ids(None).unwrap(), None);
        assert_eq!(as_list(Some(Value::Null)).unwrap(), None);
        assert!(parse(Some("{".into())).is_err());

        let calls = std::sync::Arc::new(s);
        let ac = SecurityAsCaller::new(calls);
        let c = CallerHeaders {
            authorization: "Bearer t".into(),
            forwarded_host: "h".into(),
            forwarded_port: "1".into(),
            client_code: "SYSTEM".into(),
            app_code: "appbuilder".into(),
        };
        let got = ac.call(&c, reqwest::Method::GET, &format!("{USERS}/1"), &[], None).await.unwrap().unwrap();
        assert!(got.contains("Bearer t"));
        assert_eq!(ac.call(&c, reqwest::Method::GET, &format!("{USERS}/2"), &[], None).await.unwrap(), None);
        assert_eq!(
            ac.call(&c, reqwest::Method::GET, &format!("{USERS}/3"), &[], Some(&json!({}))).await.unwrap_err(),
            FeignFailure { status: Some(403), body: "nope".into() }
        );
        let dead = SecurityAsCaller::new(std::sync::Arc::new(SecurityCalls::new(Upstream::fixed(&["http://127.0.0.1:1"])).unwrap()));
        assert_eq!(dead.call(&c, reqwest::Method::GET, USERS, &[], None).await.unwrap_err().status, None);
        assert_eq!(segment("a b/c"), "a%20b%2Fc");
    }
}
