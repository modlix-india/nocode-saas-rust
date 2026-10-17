//! The Feign clients core-exec needs beyond the platform's `SecurityClient`: security's
//! `getAppUrl`, and entity-processor's function and schema repository
//! (`IFeignEntityProcessor`).
//!
//! Feign semantics kept: an empty 2xx body is an empty `Mono` (`None` here); a non-2xx answer
//! is a `FeignException`, which `ControllerAdvice` turns into the other service's status and
//! message.

use std::time::Duration;

use anyhow::anyhow;
use axum::http::HeaderMap;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};
use platform::upstream::Upstream;
use serde_json::Value;

use crate::auth::feign_error;
use crate::error::CoreError;

/// What Feign leaves unescaped in an expanded path variable (RFC 3986 unreserved).
pub(crate) const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

pub(crate) fn client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .pool_idle_timeout(Duration::from_secs(20))
        .build()?)
}

pub(crate) fn trace_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    platform::telemetry::inject_trace_headers(&mut h);
    if let Some(r) = crate::context::request() {
        if let Some(d) = &r.debug {
            if let Ok(v) = d.parse() {
                h.insert("x-debug", v);
            }
        }
        // The draft marker travels every internal hop (`AbstractCoreConfiguration.feignInterceptor`).
        if r.draft {
            h.insert("x-draft", http::HeaderValue::from_static("true"));
        }
    }
    h
}

pub(crate) async fn text(rb: reqwest::RequestBuilder) -> Result<Option<String>, CoreError> {
    let resp = rb.headers(trace_headers()).send().await.map_err(|e| CoreError::from(anyhow!(e)))?;
    let status = resp.status();
    let bytes = resp.bytes().await.map_err(|e| CoreError::from(anyhow!(e)))?;
    if !status.is_success() {
        return Err(feign_error(status.as_u16(), &bytes));
    }
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

fn string_list(s: Option<String>) -> Result<Vec<String>, CoreError> {
    let Some(s) = s else { return Ok(Vec::new()) };
    let v: Value = serde_json::from_str(&s).map_err(|e| CoreError::from(anyhow!(e)))?;
    Ok(v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default())
}

pub struct SecurityCalls {
    pub(crate) upstream: Upstream,
    pub(crate) http: reqwest::Client,
}

impl SecurityCalls {
    pub fn new(upstream: Upstream) -> anyhow::Result<Self> {
        Ok(Self { upstream, http: client()? })
    }

    /// `IFeignSecurityService.getAppUrl(appCode, clientCode)`: plain text.
    pub async fn app_url(&self, app_code: &str, client_code: &str) -> Result<Option<String>, CoreError> {
        let path = "/api/security/clienturls/internal/applications/property/url";
        let base = self.upstream.base_for(path).await.map_err(CoreError::from)?;
        let rb = self
            .http
            .get(format!("{base}{path}"))
            .query(&[("appCode", app_code), ("clientCode", client_code)]);
        text(rb).await
    }
}

/// `IFeignEntityProcessor`.
pub struct EntityProcessor {
    upstream: Upstream,
    http: reqwest::Client,
}

pub struct RemoteCall<'a> {
    pub authorization: &'a str,
    pub forwarded_host: &'a str,
    pub forwarded_port: &'a str,
    pub header_client_code: &'a str,
    pub header_app_code: &'a str,
    pub namespace: &'a str,
    pub name: &'a str,
    pub app_code: &'a str,
    pub client_code: &'a str,
    pub body: String,
}

impl EntityProcessor {
    pub fn new(upstream: Upstream) -> anyhow::Result<Self> {
        Ok(Self { upstream, http: client()? })
    }

    async fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<Option<String>, CoreError> {
        let base = self.upstream.base().await.map_err(CoreError::from)?;
        text(self.http.get(format!("{base}/api/entity/processor/{path}")).query(query)).await
    }

    fn repo_query<'a>(app_code: &'a str, client_code: &'a str) -> Vec<(&'static str, &'a str)> {
        vec![("appCode", app_code), ("clientCode", client_code), ("includeKIRunRepos", "false")]
    }

    pub async fn find_function(
        &self,
        app_code: &str,
        client_code: &str,
        namespace: &str,
        name: &str,
    ) -> Result<Option<String>, CoreError> {
        let mut q = Self::repo_query(app_code, client_code);
        q.push(("namespace", namespace));
        q.push(("name", name));
        self.get("functions/repositoryFind", &q).await
    }

    pub async fn filter_functions(&self, app_code: &str, client_code: &str, filter: &str) -> Result<Vec<String>, CoreError> {
        let mut q = Self::repo_query(app_code, client_code);
        q.push(("filter", filter));
        string_list(self.get("functions/repositoryFilter", &q).await?)
    }

    pub async fn find_schema(
        &self,
        app_code: &str,
        client_code: &str,
        namespace: &str,
        name: &str,
    ) -> Result<Option<String>, CoreError> {
        let mut q = Self::repo_query(app_code, client_code);
        q.push(("namespace", namespace));
        q.push(("name", name));
        self.get("schemas/repositoryFind", &q).await
    }

    pub async fn filter_schemas(&self, app_code: &str, client_code: &str, filter: &str) -> Result<Vec<String>, CoreError> {
        let mut q = Self::repo_query(app_code, client_code);
        q.push(("filter", filter));
        string_list(self.get("schemas/repositoryFilter", &q).await?)
    }

    /// `executeFunction`: the caller's token and forwarded host travel with the call.
    pub async fn execute(&self, call: RemoteCall<'_>) -> Result<Option<String>, CoreError> {
        let base = self.upstream.base().await.map_err(CoreError::from)?;
        let ns = percent_encoding::utf8_percent_encode(call.namespace, PATH_SEGMENT).to_string();
        let name = percent_encoding::utf8_percent_encode(call.name, PATH_SEGMENT).to_string();
        let rb = self
            .http
            .post(format!("{base}/api/entity/processor/functions/execute/{ns}/{name}"))
            .query(&[("paramAppCode", call.app_code), ("paramClientCode", call.client_code)])
            .header("Authorization", call.authorization)
            .header("X-Forwarded-Host", call.forwarded_host)
            .header("X-Forwarded-Port", call.forwarded_port)
            .header("clientCode", call.header_client_code)
            .header("appCode", call.header_app_code)
            .header("Content-Type", "application/json")
            .body(call.body);
        text(rb).await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testing::{request, serve, user};
    use axum::extract::{Path, Query};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::Router;
    use std::collections::HashMap;

    /// entity-processor and security as far as these clients use them.
    pub(crate) async fn stub() -> String {
        async fn find(Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> axum::response::Response {
            assert_eq!(q.get("includeKIRunRepos").map(String::as_str), Some("false"));
            let draft = h.get("x-draft").is_some();
            match q.get("name").map(String::as_str) {
                Some("Create") => format!(
                    r#"{{"namespace":"{}","name":"Create","parameters":{{"entity":{{"schema":{{"type":"OBJECT"}},"parameterName":"entity"}}}},"events":{{"output":{{"name":"output","parameters":{{"created":{{"type":"OBJECT"}}}}}}}}}}"#,
                    q.get("namespace").cloned().unwrap_or_default()
                )
                .into_response(),
                Some("Owner") => r#"{"namespace":"EP.DTO","name":"Owner","type":"OBJECT","properties":{"n":{"type":"INTEGER"}}}"#.into_response(),
                Some("Fail") => (StatusCode::BAD_GATEWAY, r#"{"message":"boom"}"#).into_response(),
                Some("Garbage") => "{not json".into_response(),
                Some("Draft") if draft => r#"{"namespace":"EP","name":"Draft"}"#.into_response(),
                _ => StatusCode::OK.into_response(),
            }
        }
        async fn filter(Query(q): Query<HashMap<String, String>>) -> axum::response::Response {
            match q.get("filter").map(String::as_str) {
                Some("fail") => (StatusCode::INTERNAL_SERVER_ERROR, r#"{"message":"down"}"#).into_response(),
                Some("none") => StatusCode::OK.into_response(),
                Some("obj") => r#"{"a":1}"#.into_response(),
                Some("bad") => "[".into_response(),
                _ => r#"["EP.A.b","EP.A.c"]"#.into_response(),
            }
        }
        async fn execute(Path((ns, name)): Path<(String, String)>, Query(q): Query<HashMap<String, String>>, h: HeaderMap, body: String) -> axum::response::Response {
            assert_eq!(q.get("paramAppCode").map(String::as_str), Some("leadzump"));
            assert_eq!(h.get("authorization").and_then(|v| v.to_str().ok()), Some("token-1"));
            match name.as_str() {
                "Create" => format!(r#"[{{"name":"output","result":{{"ns":"{ns}","body":{body}}}}},{{"name":"x","result":null}}]"#).into_response(),
                "Empty" => StatusCode::OK.into_response(),
                "Fail" => (StatusCode::BAD_REQUEST, r#"{"message":"refused"}"#).into_response(),
                _ => "nope".into_response(),
            }
        }
        async fn app_url(Query(q): Query<HashMap<String, String>>) -> axum::response::Response {
            match q.get("appCode").map(String::as_str) {
                Some("appbuilder") => format!("https://{}.example", q.get("clientCode").cloned().unwrap_or_default()).into_response(),
                Some("broken") => (StatusCode::INTERNAL_SERVER_ERROR, "x").into_response(),
                _ => StatusCode::OK.into_response(),
            }
        }
        serve(
            Router::new()
                .route("/api/entity/processor/functions/repositoryFind", get(find))
                .route("/api/entity/processor/schemas/repositoryFind", get(find))
                .route("/api/entity/processor/functions/repositoryFilter", get(filter))
                .route("/api/entity/processor/schemas/repositoryFilter", get(filter))
                .route("/api/entity/processor/functions/execute/{ns}/{name}", post(execute))
                .route("/api/security/clienturls/internal/applications/property/url", get(app_url)),
        )
        .await
    }

    #[tokio::test]
    async fn entity_processor_calls_follow_feign() {
        let base = stub().await;
        let ep = EntityProcessor::new(Upstream::fixed(&[&base])).unwrap();
        assert!(ep.find_function("leadzump", "SYSTEM", "EP.C", "Create").await.unwrap().unwrap().contains("\"Create\""));
        assert_eq!(ep.find_function("leadzump", "SYSTEM", "EP.C", "Nope").await.unwrap(), None);
        assert_eq!(ep.find_function("leadzump", "SYSTEM", "EP.C", "Fail").await.unwrap_err().text(), "boom");
        assert!(ep.find_schema("leadzump", "SYSTEM", "EP.DTO", "Owner").await.unwrap().is_some());
        assert_eq!(ep.filter_functions("leadzump", "SYSTEM", "").await.unwrap(), ["EP.A.b", "EP.A.c"]);
        assert_eq!(ep.filter_schemas("leadzump", "SYSTEM", "none").await.unwrap(), Vec::<String>::new());
        assert_eq!(ep.filter_schemas("leadzump", "SYSTEM", "obj").await.unwrap(), Vec::<String>::new());
        assert!(ep.filter_schemas("leadzump", "SYSTEM", "bad").await.is_err());
        assert_eq!(ep.filter_functions("leadzump", "SYSTEM", "fail").await.unwrap_err().text(), "down");

        // The draft marker and x-debug travel with the request context.
        let ctx = request(user(&[]), true, Some("dbg"));
        let found = crate::context::with_request(ctx, ep.find_function("leadzump", "SYSTEM", "EP", "Draft")).await;
        assert!(found.unwrap().is_some());
        assert_eq!(ep.find_function("leadzump", "SYSTEM", "EP", "Draft").await.unwrap(), None);

        let call = RemoteCall {
            authorization: "token-1",
            forwarded_host: "h",
            forwarded_port: "1",
            header_client_code: "SYSTEM",
            header_app_code: "leadzump",
            namespace: "EP.A B",
            name: "Create",
            app_code: "leadzump",
            client_code: "SYSTEM",
            body: "{}".into(),
        };
        assert!(ep.execute(call).await.unwrap().unwrap().contains("EP.A B"));

        let unreachable = EntityProcessor::new(Upstream::fixed(&["http://127.0.0.1:1"])).unwrap();
        assert!(unreachable.filter_functions("a", "b", "").await.is_err());
    }

    #[tokio::test]
    async fn security_app_url_is_plain_text() {
        let base = stub().await;
        let sec = SecurityCalls::new(Upstream::fixed(&[&base])).unwrap();
        assert_eq!(sec.app_url("appbuilder", "SYSTEM").await.unwrap().as_deref(), Some("https://SYSTEM.example"));
        assert_eq!(sec.app_url("unknown", "").await.unwrap(), None);
        assert_eq!(sec.app_url("broken", "").await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
