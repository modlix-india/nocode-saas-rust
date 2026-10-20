//! The internal routes the retired Java `worker` called for its platform jobs, as its Feign
//! clients (`IFeignSecurityService`, `IFeignCoreService`, `IFeignEntityProcessorService`,
//! `IFeignFilesService`, `IFeignUIService`) sent them: `POST`, the `@RequestParam`s in
//! declaration order, no body except `events/internal/raise`'s JSON, no authentication (the
//! targets are internal routes; nginx keeps them off the public edge).
//!
//! Only `CoreServices.Platform.*` call these, and only behind their guard
//! (`functions::platform`).
//!
//! Answers are read as Feign reads the declared types: an empty 2xx body is `null`
//! (`None`), a non-2xx answer is the other service's status and message
//! ([`crate::clients::text`]), an answer of the wrong shape is a decoding error.

use anyhow::anyhow;
use platform::upstream::Upstream;
use serde_json::{Map, Value};

use crate::clients::{client, text, PATH_SEGMENT};
use crate::error::CoreError;

/// The services the platform jobs reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    Security,
    Core,
    EntityProcessor,
    Files,
    Ui,
}

impl Service {
    pub fn name(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Core => "core",
            Self::EntityProcessor => "entity-processor",
            Self::Files => "files",
            Self::Ui => "ui",
        }
    }
}

/// Where each service is. An upstream that could not be made from the configuration is kept
/// as its error, so a missing `[ui]` or `[core] upstream` fails the job that needs it (with
/// the reason) instead of the whole unit at startup.
#[derive(Clone)]
pub struct Upstreams {
    pub security: Result<Upstream, String>,
    pub core: Result<Upstream, String>,
    pub entity_processor: Result<Upstream, String>,
    pub files: Result<Upstream, String>,
    pub ui: Result<Upstream, String>,
}

impl Upstreams {
    /// Every service at the same fixed address (tests).
    pub fn all(upstream: Upstream) -> Self {
        Self {
            security: Ok(upstream.clone()),
            core: Ok(upstream.clone()),
            entity_processor: Ok(upstream.clone()),
            files: Ok(upstream.clone()),
            ui: Ok(upstream),
        }
    }
}

pub struct PlatformCalls {
    upstreams: Upstreams,
    http: reqwest::Client,
}

/// A `Mono<T>` answer as JSON: `None` for an empty body (or `null`).
fn parse(body: Option<String>) -> Result<Option<Value>, CoreError> {
    match body {
        None => Ok(None),
        Some(s) => match serde_json::from_str::<Value>(&s) {
            Ok(Value::Null) => Ok(None),
            Ok(v) => Ok(Some(v)),
            Err(e) => Err(CoreError::from(anyhow!("JSON decoding error: {e}"))),
        },
    }
}

fn decode_error(what: &str, got: &Value) -> CoreError {
    CoreError::from(anyhow!("JSON decoding error: Cannot deserialize value of type `{what}` from {got}"))
}

/// A `Boolean` answer: `true`/`false`, or a string of either (Jackson's coercion).
pub fn as_bool(v: Option<Value>) -> Result<Option<bool>, CoreError> {
    match v {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(b)),
        Some(Value::String(s)) if s == "true" || s == "false" => Ok(Some(s == "true")),
        Some(other) => Err(decode_error("java.lang.Boolean", &other)),
    }
}

/// An `Integer` answer: a whole number, or a string of one.
pub fn as_int(v: Option<Value>) -> Result<Option<i64>, CoreError> {
    match v {
        None => Ok(None),
        Some(Value::Number(n)) if n.as_i64().is_some() => Ok(n.as_i64()),
        Some(Value::String(s)) if s.trim().parse::<i64>().is_ok() => Ok(s.trim().parse().ok()),
        Some(other) => Err(decode_error("java.lang.Integer", &other)),
    }
}

/// A `Map<String, ...>` (or bean) answer.
pub fn as_object(v: Option<Value>, what: &str) -> Result<Option<Map<String, Value>>, CoreError> {
    match v {
        None => Ok(None),
        Some(Value::Object(m)) => Ok(Some(m)),
        Some(other) => Err(decode_error(what, &other)),
    }
}

/// A `List<...>` answer.
pub fn as_list(v: Option<Value>, what: &str) -> Result<Option<Vec<Value>>, CoreError> {
    match v {
        None => Ok(None),
        Some(Value::Array(a)) => Ok(Some(a)),
        Some(other) => Err(decode_error(what, &other)),
    }
}

fn segment(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, PATH_SEGMENT).to_string()
}

const MAP_OF_INTEGERS: &str = "java.util.Map<java.lang.String,java.lang.Integer>";

impl PlatformCalls {
    pub fn new(upstreams: Upstreams) -> anyhow::Result<Self> {
        Ok(Self { upstreams, http: client()? })
    }

    /// Whether the service has an upstream (entity-processor retired on 2026-10-18 and may have
    /// none).
    pub fn has_upstream(&self, service: Service) -> bool {
        self.upstream(service).is_ok()
    }

    fn upstream(&self, service: Service) -> Result<&Upstream, CoreError> {
        let u = match service {
            Service::Security => &self.upstreams.security,
            Service::Core => &self.upstreams.core,
            Service::EntityProcessor => &self.upstreams.entity_processor,
            Service::Files => &self.upstreams.files,
            Service::Ui => &self.upstreams.ui,
        };
        u.as_ref()
            .map_err(|e| CoreError::unknown(format!("No upstream for the {} service: {e}", service.name())))
    }

    /// `POST <service><path>?<query>` with an optional JSON body, the answer as JSON.
    async fn post(&self, service: Service, path: &str, query: &[(&str, String)], body: Option<&Value>) -> Result<Option<Value>, CoreError> {
        let base = self.upstream(service)?.base_for(path).await.map_err(CoreError::from)?;
        let mut rb = self.http.post(format!("{base}{path}"));
        if !query.is_empty() {
            rb = rb.query(query);
        }
        if let Some(b) = body {
            rb = rb.header("Content-Type", "application/json").body(b.to_string());
        }
        parse(text(rb).await?)
    }

    // ------------------------------------------------------------------ security

    /// `renewExpiringCertificates(daysBeforeExpiry)`: `SSLCertificateRenewalResult`
    /// (`renewedCount`, `failedCount`, `errors`).
    pub async fn renew_certificates(&self, days_before_expiry: i64) -> Result<Option<Map<String, Value>>, CoreError> {
        let v = self
            .post(
                Service::Security,
                "/api/security/ssl/internal/renew-certificates",
                &[("daysBeforeExpiry", days_before_expiry.to_string())],
                None,
            )
            .await?;
        as_object(v, "com.modlix.saas.worker.dto.SSLCertificateRenewalResult")
    }

    /// `cleanupTokens(unusedDays)`: `expiredTokensRemoved`, `unusedTokensRemoved` (and
    /// `expiredDraftTokensRemoved`).
    pub async fn cleanup_tokens(&self, unused_days: i64) -> Result<Option<Map<String, Value>>, CoreError> {
        let v = self
            .post(Service::Security, "/api/security/internal/tokens/cleanup", &[("unusedDays", unused_days.to_string())], None)
            .await?;
        as_object(v, MAP_OF_INTEGERS)
    }

    // ------------------------------------------------------------------ billing

    /// The 15-minute meter of one service: `triggerSecurityMetering` /
    /// `triggerBillingMetering`. Files is never asked for anything else here.
    pub async fn meter(&self, service: Service) -> Result<Option<bool>, CoreError> {
        let path = match service {
            Service::Security => "/api/security/internal/billing/meter/security",
            Service::Core => "/api/core/internal/billing/meter",
            Service::EntityProcessor => "/api/entity/processor/internal/billing/meter",
            Service::Files => "/api/files/internal/billing/meter",
            Service::Ui => return Err(CoreError::unknown("The ui service has no billing meter")),
        };
        as_bool(self.post(service, path, &[], None).await?)
    }

    /// `reconcileBilling()` of one service (no `date`: the service reconciles yesterday).
    pub async fn reconcile(&self, service: Service) -> Result<Option<bool>, CoreError> {
        let path = match service {
            Service::Security => "/api/security/internal/billing/reconcile",
            Service::Core => "/api/core/internal/billing/reconcile",
            Service::EntityProcessor => "/api/entity/processor/internal/billing/reconcile",
            Service::Files => "/api/files/internal/billing/reconcile",
            Service::Ui => return Err(CoreError::unknown("The ui service has no billing reconcile")),
        };
        as_bool(self.post(service, path, &[], None).await?)
    }

    // ------------------------------------------------------------------ files

    /// `cleanupExpired(resourceType, limit)`: how many files went.
    pub async fn cleanup_expired(&self, resource_type: &str, limit: i64) -> Result<Option<i64>, CoreError> {
        let path = format!("/api/files/internal/{}/cleanupExpired", segment(resource_type));
        as_int(self.post(Service::Files, &path, &[("limit", limit.to_string())], None).await?)
    }

    /// `applyRetention(resourceType, limit)`: `[{clientCode, appCode, resourceType, paths}]`.
    pub async fn apply_retention(&self, resource_type: &str, limit: i64) -> Result<Option<Vec<Value>>, CoreError> {
        let path = format!("/api/files/internal/{}/applyRetention", segment(resource_type));
        let v = self.post(Service::Files, &path, &[("limit", limit.to_string())], None).await?;
        as_list(v, "java.util.List<com.modlix.saas.worker.dto.FilesRetentionResult>")
    }

    // ------------------------------------------------------------------ core

    /// `raiseEvent(CoreEventRaiseRequest)`: whether core handed the event to the queue.
    pub async fn raise_event(&self, request: &Value) -> Result<Option<bool>, CoreError> {
        as_bool(self.post(Service::Core, "/api/core/events/internal/raise", &[], Some(request)).await?)
    }

    /// `cleanupEventRuns(retentionDays, successRetentionDays, staleAfterHours, limit)`:
    /// `runsRemoved`, `successesRemoved`, `staleClosed`.
    pub async fn cleanup_event_runs(
        &self,
        retention_days: i64,
        success_retention_days: i64,
        stale_after_hours: i64,
        limit: i64,
    ) -> Result<Option<Map<String, Value>>, CoreError> {
        let q = [
            ("retentionDays", retention_days.to_string()),
            ("successRetentionDays", success_retention_days.to_string()),
            ("staleAfterHours", stale_after_hours.to_string()),
            ("limit", limit.to_string()),
        ];
        let v = self.post(Service::Core, "/api/core/eventRuns/internal/cleanupOlderThan", &q, None).await?;
        as_object(v, MAP_OF_INTEGERS)
    }

    /// `cleanupTransports(retentionDays, limit)` of ui or core: `transportsRemoved`,
    /// `versionsRemoved`.
    pub async fn cleanup_transports(&self, service: Service, retention_days: i64, limit: i64) -> Result<Option<Map<String, Value>>, CoreError> {
        let path = match service {
            Service::Ui => "/api/ui/transports/internal/cleanupOlderThan",
            Service::Core => "/api/core/transports/internal/cleanupOlderThan",
            other => return Err(CoreError::unknown(format!("The {} service keeps no transports", other.name()))),
        };
        let q = [("retentionDays", retention_days.to_string()), ("limit", limit.to_string())];
        as_object(self.post(service, path, &q, None).await?, MAP_OF_INTEGERS)
    }

    // ------------------------------------------------------------------ entity-processor

    /// `stampExpiredWhatsappMedia(retentionDays, limit)`: how many messages were marked.
    pub async fn stamp_expired_whatsapp_media(&self, retention_days: i64, limit: i64) -> Result<Option<i64>, CoreError> {
        let q = [("retentionDays", retention_days.to_string()), ("limit", limit.to_string())];
        as_int(self.post(Service::EntityProcessor, "/api/entity/processor/whatsapp/internal/media/stampExpired", &q, None).await?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::{HeaderMap, Method, StatusCode, Uri};
    use axum::response::{IntoResponse, Response};
    use axum::Router;
    use parking_lot::Mutex;
    use serde_json::json;

    use super::*;

    /// One request a fake service received.
    #[derive(Debug, Clone)]
    pub(crate) struct Received {
        /// Which fake (`security`, `core`, `entity-processor`, `files`, `ui`) it reached.
        pub service: &'static str,
        pub method: String,
        pub path: String,
        pub query: String,
        pub content_type: Option<String>,
        pub body: String,
    }

    /// The five services the platform jobs call, each on its own port so a call sent to the
    /// wrong service is seen. Every request is recorded; a path answers what a test set in
    /// `answers` (`path` to status and body), else what the Java service answers to a
    /// healthy call.
    #[derive(Default)]
    pub(crate) struct Targets {
        pub received: Mutex<Vec<Received>>,
        pub answers: Mutex<HashMap<String, (u16, String)>>,
    }

    impl Targets {
        pub fn answer(&self, path: &str, status: u16, body: &str) {
            self.answers.lock().insert(path.to_string(), (status, body.to_string()));
        }

        pub fn calls(&self) -> Vec<Received> {
            self.received.lock().clone()
        }

        /// `service path?query` of every call, in order.
        pub fn lines(&self) -> Vec<String> {
            self.received
                .lock()
                .iter()
                .map(|r| if r.query.is_empty() { format!("{} {}", r.service, r.path) } else { format!("{} {}?{}", r.service, r.path, r.query) })
                .collect()
        }

        /// Serves the five fakes and answers the calls over them.
        pub async fn serve(self: &Arc<Self>) -> (Upstreams, PlatformCalls) {
            let mut bases = Vec::new();
            for name in ["security", "core", "entity-processor", "files", "ui"] {
                let state = (self.clone(), name);
                let base = crate::testing::serve(Router::new().fallback(handle).with_state(state)).await;
                bases.push(base);
            }
            let up = |i: usize| -> Result<Upstream, String> { Ok(Upstream::fixed(&[&bases[i]])) };
            let upstreams = || Upstreams { security: up(0), core: up(1), entity_processor: up(2), files: up(3), ui: up(4) };
            (upstreams(), PlatformCalls::new(upstreams()).unwrap())
        }
    }

    fn default_answer(service: &str, path: &str) -> Option<String> {
        let a = match (service, path) {
            ("security", "/api/security/ssl/internal/renew-certificates") => json!({"renewedCount": 2, "failedCount": 1, "errors": ["x.example: dns"]}),
            ("security", "/api/security/internal/tokens/cleanup") => {
                json!({"expiredTokensRemoved": 4, "unusedTokensRemoved": 5, "expiredDraftTokensRemoved": 6})
            }
            ("security", "/api/security/internal/billing/meter/security")
            | ("core", "/api/core/internal/billing/meter")
            | ("entity-processor", "/api/entity/processor/internal/billing/meter")
            | ("files", "/api/files/internal/billing/meter")
            | ("security", "/api/security/internal/billing/reconcile")
            | ("core", "/api/core/internal/billing/reconcile")
            | ("entity-processor", "/api/entity/processor/internal/billing/reconcile")
            | ("files", "/api/files/internal/billing/reconcile")
            | ("core", "/api/core/events/internal/raise") => json!(true),
            ("files", "/api/files/internal/secured/cleanupExpired") => json!(3),
            ("files", "/api/files/internal/static/cleanupExpired") => json!(1),
            ("files", "/api/files/internal/secured/applyRetention") | ("files", "/api/files/internal/static/applyRetention") => json!([]),
            ("entity-processor", "/api/entity/processor/whatsapp/internal/media/stampExpired") => json!(7),
            ("ui", "/api/ui/transports/internal/cleanupOlderThan") => json!({"transportsRemoved": 8, "versionsRemoved": 8}),
            ("core", "/api/core/transports/internal/cleanupOlderThan") => json!({"transportsRemoved": 2, "versionsRemoved": 1}),
            ("core", "/api/core/eventRuns/internal/cleanupOlderThan") => json!({"runsRemoved": 50000, "successesRemoved": 49000, "staleClosed": 3}),
            _ => return None,
        };
        Some(a.to_string())
    }

    async fn handle(
        State((t, service)): State<(Arc<Targets>, &'static str)>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        let path = uri.path().to_string();
        t.received.lock().push(Received {
            service,
            method: method.to_string(),
            path: path.clone(),
            query: uri.query().unwrap_or("").to_string(),
            content_type: headers.get("content-type").and_then(|v| v.to_str().ok()).map(str::to_string),
            body: String::from_utf8_lossy(&body).into_owned(),
        });
        if method != Method::POST {
            return (StatusCode::METHOD_NOT_ALLOWED, r#"{"message":"POST only"}"#).into_response();
        }
        if let Some((s, b)) = t.answers.lock().get(&path).cloned() {
            return (StatusCode::from_u16(s).unwrap_or(StatusCode::OK), b).into_response();
        }
        // core's raise, as `CoreInternalEventController` answers: 400 `false` without an app
        // or client; here also an app named `refused` (not handed to the queue) and `broken`.
        if path == "/api/core/events/internal/raise" {
            let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            match req["appCode"].as_str() {
                None => return (StatusCode::BAD_REQUEST, "false").into_response(),
                Some("refused") => return (StatusCode::OK, "false").into_response(),
                Some("broken") => return (StatusCode::INTERNAL_SERVER_ERROR, r#"{"message":"queue down"}"#).into_response(),
                Some(_) => {}
            }
        }
        match default_answer(service, &path) {
            Some(b) => (StatusCode::OK, [("content-type", "application/json")], b).into_response(),
            None => (StatusCode::NOT_FOUND, format!(r#"{{"message":"{service} has no {path}"}}"#)).into_response(),
        }
    }

    #[tokio::test]
    async fn each_call_goes_to_its_service_as_the_worker_sent_it() {
        let t = Arc::new(Targets::default());
        let (_, c) = t.serve().await;
        assert_eq!(c.renew_certificates(3).await.unwrap().unwrap()["renewedCount"], json!(2));
        assert_eq!(c.cleanup_tokens(90).await.unwrap().unwrap()["unusedTokensRemoved"], json!(5));
        for s in [Service::Security, Service::Core, Service::EntityProcessor, Service::Files] {
            assert_eq!(c.meter(s).await.unwrap(), Some(true), "{s:?}");
            assert_eq!(c.reconcile(s).await.unwrap(), Some(true), "{s:?}");
        }
        assert_eq!(c.cleanup_expired("secured", 500).await.unwrap(), Some(3));
        assert_eq!(c.apply_retention("static", 500).await.unwrap(), Some(vec![]));
        let req = json!({"eventName": "FILES_EXPIRED", "appCode": "a", "clientCode": "C", "data": {"resourceType": "SECURED", "paths": ["/a/x"]}});
        assert_eq!(c.raise_event(&req).await.unwrap(), Some(true));
        assert_eq!(c.cleanup_event_runs(90, 7, 6, 50000).await.unwrap().unwrap()["staleClosed"], json!(3));
        assert_eq!(c.cleanup_transports(Service::Ui, 90, 200).await.unwrap().unwrap()["transportsRemoved"], json!(8));
        assert_eq!(c.cleanup_transports(Service::Core, 90, 200).await.unwrap().unwrap()["versionsRemoved"], json!(1));
        assert_eq!(c.stamp_expired_whatsapp_media(30, 1000).await.unwrap(), Some(7));

        assert_eq!(
            t.lines(),
            [
                "security /api/security/ssl/internal/renew-certificates?daysBeforeExpiry=3",
                "security /api/security/internal/tokens/cleanup?unusedDays=90",
                "security /api/security/internal/billing/meter/security",
                "security /api/security/internal/billing/reconcile",
                "core /api/core/internal/billing/meter",
                "core /api/core/internal/billing/reconcile",
                "entity-processor /api/entity/processor/internal/billing/meter",
                "entity-processor /api/entity/processor/internal/billing/reconcile",
                "files /api/files/internal/billing/meter",
                "files /api/files/internal/billing/reconcile",
                "files /api/files/internal/secured/cleanupExpired?limit=500",
                "files /api/files/internal/static/applyRetention?limit=500",
                "core /api/core/events/internal/raise",
                "core /api/core/eventRuns/internal/cleanupOlderThan?retentionDays=90&successRetentionDays=7&staleAfterHours=6&limit=50000",
                "ui /api/ui/transports/internal/cleanupOlderThan?retentionDays=90&limit=200",
                "core /api/core/transports/internal/cleanupOlderThan?retentionDays=90&limit=200",
                "entity-processor /api/entity/processor/whatsapp/internal/media/stampExpired?retentionDays=30&limit=1000",
            ]
        );
        let calls = t.calls();
        assert!(calls.iter().all(|r| r.method == "POST"));
        // Only the raise carries a body, as JSON.
        let raise = calls.iter().find(|r| r.path.ends_with("/raise")).unwrap();
        assert_eq!(raise.content_type.as_deref(), Some("application/json"));
        assert_eq!(serde_json::from_str::<Value>(&raise.body).unwrap(), req);
        assert!(calls.iter().filter(|r| !r.path.ends_with("/raise")).all(|r| r.body.is_empty() && r.content_type.is_none()));
        // A ui meter or a files transport sweep is not a call anybody makes.
        assert!(c.meter(Service::Ui).await.is_err());
        assert!(c.reconcile(Service::Ui).await.is_err());
        assert!(c.cleanup_transports(Service::Files, 1, 1).await.is_err());
        assert_eq!(t.calls().len(), 17);
    }

    #[tokio::test]
    async fn answers_are_read_as_feign_reads_them() {
        let t = Arc::new(Targets::default());
        let (_, c) = t.serve().await;
        // Empty is null; a refusal is the service's status and message.
        t.answer("/api/core/internal/billing/meter", 200, "");
        assert_eq!(c.meter(Service::Core).await.unwrap(), None);
        t.answer("/api/core/internal/billing/meter", 200, "\"true\"");
        assert_eq!(c.meter(Service::Core).await.unwrap(), Some(true));
        t.answer("/api/core/internal/billing/meter", 200, "{}");
        assert!(c.meter(Service::Core).await.unwrap_err().text().contains("java.lang.Boolean"));
        t.answer("/api/core/internal/billing/meter", 503, r#"{"message":"core is draining"}"#);
        let e = c.meter(Service::Core).await.unwrap_err();
        assert_eq!((e.status(), e.text()), (StatusCode::SERVICE_UNAVAILABLE, "core is draining".to_string()));
        t.answer("/api/files/internal/secured/cleanupExpired", 200, "\" 12 \"");
        assert_eq!(c.cleanup_expired("secured", 1).await.unwrap(), Some(12));
        t.answer("/api/files/internal/secured/cleanupExpired", 200, "1.5");
        assert!(c.cleanup_expired("secured", 1).await.is_err());
        t.answer("/api/files/internal/secured/cleanupExpired", 200, "null");
        assert_eq!(c.cleanup_expired("secured", 1).await.unwrap(), None);
        t.answer("/api/files/internal/secured/applyRetention", 200, "{}");
        assert!(c.apply_retention("secured", 1).await.is_err());
        t.answer("/api/security/internal/tokens/cleanup", 200, "[1]");
        assert!(c.cleanup_tokens(1).await.unwrap_err().text().contains("java.util.Map"));
        t.answer("/api/security/internal/tokens/cleanup", 200, "not json");
        assert!(c.cleanup_tokens(1).await.unwrap_err().text().starts_with("JSON decoding error"));
        // A path segment is escaped as Feign expands it.
        let _ = c.cleanup_expired("a b/c", 1).await;
        assert_eq!(t.calls().last().unwrap().path, "/api/files/internal/a%20b%2Fc/cleanupExpired");
    }

    #[tokio::test]
    async fn a_service_without_an_upstream_fails_only_its_calls() {
        let t = Arc::new(Targets::default());
        let (mut ups, _) = t.serve().await;
        ups.ui = Err("upstream lighthouse:UI needs [registry] zones configured".into());
        let c = PlatformCalls::new(ups).unwrap();
        let e = c.cleanup_transports(Service::Ui, 90, 200).await.unwrap_err();
        assert_eq!(e.text(), "No upstream for the ui service: upstream lighthouse:UI needs [registry] zones configured");
        assert_eq!(c.meter(Service::Core).await.unwrap(), Some(true));
        assert_eq!(t.lines(), ["core /api/core/internal/billing/meter"]);
        let dead = PlatformCalls::new(Upstreams::all(Upstream::fixed(&["http://127.0.0.1:1"]))).unwrap();
        assert!(dead.meter(Service::Files).await.is_err());
    }
}
