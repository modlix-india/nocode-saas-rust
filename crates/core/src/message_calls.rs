//! `IFeignMessageService` (Feign name `message`): the message service's internal routes the
//! `CoreServices.Message.*` functions call. They check only that a session belongs to the app
//! and client named; whether the caller may act for that client is decided in the functions
//! before any of these is called.
//!
//! Feign semantics as in [`crate::clients`]: `@RequestParam`s in declaration order (a null one
//! left out), path variables escaped, JSON bodies (Jackson, `Content-Type: application/json`),
//! an empty 2xx body is an empty `Mono` (`None`), a non-2xx answer is the other service's
//! status and message. Answers are untyped (`Map<String, Object>`), passed straight back.

use anyhow::anyhow;
use platform::upstream::Upstream;
use serde_json::{Map, Value};

use crate::clients::{client, text, PATH_SEGMENT};
use crate::error::CoreError;

pub const WHATSAPP_SESSION_PATH: &str = "/api/message/whatsapp/sessions/internal";
pub const EXOTEL_CALL_PATH: &str = "/api/message/call/exotel";

/// Jackson's error for an answer that does not read into the declared type.
fn decode_error(what: &str, detail: impl std::fmt::Display) -> CoreError {
    CoreError::from(anyhow!("JSON decoding error: Cannot deserialize value of type `{what}`: {detail}"))
}

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

/// A `Mono<Map<String, Object>>` answer.
pub(crate) fn as_map(body: Option<String>) -> Result<Option<Map<String, Value>>, CoreError> {
    match parse(body)? {
        None => Ok(None),
        Some(Value::Object(m)) => Ok(Some(m)),
        Some(other) => Err(decode_error("java.util.LinkedHashMap<java.lang.String,java.lang.Object>", other)),
    }
}

/// A `Mono<List<...>>` answer.
fn as_list(body: Option<String>) -> Result<Option<Vec<Value>>, CoreError> {
    match parse(body)? {
        None => Ok(None),
        Some(Value::Array(a)) => Ok(Some(a)),
        Some(other) => Err(decode_error("java.util.ArrayList<java.util.Map<java.lang.String,java.lang.Object>>", other)),
    }
}

/// A `Mono<Boolean>` answer: `true`/`false`, or a string of either.
fn as_bool(body: Option<String>) -> Result<Option<bool>, CoreError> {
    match parse(body)? {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(b)),
        Some(Value::String(s)) if s == "true" || s == "false" => Ok(Some(s == "true")),
        Some(other) => Err(decode_error("java.lang.Boolean", other)),
    }
}

fn segment(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, PATH_SEGMENT).to_string()
}

pub struct MessageCalls {
    upstream: Upstream,
    http: reqwest::Client,
}

impl MessageCalls {
    pub fn new(upstream: Upstream) -> anyhow::Result<Self> {
        Ok(Self { upstream, http: client()? })
    }

    async fn url(&self, path: &str) -> Result<String, CoreError> {
        let base = self.upstream.base().await.map_err(CoreError::from)?;
        Ok(format!("{base}{path}"))
    }

    fn tenant<'a>(app_code: &'a str, client_code: &'a str) -> Vec<(&'static str, &'a str)> {
        vec![("appCode", app_code), ("clientCode", client_code)]
    }

    fn session_path(session_id: &str, rest: &str) -> String {
        format!("{WHATSAPP_SESSION_PATH}/{}{rest}", segment(session_id))
    }

    fn json(rb: reqwest::RequestBuilder, body: &Value) -> reqwest::RequestBuilder {
        rb.header("Content-Type", "application/json").body(body.to_string())
    }

    /// `createWhatsappSession`: places a session on a bridge and starts pairing. The body
    /// carries `phoneNumber`, an optional `productId` and `ownerService`.
    pub async fn create_whatsapp_session(&self, app_code: &str, client_code: &str, body: &Value) -> Result<Option<Map<String, Value>>, CoreError> {
        let rb = self.http.post(self.url(WHATSAPP_SESSION_PATH).await?).query(&Self::tenant(app_code, client_code));
        as_map(text(Self::json(rb, body)).await?)
    }

    /// `listWhatsappSessions`: every session the tenant has.
    pub async fn list_whatsapp_sessions(&self, app_code: &str, client_code: &str) -> Result<Option<Vec<Value>>, CoreError> {
        let rb = self.http.get(self.url(WHATSAPP_SESSION_PATH).await?).query(&Self::tenant(app_code, client_code));
        as_list(text(rb).await?)
    }

    /// `getWhatsappSessionQr`: the pairing code of a session that is still pairing.
    pub async fn get_whatsapp_session_qr(&self, app_code: &str, client_code: &str, session_id: &str) -> Result<Option<Map<String, Value>>, CoreError> {
        let rb = self
            .http
            .get(self.url(&Self::session_path(session_id, "/qr")).await?)
            .query(&Self::tenant(app_code, client_code));
        as_map(text(rb).await?)
    }

    /// `unlinkWhatsappSession` (`Mono<Void>`: whatever comes back is dropped).
    pub async fn unlink_whatsapp_session(&self, app_code: &str, client_code: &str, session_id: &str) -> Result<(), CoreError> {
        let rb = self
            .http
            .delete(self.url(&Self::session_path(session_id, "")).await?)
            .query(&Self::tenant(app_code, client_code));
        text(rb).await.map(|_| ())
    }

    /// `markWhatsappSessionDefault`: false when the code names nothing placeable.
    pub async fn mark_whatsapp_session_default(&self, app_code: &str, client_code: &str, session_id: &str) -> Result<Option<bool>, CoreError> {
        let rb = self
            .http
            .patch(self.url(&Self::session_path(session_id, "/default")).await?)
            .query(&Self::tenant(app_code, client_code));
        as_bool(text(rb).await?)
    }

    /// `resolveWhatsappSession`: the session a code names, or the tenant's default; empty when
    /// the tenant has no linked number. A null `sessionCode` is left out of the query.
    pub async fn resolve_whatsapp_session(&self, app_code: &str, client_code: &str, session_code: Option<&str>) -> Result<Option<Map<String, Value>>, CoreError> {
        let mut q = Self::tenant(app_code, client_code);
        if let Some(s) = session_code {
            q.push(("sessionCode", s));
        }
        let rb = self.http.get(self.url(&format!("{WHATSAPP_SESSION_PATH}/resolve")).await?).query(&q);
        as_map(text(rb).await?)
    }

    /// `sendWhatsappSessionMessage`: a text, or an attachment with an optional caption.
    pub async fn send_whatsapp_session_message(
        &self,
        app_code: &str,
        client_code: &str,
        session_id: &str,
        body: &Value,
    ) -> Result<Option<Map<String, Value>>, CoreError> {
        let rb = self
            .http
            .post(self.url(&Self::session_path(session_id, "/messages")).await?)
            .query(&Self::tenant(app_code, client_code));
        as_map(text(Self::json(rb, body)).await?)
    }

    /// `makeCallInternal`: places a call, recording `ownerService` for its status events.
    pub async fn make_call_internal(
        &self,
        app_code: &str,
        client_code: &str,
        owner_service: &str,
        body: &Value,
    ) -> Result<Option<Map<String, Value>>, CoreError> {
        let mut q = Self::tenant(app_code, client_code);
        q.push(("ownerService", owner_service));
        let rb = self.http.post(self.url(&format!("{EXOTEL_CALL_PATH}/internal/make")).await?).query(&q);
        as_map(text(Self::json(rb, body)).await?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use axum::extract::RawQuery;
    use axum::http::{HeaderMap, Method, StatusCode, Uri};
    use axum::response::IntoResponse;
    use axum::routing::any;
    use axum::Router;
    use parking_lot::Mutex;
    use serde_json::json;

    use super::*;
    use crate::testing::serve;

    /// Every request the fake message service saw: method, path, query, content type, body.
    pub(crate) type Seen = Arc<Mutex<Vec<(String, String, String, String, String)>>>;

    /// A message service that answers each route from `answers` (path suffix -> status and
    /// body), recording every request.
    pub(crate) async fn fake(answers: Vec<(&'static str, u16, &'static str)>) -> (String, Seen) {
        let seen: Seen = Default::default();
        let s = seen.clone();
        let router = Router::new().fallback(any(move |method: Method, uri: Uri, RawQuery(q): RawQuery, h: HeaderMap, body: String| {
            let s = s.clone();
            let answers = answers.clone();
            async move {
                let path = uri.path().to_string();
                let ct = h.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                s.lock().push((method.to_string(), path.clone(), q.unwrap_or_default(), ct, body));
                match answers.iter().find(|(suffix, _, _)| path.ends_with(suffix)) {
                    Some((_, status, body)) => (StatusCode::from_u16(*status).unwrap(), body.to_string()).into_response(),
                    None => StatusCode::OK.into_response(),
                }
            }
        }));
        (serve(router).await, seen)
    }

    #[tokio::test]
    async fn routes_queries_and_bodies_as_feign_sends_them() {
        let (base, seen) = fake(vec![
            ("/internal", 200, r#"{"code":"S1","x":null}"#),
            ("/qr", 200, r#"{"qr":"2@a"}"#),
            ("/default", 200, "true"),
            ("/resolve", 200, r#"{"code":"S1"}"#),
            ("/messages", 200, r#"{"messageId":"m"}"#),
            ("/make", 200, r#"{"sid":"c"}"#),
        ])
        .await;
        let m = MessageCalls::new(Upstream::fixed(&[&base])).unwrap();
        let body = json!({"phoneNumber": "+91"});
        assert_eq!(m.create_whatsapp_session("app", "C1", &body).await.unwrap().unwrap()["code"], json!("S1"));
        assert_eq!(m.get_whatsapp_session_qr("app", "C1", "S 1/2").await.unwrap().unwrap()["qr"], json!("2@a"));
        m.unlink_whatsapp_session("app", "C1", "S1").await.unwrap();
        assert_eq!(m.mark_whatsapp_session_default("app", "C1", "S1").await.unwrap(), Some(true));
        assert!(m.resolve_whatsapp_session("app", "C1", None).await.unwrap().is_some());
        assert!(m.resolve_whatsapp_session("app", "C1", Some("S9")).await.unwrap().is_some());
        assert!(m.send_whatsapp_session_message("app", "C1", "S1", &json!({"to": "1"})).await.unwrap().is_some());
        assert!(m.make_call_internal("app", "C1", "core", &json!({})).await.unwrap().is_some());

        let seen = seen.lock().clone();
        let lines: Vec<String> = seen.iter().map(|(m, p, q, ct, b)| format!("{m} {p}?{q} [{ct}] {b}")).collect();
        assert_eq!(
            lines,
            [
                r#"POST /api/message/whatsapp/sessions/internal?appCode=app&clientCode=C1 [application/json] {"phoneNumber":"+91"}"#,
                "GET /api/message/whatsapp/sessions/internal/S%201%2F2/qr?appCode=app&clientCode=C1 [] ",
                "DELETE /api/message/whatsapp/sessions/internal/S1?appCode=app&clientCode=C1 [] ",
                "PATCH /api/message/whatsapp/sessions/internal/S1/default?appCode=app&clientCode=C1 [] ",
                "GET /api/message/whatsapp/sessions/internal/resolve?appCode=app&clientCode=C1 [] ",
                "GET /api/message/whatsapp/sessions/internal/resolve?appCode=app&clientCode=C1&sessionCode=S9 [] ",
                r#"POST /api/message/whatsapp/sessions/internal/S1/messages?appCode=app&clientCode=C1 [application/json] {"to":"1"}"#,
                "POST /api/message/call/exotel/internal/make?appCode=app&clientCode=C1&ownerService=core [application/json] {}",
            ]
        );
    }

    #[tokio::test]
    async fn answers_are_read_as_jackson_reads_them() {
        let (base, _) = fake(vec![("/internal", 200, r#"[{"code":"S1"}]"#), ("/default", 200, "null"), ("/qr", 200, "")]).await;
        let m = MessageCalls::new(Upstream::fixed(&[&base])).unwrap();
        assert_eq!(m.list_whatsapp_sessions("a", "c").await.unwrap().unwrap().len(), 1);
        assert_eq!(m.mark_whatsapp_session_default("a", "c", "S").await.unwrap(), None);
        assert_eq!(m.get_whatsapp_session_qr("a", "c", "S").await.unwrap(), None);
        // A list where a map is expected, and the other way round.
        assert!(m.create_whatsapp_session("a", "c", &json!({})).await.unwrap_err().text().contains("LinkedHashMap"));

        let (base, _) = fake(vec![("/internal", 200, r#"{"a":1}"#), ("/default", 200, r#""false""#), ("/resolve", 200, "{bad")]).await;
        let m = MessageCalls::new(Upstream::fixed(&[&base])).unwrap();
        assert!(m.list_whatsapp_sessions("a", "c").await.unwrap_err().text().contains("ArrayList"));
        assert_eq!(m.mark_whatsapp_session_default("a", "c", "S").await.unwrap(), Some(false));
        assert!(m.resolve_whatsapp_session("a", "c", None).await.unwrap_err().text().starts_with("JSON decoding error"));

        let (base, _) = fake(vec![("/default", 200, "1"), ("/S", 409, r#"{"message":"already linked"}"#)]).await;
        let m = MessageCalls::new(Upstream::fixed(&[&base])).unwrap();
        assert!(m.mark_whatsapp_session_default("a", "c", "S").await.unwrap_err().text().contains("Boolean"));
        let e = m.unlink_whatsapp_session("a", "c", "S").await.unwrap_err();
        assert_eq!((e.status(), e.text()), (StatusCode::CONFLICT, "already linked".to_string()));

        let dead = MessageCalls::new(Upstream::fixed(&["http://127.0.0.1:1"])).unwrap();
        assert!(dead.list_whatsapp_sessions("a", "c").await.is_err());
    }
}
