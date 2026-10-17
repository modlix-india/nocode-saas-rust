//! What an OTP sign-in sends out: the `USER_OTP_GENERATE` event on RabbitMQ (which ends in an
//! e-mail, sent by core's event actions) and the 2Factor SMS.
//!
//! The event is what `EventCreationService.createEvent` publishes: exchange `events`, routing keys
//! `events1..3` taken round robin (advanced before each send), `Jackson2JsonMessageConverter`
//! with the services' `ObjectMapper` (pretty JSON, `NON_EMPTY`), `__TypeId__` naming the Java
//! class, persistent delivery. The AMQP side is `crates/connections`' publisher.

use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use axum::http::StatusCode;
use connections::mq::Publisher;
use serde_json::Value;

use crate::errors::{AuthError, AuthResult, SMS_OTP_ERROR};
use crate::jackson::{pretty, Obj};

pub const EVENT_TYPE_ID: &str = "com.fincity.saas.commons.mq.events.EventQueObject";
pub const USER_OTP_GENERATE: &str = "USER_OTP_GENERATE";

/// `EventQueObject`.
#[derive(Debug, Clone, Default)]
pub struct EventMessage {
    pub event_name: String,
    pub client_code: Option<String>,
    pub app_code: Option<String>,
    pub x_debug: Option<String>,
    pub draft: bool,
    /// `Map.of(...)`: its order is random per JVM, so any order is Java's order.
    pub data: Vec<(String, Value)>,
}

impl EventMessage {
    pub fn to_json(&self) -> String {
        let mut data = serde_json::Map::new();
        for (k, v) in &self.data {
            data.insert(k.clone(), v.clone());
        }
        let v = Obj::new()
            .put("eventName", self.event_name.clone())
            .put("clientCode", crate::jackson::opt(self.client_code.clone()))
            .put("appCode", crate::jackson::opt(self.app_code.clone()))
            .put("draft", self.draft)
            .put("data", Value::Object(data))
            // `getXDebug()` names the property `xdebug`, which no field matches: it comes last.
            .put("xdebug", crate::jackson::opt(self.x_debug.clone()))
            .build();
        pretty(&v)
    }
}

#[async_trait]
pub trait EventSink: Send + Sync {
    /// `createEvent`: true once published.
    async fn publish(&self, event: &EventMessage) -> AuthResult<bool>;
}

/// The local stack's sink: the event is logged and counted as sent, so a test sign-in mails
/// nobody.
pub struct LoggedEvents;

#[async_trait]
impl EventSink for LoggedEvents {
    async fn publish(&self, event: &EventMessage) -> AuthResult<bool> {
        tracing::info!(event = event.event_name, app = ?event.app_code, client = ?event.client_code, "event not published (otp.publish_events = false)");
        Ok(true)
    }
}

/// RabbitMQ, opened on first use and reopened when it drops.
pub struct AmqpEvents {
    publisher: Publisher,
    exchange: String,
    keys: Vec<String>,
    next: AtomicUsize,
}

impl AmqpEvents {
    pub fn new(uri: &str, exchange: &str, routing_keys: &str) -> Self {
        Self {
            publisher: Publisher::new(uri),
            exchange: exchange.to_string(),
            keys: routing_keys.split(',').map(|k| k.trim().to_string()).filter(|k| !k.is_empty()).collect(),
            next: AtomicUsize::new(0),
        }
    }

    /// `nextRoutingKey = nextRoutingKey.getNext()`: the first message goes to the second key.
    pub fn next_key(&self) -> String {
        if self.keys.is_empty() {
            return String::new();
        }
        let i = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        self.keys[i % self.keys.len()].clone()
    }

    /// Publishes a body to `exchange` with `routing_key`, through `crates/connections`'
    /// publisher (one connection, reopened when it drops).
    pub async fn send(&self, exchange: &str, routing_key: &str, body: &[u8]) -> AuthResult<()> {
        self.publisher.publish(exchange, routing_key, body, EVENT_TYPE_ID).await.map_err(AuthError::internal)
    }
}

/// The AMQP properties Spring AMQP writes for a converted `EventQueObject`.
pub fn message_properties() -> lapin::BasicProperties {
    connections::mq::message_properties(EVENT_TYPE_ID)
}

#[async_trait]
impl EventSink for AmqpEvents {
    async fn publish(&self, event: &EventMessage) -> AuthResult<bool> {
        let key = self.next_key();
        self.send(&self.exchange.clone(), &key, event.to_json().as_bytes()).await?;
        Ok(true)
    }
}

#[async_trait]
pub trait SmsSender: Send + Sync {
    /// `MessageService.sendOtpMessage(phone, vars)`.
    async fn send_otp(&self, phone: &str, purpose_display: &str, otp: &str, expire_minutes: i64) -> AuthResult<bool>;
}

/// `TwoFactorService`: 2Factor's transactional SMS, or a log line when no API key is set.
pub struct TwoFactorSms {
    pub api_key: String,
    pub base_url: String,
    http: reqwest::Client,
}

pub const TWO_FACTOR_API_URL: &str = "https://2factor.in/API/R1/";

impl TwoFactorSms {
    pub fn new(api_key: &str, base_url: &str) -> Self {
        Self { api_key: api_key.to_string(), base_url: base_url.to_string(), http: reqwest::Client::new() }
    }

    /// `TransactionalSms.toBodyMap()`.
    pub fn form(&self, phone: &str, purpose_display: &str, otp: &str, expire_minutes: i64) -> Vec<(String, String)> {
        [
            ("module", "TRANS_SMS".to_string()),
            ("apikey", self.api_key.clone()),
            ("to", phone.to_string()),
            ("from", "APYAFI".to_string()),
            ("templatename", "APYACXFININVOTP".to_string()),
            ("var1", purpose_display.to_string()),
            ("var2", otp.to_string()),
            ("var3", format!("{expire_minutes}mins")),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }
}

#[async_trait]
impl SmsSender for TwoFactorSms {
    async fn send_otp(&self, phone: &str, purpose_display: &str, otp: &str, expire_minutes: i64) -> AuthResult<bool> {
        if self.api_key.trim().is_empty() {
            tracing::info!(phone, "SMS not sent: no 2Factor key configured");
            return Ok(true);
        }
        // Every failure ends as Java's onErrorResume does: a 500 whose message is the key itself.
        let failed = || AuthError::literal(StatusCode::INTERNAL_SERVER_ERROR, "SEC.SMS_OTP_ERROR", SMS_OTP_ERROR);
        let resp = self
            .http
            .post(&self.base_url)
            .header("Accept", "application/json")
            .form(&self.form(phone, purpose_display, otp, expire_minutes))
            .send()
            .await
            .map_err(|_| failed())?;
        if !resp.status().is_success() {
            return Err(failed());
        }
        let body: Value = resp.json().await.map_err(|_| failed())?;
        match body.get("Status").and_then(Value::as_str) {
            Some(s) if s != "Error" => Ok(true),
            _ => Err(failed()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_json_in_jackson_order() {
        let e = EventMessage {
            event_name: USER_OTP_GENERATE.into(),
            client_code: Some("SYSTEM".into()),
            app_code: Some("appbuilder".into()),
            x_debug: Some("dbg".into()),
            draft: false,
            data: vec![("otp".into(), Value::from("1234")), ("expireInterval".into(), Value::from(5))],
        };
        assert_eq!(
            e.to_json(),
            "{\n  \"eventName\" : \"USER_OTP_GENERATE\",\n  \"clientCode\" : \"SYSTEM\",\n  \"appCode\" : \"appbuilder\",\n  \"draft\" : false,\n  \"data\" : {\n    \"otp\" : \"1234\",\n    \"expireInterval\" : 5\n  },\n  \"xdebug\" : \"dbg\"\n}"
        );
    }

    #[test]
    fn routing_keys_round_robin_from_the_second() {
        let a = AmqpEvents::new("amqp://x", "events", "events1,events2,events3");
        assert_eq!((a.next_key(), a.next_key(), a.next_key(), a.next_key()), ("events2".into(), "events3".into(), "events1".into(), "events2".into()));
        assert_eq!(AmqpEvents::new("amqp://x", "events", "").next_key(), "");
        let p = message_properties();
        assert_eq!(p.delivery_mode(), &Some(2));
        assert_eq!(p.content_type().as_ref().map(|s| s.as_str()), Some("application/json"));
    }

    #[test]
    fn sms_form_matches_two_factor_body() {
        let s = TwoFactorSms::new("k", TWO_FACTOR_API_URL);
        let f = s.form("+919999999999", "login", "1234", 5);
        assert_eq!(f[0], ("module".to_string(), "TRANS_SMS".to_string()));
        assert_eq!(f[7], ("var3".to_string(), "5mins".to_string()));
    }

    #[tokio::test]
    async fn sms_without_key_is_logged() {
        assert!(TwoFactorSms::new("", TWO_FACTOR_API_URL).send_otp("1", "login", "1", 5).await.unwrap());
        assert!(LoggedEvents.publish(&EventMessage::default()).await.unwrap());
    }

    #[tokio::test]
    async fn sms_against_a_local_provider() {
        use axum::routing::post;
        let app = axum::Router::new()
            .route("/ok/", post(|| async { axum::Json(serde_json::json!({"Status": "Success"})) }))
            .route("/err/", post(|| async { axum::Json(serde_json::json!({"Status": "Error"})) }))
            .route("/bad/", post(|| async { (StatusCode::BAD_REQUEST, "no") }))
            .route("/junk/", post(|| async { "not json" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let at = |p: &str| TwoFactorSms::new("key", &format!("http://{addr}/{p}/"));
        assert!(at("ok").send_otp("1", "login", "1", 5).await.unwrap());
        for p in ["err", "bad", "junk"] {
            let e = at(p).send_otp("1", "login", "1", 5).await.unwrap_err();
            assert_eq!((e.status(), e.message()), (StatusCode::INTERNAL_SERVER_ERROR, SMS_OTP_ERROR.to_string()));
        }
        let unreachable = TwoFactorSms::new("key", "http://127.0.0.1:1/");
        assert!(unreachable.send_otp("1", "l", "1", 5).await.is_err());
    }

    /// Against the local RabbitMQ (gated: `SECURITY_AUTH_LIVE=1` and `SECURITY_AUTH_TEST_MQ_URI`).
    /// Publishes to the default exchange with a routing key no queue is bound to, so the message
    /// is dropped and nobody is mailed.
    #[tokio::test]
    async fn amqp_publish_live() {
        let (Ok(_), Ok(uri)) = (std::env::var("SECURITY_AUTH_LIVE"), std::env::var("SECURITY_AUTH_TEST_MQ_URI")) else {
            eprintln!("skipped: SECURITY_AUTH_LIVE / SECURITY_AUTH_TEST_MQ_URI not set");
            return;
        };
        let a = AmqpEvents::new(&uri, "", "security-auth-test-nowhere");
        a.send("", "security-auth-test-nowhere", b"{}").await.unwrap();
        // The connection is reused.
        a.send("", "security-auth-test-nowhere", b"{}").await.unwrap();
    }

    /// A broker nobody listens on: the publish fails (no network beyond the refused connect).
    #[tokio::test]
    async fn amqp_publish_unreachable() {
        let bad = AmqpEvents::new("amqp://nobody:nothing@127.0.0.1:1/%2f", "", "x");
        assert!(bad.publish(&EventMessage::default()).await.is_err());
    }
}
