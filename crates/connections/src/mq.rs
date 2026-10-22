//! The RabbitMQ publishers: `EventCreationService` (exchange `events`, routing keys
//! `events1..3`) and the send half of `NotificationService` (exchange `notifications`,
//! `notifications1..3`).
//!
//! Messages are what Spring AMQP's `Jackson2JsonMessageConverter` makes with the services'
//! `ObjectMapper`: pretty-printed JSON (`INDENT_OUTPUT`), `NON_EMPTY` properties in Jackson's
//! order, `content-type: application/json`, `content-encoding: UTF-8`, a `__TypeId__` header
//! naming the Java class, persistent delivery and priority 0. The round robin advances before
//! each send, so the first message goes to the second key, as in Java.

use std::sync::atomic::{AtomicUsize, Ordering};

use lapin::options::BasicPublishOptions;
use lapin::types::{AMQPValue, FieldTable, ShortString};
use lapin::{BasicProperties, Channel, Connection, ConnectionProperties};
use serde_json::{Map, Value};
use tokio::sync::Mutex;

use crate::context::Caller;
use crate::error::{ConnError, ConnResult};
use crate::java::{self, json};

pub const EVENT_TYPE_ID: &str = "com.fincity.saas.commons.mq.events.EventQueObject";
pub const NOTIFICATION_TYPE_ID: &str = "com.fincity.saas.commons.mq.notifications.NotificationQueObject";

/// An exchange and its routing keys (`events.mq.exchange` / `events.mq.routingkeys`).
#[derive(Debug)]
pub struct Route {
    pub exchange: String,
    keys: Vec<String>,
    next: AtomicUsize,
}

impl Route {
    pub fn new(exchange: &str, routing_keys: &str) -> Self {
        Self {
            exchange: exchange.to_string(),
            keys: routing_keys.split(',').map(str::to_string).collect(),
            next: AtomicUsize::new(0),
        }
    }

    pub fn events() -> Self {
        Self::new("events", "events1,events2,events3")
    }

    pub fn notifications() -> Self {
        Self::new("notifications", "notifications1,notifications2,notifications3")
    }

    /// `nextRoutingKey = nextRoutingKey.getNext()`, then its item.
    pub fn next_key(&self) -> &str {
        let i = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        &self.keys[i % self.keys.len()]
    }
}

/// A publishing connection, opened on first use and reopened when it drops (as Spring's
/// `CachingConnectionFactory` does).
pub struct Publisher {
    uri: String,
    channel: Mutex<Option<(Connection, Channel)>>,
}

impl Publisher {
    /// `uri` is an AMQP URI (`amqp://user:password@host:5672/%2f`).
    pub fn new(uri: impl Into<String>) -> Self {
        Self { uri: uri.into(), channel: Mutex::new(None) }
    }

    async fn channel(&self) -> ConnResult<Channel> {
        let mut guard = self.channel.lock().await;
        if let Some((conn, ch)) = guard.as_ref() {
            if conn.status().connected() && ch.status().connected() {
                return Ok(ch.clone());
            }
        }
        let conn = Connection::connect(&self.uri, ConnectionProperties::default())
            .await
            .map_err(|e| ConnError::other(format!("AMQP connection failed: {e}")))?;
        let ch = conn.create_channel().await.map_err(|e| ConnError::other(e.to_string()))?;
        *guard = Some((conn, ch.clone()));
        Ok(ch)
    }

    /// `amqpTemplate.convertAndSend(exchange, routingKey, object)` for an already-written body.
    pub async fn publish(&self, exchange: &str, routing_key: &str, body: &[u8], type_id: &str) -> ConnResult<()> {
        let ch = self.channel().await?;
        ch.basic_publish(
            ShortString::from(exchange),
            ShortString::from(routing_key),
            BasicPublishOptions::default(),
            body,
            message_properties(type_id),
        )
        .await
        .map_err(|e| ConnError::other(e.to_string()))?;
        Ok(())
    }
}

/// The AMQP properties `DefaultMessagePropertiesConverter` writes for a converted message.
pub fn message_properties(type_id: &str) -> BasicProperties {
    let mut headers = FieldTable::default();
    headers.insert(ShortString::from("__TypeId__"), AMQPValue::LongString(type_id.into()));
    BasicProperties::default()
        .with_content_type(ShortString::from("application/json"))
        .with_content_encoding(ShortString::from("UTF-8"))
        .with_headers(headers)
        .with_delivery_mode(2)
        .with_priority(0)
}

fn put_non_empty(m: &mut Map<String, Value>, key: &str, v: Value) {
    if json::jackson_non_empty(&v) {
        m.insert(key.to_string(), v);
    }
}

fn opt_str(s: &Option<String>) -> Value {
    s.as_ref().map(|s| Value::String(s.clone())).unwrap_or(Value::Null)
}

/// A `BigInteger` property as security may send it: a number, or a numeric string.
fn big_integer(v: Option<&Value>) -> Value {
    match v {
        Some(Value::Number(n)) => Value::Number(n.clone()),
        Some(Value::String(s)) => s.trim().parse::<i64>().map(Value::from).unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

/// A `LocalDateTime` property: epoch seconds, as `CommonsSerializationModule` reads and writes.
fn epoch_seconds(v: Option<&Value>) -> Value {
    match v {
        Some(Value::Number(n)) => n.as_i64().map(Value::from).unwrap_or_else(|| Value::from(n.as_f64().unwrap_or(0.0) as i64)),
        _ => Value::Null,
    }
}

fn plain(v: Option<&Value>) -> Value {
    v.cloned().unwrap_or(Value::Null)
}

fn boolean(v: Option<&Value>) -> Value {
    Value::Bool(v.and_then(Value::as_bool).unwrap_or(false))
}

/// `ContextUser` as the services' `ObjectMapper` writes it after reading it from security.
pub fn jackson_context_user(user: &Map<String, Value>) -> Value {
    let mut m = Map::new();
    put_non_empty(&mut m, "id", big_integer(user.get("id")));
    put_non_empty(&mut m, "createdBy", big_integer(user.get("createdBy")));
    put_non_empty(&mut m, "updatedBy", big_integer(user.get("updatedBy")));
    put_non_empty(&mut m, "createdAt", epoch_seconds(user.get("createdAt")));
    put_non_empty(&mut m, "updatedAt", epoch_seconds(user.get("updatedAt")));
    put_non_empty(&mut m, "clientId", big_integer(user.get("clientId")));
    for k in ["userName", "emailId", "phoneNumber", "firstName", "lastName", "middleName", "localeCode", "timeZone"] {
        put_non_empty(&mut m, k, plain(user.get(k)).as_str().map(Value::from).unwrap_or(Value::Null));
    }
    for k in ["accountNonExpired", "accountNonLocked", "credentialsNonExpired"] {
        m.insert(k.into(), boolean(user.get(k)));
    }
    for k in ["noFailedAttempt", "noPinFailedAttempt", "noOtpResendAttempts", "noOtpFailedAttempt"] {
        put_non_empty(&mut m, k, plain(user.get(k)).as_i64().map(Value::from).unwrap_or(Value::Null));
    }
    put_non_empty(&mut m, "statusCode", plain(user.get("statusCode")).as_str().map(Value::from).unwrap_or(Value::Null));
    put_non_empty(&mut m, "lockedUntil", epoch_seconds(user.get("lockedUntil")));
    put_non_empty(&mut m, "lockedDueTo", plain(user.get("lockedDueTo")).as_str().map(Value::from).unwrap_or(Value::Null));
    put_non_empty(&mut m, "stringAuthorities", plain(user.get("stringAuthorities")));
    put_non_empty(&mut m, "designationId", big_integer(user.get("designationId")));
    Value::Object(m)
}

/// The caller's `ContextAuthentication` as the services' `ObjectMapper` writes it: security's
/// answer read into the Java class (unknown and ignored properties dropped), the URL codes
/// from the request, `NON_EMPTY`, then the getter-only `authenticated`, `systemClient`, `name`.
pub fn jackson_authentication(caller: &Caller) -> Value {
    let empty = Map::new();
    let raw = caller.raw.as_ref().unwrap_or(&empty);
    let mut m = Map::new();
    let user = raw.get("user").and_then(Value::as_object);
    if let Some(u) = user {
        m.insert("user".into(), jackson_context_user(u));
    }
    put_non_empty(&mut m, "loggedInFromClientId", big_integer(raw.get("loggedInFromClientId")));
    for k in ["loggedInFromClientCode", "clientTypeCode", "clientLevelType", "clientCode", "accessToken"] {
        put_non_empty(&mut m, k, plain(raw.get(k)).as_str().map(Value::from).unwrap_or(Value::Null));
    }
    put_non_empty(&mut m, "accessTokenExpiryAt", epoch_seconds(raw.get("accessTokenExpiryAt")));
    put_non_empty(&mut m, "urlClientCode", opt_str(&caller.url_client_code));
    put_non_empty(&mut m, "urlAppCode", opt_str(&caller.url_app_code));
    put_non_empty(&mut m, "verifiedAppCode", plain(raw.get("verifiedAppCode")).as_str().map(Value::from).unwrap_or(Value::Null));
    m.insert("authenticated".into(), Value::Bool(caller.authenticated));
    m.insert("systemClient".into(), Value::Bool(raw.get("clientTypeCode").and_then(Value::as_str) == Some("SYS")));
    let name = user.and_then(|u| u.get("firstName")).and_then(Value::as_str).map(Value::from).unwrap_or(Value::Null);
    put_non_empty(&mut m, "name", name);
    Value::Object(m)
}

/// `EventQueObject`.
#[derive(Debug, Clone, Default)]
pub struct EventMessage {
    pub event_name: Option<String>,
    pub client_code: Option<String>,
    pub app_code: Option<String>,
    pub x_debug: Option<String>,
    pub draft: bool,
    /// `JsonUtil.toMap(...)` of the step's data: written in Java's hash order.
    pub data: Option<Map<String, Value>>,
    /// The caller's authentication, already in Jackson's shape ([`jackson_authentication`]).
    pub authentication: Option<Value>,
}

impl EventMessage {
    pub fn to_json(&self) -> String {
        let mut m = Map::new();
        put_non_empty(&mut m, "eventName", opt_str(&self.event_name));
        put_non_empty(&mut m, "clientCode", opt_str(&self.client_code));
        put_non_empty(&mut m, "appCode", opt_str(&self.app_code));
        m.insert("draft".into(), Value::Bool(self.draft));
        let data = self.data.clone().map(|d| java::hash_map_order_deep(Value::Object(d))).unwrap_or(Value::Null);
        put_non_empty(&mut m, "data", data);
        put_non_empty(&mut m, "authentication", self.authentication.clone().unwrap_or(Value::Null));
        // `getXDebug()` names the property `xdebug`, which no field matches: it comes last.
        put_non_empty(&mut m, "xdebug", opt_str(&self.x_debug));
        json::jackson_pretty(&Value::Object(m))
    }
}

/// `NotificationQueObject`.
#[derive(Debug, Clone)]
pub struct NotificationMessage {
    /// A random UUID without dashes, made when the object is.
    pub id: String,
    pub app_code: Option<String>,
    pub client_code: Option<String>,
    pub url_client_code: Option<String>,
    pub triggered_user_id: Option<u64>,
    pub target_id: Option<Value>,
    pub target_type: Option<String>,
    pub target_code: Option<String>,
    pub filter_authorization: Option<String>,
    pub notification_name: Option<String>,
    pub notification_category: Option<String>,
    pub connection_name: Option<String>,
    pub x_debug: Option<String>,
    pub draft: bool,
    pub payload: Option<Map<String, Value>>,
    /// `DATA` for a data notification (Rust only): pushed to the open streams, never stored.
    /// Absent for a normal notification.
    pub kind: Option<String>,
    /// A data notification's SSE event name.
    pub event_name: Option<String>,
    /// A data notification's data, any JSON, sent as given.
    pub data: Option<Value>,
    /// When a data notification stops being worth delivering, in epoch milliseconds.
    pub expires_at: Option<i64>,
}

/// [`NotificationMessage::kind`] of a data notification.
pub const KIND_DATA: &str = "DATA";

impl Default for NotificationMessage {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().simple().to_string(),
            app_code: None,
            client_code: None,
            url_client_code: None,
            triggered_user_id: None,
            target_id: None,
            target_type: None,
            target_code: None,
            filter_authorization: None,
            notification_name: None,
            notification_category: None,
            connection_name: None,
            x_debug: None,
            draft: false,
            payload: None,
            kind: None,
            event_name: None,
            data: None,
            expires_at: None,
        }
    }
}

impl NotificationMessage {
    pub fn to_json(&self) -> String {
        let mut m = Map::new();
        m.insert("id".into(), Value::String(self.id.clone()));
        put_non_empty(&mut m, "appCode", opt_str(&self.app_code));
        put_non_empty(&mut m, "clientCode", opt_str(&self.client_code));
        put_non_empty(&mut m, "urlClientCode", opt_str(&self.url_client_code));
        put_non_empty(&mut m, "triggeredUserId", self.triggered_user_id.map(Value::from).unwrap_or(Value::Null));
        put_non_empty(&mut m, "targetId", self.target_id.clone().unwrap_or(Value::Null));
        put_non_empty(&mut m, "targetType", opt_str(&self.target_type));
        put_non_empty(&mut m, "targetCode", opt_str(&self.target_code));
        put_non_empty(&mut m, "filterAuthorization", opt_str(&self.filter_authorization));
        put_non_empty(&mut m, "notificationName", opt_str(&self.notification_name));
        put_non_empty(&mut m, "notificationCategory", opt_str(&self.notification_category));
        put_non_empty(&mut m, "connectionName", opt_str(&self.connection_name));
        m.insert("draft".into(), Value::Bool(self.draft));
        let payload = self.payload.clone().map(|d| java::hash_map_order_deep(Value::Object(d))).unwrap_or(Value::Null);
        put_non_empty(&mut m, "payload", payload);
        if let Some(kind) = &self.kind {
            // A data notification's own properties; `data` goes as given, null included.
            m.insert("kind".into(), Value::String(kind.clone()));
            put_non_empty(&mut m, "eventName", opt_str(&self.event_name));
            m.insert("data".into(), self.data.clone().unwrap_or(Value::Null));
            put_non_empty(&mut m, "expiresAt", self.expires_at.map(Value::from).unwrap_or(Value::Null));
        }
        put_non_empty(&mut m, "xdebug", opt_str(&self.x_debug));
        json::jackson_pretty(&Value::Object(m))
    }
}

/// The first half of `EventCreationService.createEvent`: the next routing key, and the message
/// with the draft marker and `x-debug` of the caller's request.
pub fn prepare_event(route: &Route, caller: &Caller, mut event: EventMessage) -> (String, String) {
    let key = route.next_key().to_string();
    event.draft = caller.draft;
    if let Some(d) = &caller.debug {
        event.x_debug = Some(d.clone());
    }
    (key, event.to_json())
}

/// `EventCreationService.createEvent`.
pub async fn create_event(publisher: &Publisher, route: &Route, caller: &Caller, event: EventMessage) -> ConnResult<bool> {
    let (key, body) = prepare_event(route, caller, event);
    publisher.publish(&route.exchange, &key, body.as_bytes(), EVENT_TYPE_ID).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_robin_starts_at_the_second_key() {
        let r = Route::events();
        assert_eq!([r.next_key(), r.next_key(), r.next_key(), r.next_key()], ["events2", "events3", "events1", "events2"]);
    }
}
