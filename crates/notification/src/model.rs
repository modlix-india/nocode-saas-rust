//! What crosses the process boundary: the queue message (`NotificationQueObject`), the core
//! definitions (`CoreNotification`, `NotificationConnectionDetails`) and the recipients
//! security answers (`NotificationUser`), each read the way Jackson reads it into the Java class.

use serde_json::{Map, Value};

/// A field Jackson could not bind: the message is a fatal conversion error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable(pub String);

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `StringDeserializer`: strings as they are, other scalars as their text, containers refused.
fn string_field(m: &Map<String, Value>, key: &str) -> Result<Option<String>, Unreadable> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(Value::Bool(b)) => Ok(Some(b.to_string())),
        Some(Value::Number(n)) => Ok(Some(n.to_string())),
        Some(_) => Err(Unreadable(format!("Cannot deserialize value of type `java.lang.String` from {key}"))),
    }
}

/// `NumberDeserializers.BigIntegerDeserializer`: integers, floats truncated
/// (`ACCEPT_FLOAT_AS_INT`), numeric strings; anything else refused.
fn big_integer_field(m: &Map<String, Value>, key: &str) -> Result<Option<i128>, Unreadable> {
    let bad = || Unreadable(format!("Cannot deserialize value of type `java.math.BigInteger` from {key}"));
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                Ok(Some(i as i128))
            } else if let Some(u) = n.as_u64() {
                Ok(Some(u as i128))
            } else {
                Ok(n.as_f64().map(|f| f.trunc() as i128))
            }
        }
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                return Ok(None);
            }
            t.parse::<i128>().map(Some).map_err(|_| bad())
        }
        Some(_) => Err(bad()),
    }
}

/// A primitive `boolean`: `true`/`false`, their strings, an integer (0 is false), null as false.
fn boolean_field(m: &Map<String, Value>, key: &str) -> Result<bool, Unreadable> {
    let bad = || Unreadable(format!("Cannot deserialize value of type `boolean` from {key}"));
    match m.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(Value::Number(n)) if n.is_i64() || n.is_u64() => Ok(n.to_string() != "0"),
        Some(Value::String(s)) => match s.trim() {
            t if t.eq_ignore_ascii_case("true") => Ok(true),
            t if t.eq_ignore_ascii_case("false") || t.is_empty() => Ok(false),
            _ => Err(bad()),
        },
        Some(_) => Err(bad()),
    }
}

/// `NotificationQueObject` as the listener receives it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct QueueMessage {
    pub id: Option<String>,
    pub app_code: Option<String>,
    pub client_code: Option<String>,
    pub url_client_code: Option<String>,
    pub triggered_user_id: Option<i128>,
    pub target_id: Option<i128>,
    pub target_type: Option<String>,
    pub target_code: Option<String>,
    pub filter_authorization: Option<String>,
    pub notification_name: Option<String>,
    pub notification_category: Option<String>,
    pub connection_name: Option<String>,
    /// `getXDebug()`/`setXDebug()`: the JSON property is `xdebug`.
    pub x_debug: Option<String>,
    pub draft: bool,
    pub payload: Option<Map<String, Value>>,
    /// `DATA` for a data notification (Rust only): pushed to open streams, never stored.
    pub kind: Option<String>,
    /// A data notification's SSE event name.
    pub event_name: Option<String>,
    /// A data notification's data, any JSON (`None` when absent or null).
    pub data: Option<Value>,
    /// When a data notification stops being worth delivering, in epoch milliseconds.
    pub expires_at: Option<i128>,
}

/// [`QueueMessage::kind`] of a data notification.
pub const KIND_DATA: &str = "DATA";

impl QueueMessage {
    /// A data notification rather than a stored one.
    pub fn is_data(&self) -> bool {
        self.kind.as_deref() == Some(KIND_DATA)
    }

    /// `Jackson2JsonMessageConverter` into `NotificationQueObject` with the services'
    /// `ObjectMapper` (unknown properties ignored). A body that is not a JSON object, or a
    /// property Jackson cannot bind, is a conversion error, which Spring rejects for good.
    pub fn parse(body: &[u8]) -> Result<Self, Unreadable> {
        let v: Value = serde_json::from_slice(body).map_err(|e| Unreadable(format!("Failed to convert Message content: {e}")))?;
        let Value::Object(m) = v else {
            return Err(Unreadable("Failed to convert Message content: not a NotificationQueObject".into()));
        };
        let payload = match m.get("payload") {
            None | Some(Value::Null) => None,
            Some(Value::Object(p)) => Some(p.clone()),
            Some(_) => return Err(Unreadable("Cannot deserialize value of type `java.util.Map` from payload".into())),
        };
        Ok(Self {
            id: string_field(&m, "id")?,
            app_code: string_field(&m, "appCode")?,
            client_code: string_field(&m, "clientCode")?,
            url_client_code: string_field(&m, "urlClientCode")?,
            triggered_user_id: big_integer_field(&m, "triggeredUserId")?,
            target_id: big_integer_field(&m, "targetId")?,
            target_type: string_field(&m, "targetType")?,
            target_code: string_field(&m, "targetCode")?,
            filter_authorization: string_field(&m, "filterAuthorization")?,
            notification_name: string_field(&m, "notificationName")?,
            notification_category: string_field(&m, "notificationCategory")?,
            connection_name: string_field(&m, "connectionName")?,
            x_debug: string_field(&m, "xdebug")?,
            draft: boolean_field(&m, "draft")?,
            payload,
            kind: string_field(&m, "kind")?,
            event_name: string_field(&m, "eventName")?,
            data: m.get("data").filter(|d| !d.is_null()).cloned(),
            expires_at: big_integer_field(&m, "expiresAt")?,
        })
    }

    /// Lombok's `toString()`, for the log lines Java writes; a data notification adds its own
    /// properties, with the data's size rather than the data.
    pub fn describe(&self) -> String {
        let s = |v: &Option<String>| v.clone().unwrap_or_else(|| "null".into());
        let n = |v: &Option<i128>| v.map(|x| x.to_string()).unwrap_or_else(|| "null".into());
        let data = match &self.kind {
            None => String::new(),
            Some(kind) => format!(
                ", kind={kind}, eventName={}, expiresAt={}, data={} bytes",
                s(&self.event_name),
                n(&self.expires_at),
                self.data.as_ref().map(|d| d.to_string().len()).unwrap_or(0)
            ),
        };
        format!(
            "NotificationQueObject(id={}, appCode={}, clientCode={}, urlClientCode={}, triggeredUserId={}, targetId={}, targetType={}, targetCode={}, filterAuthorization={}, notificationName={}, notificationCategory={}, connectionName={}, xDebug={}, draft={}, payload={}{data})",
            s(&self.id),
            s(&self.app_code),
            s(&self.client_code),
            s(&self.url_client_code),
            n(&self.triggered_user_id),
            n(&self.target_id),
            s(&self.target_type),
            s(&self.target_code),
            s(&self.filter_authorization),
            s(&self.notification_name),
            s(&self.notification_category),
            s(&self.connection_name),
            s(&self.x_debug),
            self.draft,
            self.payload.as_ref().map(|p| Value::Object(p.clone()).to_string()).unwrap_or_else(|| "null".into()),
        )
    }
}

/// `NotificationType`: what is stored is the constant's name.
pub const NOTIFICATION_TYPES: [&str; 10] =
    ["ALERT", "INFO", "WARNING", "ERROR", "SUCCESS", "REMINDER", "SYSTEM", "PROMOTIONAL", "UPDATE", "SECURITY"];

/// `CoreNotification.NotificationTemplate`: `templateParts` keeps the order core sent it in
/// (Jackson reads it into a `LinkedHashMap`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NotificationTemplate {
    /// Language, then part name, then the FreeMarker source (`None` for a JSON null).
    pub template_parts: Option<Vec<(String, Option<Vec<(String, Option<String>)>>)>>,
}

/// `CoreNotification`.
#[derive(Debug, Clone, PartialEq)]
pub struct CoreNotification {
    pub name: Option<String>,
    /// The `NotificationType` constant; `None` when core sent an explicit null.
    pub notification_type: Option<String>,
    pub default_language: Option<String>,
    pub language_expression: Option<String>,
    /// `None` when absent or null; a channel mapped to null is `Some(None)`.
    pub channel_templates: Option<Vec<(String, Option<NotificationTemplate>)>>,
    /// `channelEnabled`: per channel, whether a person who made no choice gets it (`true` or
    /// absent: on until they turn it off; `false`: off until they turn it on). Rust only: Java
    /// stored it and never read it.
    pub channel_enabled: Vec<(String, bool)>,
}

impl CoreNotification {
    /// The definition from core's JSON, as Feign's Jackson decoder reads it. A value the Java
    /// class cannot hold (an unknown `notificationType`, a template part that is an object) is
    /// a decode error.
    pub fn from_json(v: &Value) -> Result<Self, Unreadable> {
        let Value::Object(m) = v else {
            return Err(Unreadable("Error while extracting response for type [class CoreNotification]".into()));
        };
        let notification_type = match m.get("notificationType") {
            None => Some("INFO".to_string()),
            Some(Value::Null) => None,
            Some(Value::String(t)) if NOTIFICATION_TYPES.contains(&t.as_str()) => Some(t.clone()),
            Some(other) => {
                return Err(Unreadable(format!("Cannot deserialize value of type `NotificationType` from {other}")));
            }
        };
        let channel_templates = match m.get("channelTemplates") {
            None | Some(Value::Null) => None,
            Some(Value::Object(ch)) => {
                let mut out = Vec::new();
                for (k, t) in ch {
                    out.push((k.clone(), Self::template(t)?));
                }
                Some(out)
            }
            Some(_) => return Err(Unreadable("Cannot deserialize channelTemplates".into())),
        };
        let channel_enabled = match m.get("channelEnabled") {
            Some(Value::Object(ce)) => ce.iter().filter_map(|(k, v)| v.as_bool().map(|b| (k.clone(), b))).collect(),
            _ => Vec::new(),
        };
        Ok(Self {
            name: string_field(m, "name")?,
            notification_type,
            default_language: string_field(m, "defaultLanguage")?,
            language_expression: string_field(m, "languageExpression")?,
            channel_templates,
            channel_enabled,
        })
    }

    fn template(v: &Value) -> Result<Option<NotificationTemplate>, Unreadable> {
        let m = match v {
            Value::Null => return Ok(None),
            Value::Object(m) => m,
            _ => return Err(Unreadable("Cannot deserialize NotificationTemplate".into())),
        };
        let template_parts = match m.get("templateParts") {
            None | Some(Value::Null) => None,
            Some(Value::Object(langs)) => {
                let mut out = Vec::new();
                for (lang, parts) in langs {
                    let parts = match parts {
                        Value::Null => None,
                        Value::Object(p) => {
                            let mut list = Vec::new();
                            for (name, _) in p {
                                list.push((name.clone(), string_field(p, name)?));
                            }
                            Some(list)
                        }
                        _ => return Err(Unreadable("Cannot deserialize templateParts".into())),
                    };
                    out.push((lang.clone(), parts));
                }
                Some(out)
            }
            Some(_) => return Err(Unreadable("Cannot deserialize templateParts".into())),
        };
        Ok(Some(NotificationTemplate { template_parts }))
    }

    pub fn has_channel(&self, channel: &str) -> Option<bool> {
        self.channel_templates.as_ref().map(|c| c.iter().any(|(k, _)| k == channel))
    }

    /// Whether `channel` reaches a person who made no choice about it (`channelEnabled`).
    pub fn on_by_default(&self, channel: &str) -> bool {
        self.channel_enabled.iter().find(|(k, _)| k == channel).map_or(true, |(_, on)| *on)
    }

    /// `channelTemplates.get(channel)`: `None` when the channel is absent or mapped to null.
    pub fn channel(&self, channel: &str) -> Option<&NotificationTemplate> {
        self.channel_templates
            .as_ref()
            .and_then(|c| c.iter().find(|(k, _)| k == channel))
            .and_then(|(_, t)| t.as_ref())
    }
}

/// The MAIL connection inside `NotificationConnectionDetails` (`model.Connection`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MailConnection {
    pub connection_sub_type: Option<String>,
    pub connection_details: Option<Map<String, Value>>,
}

/// `NotificationConnectionDetails`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NotificationConnection {
    pub in_app: bool,
    pub mail: Option<MailConnection>,
}

impl NotificationConnection {
    pub fn from_json(v: &Value) -> Result<Self, Unreadable> {
        let Value::Object(m) = v else {
            return Err(Unreadable("Error while extracting response for type [class NotificationConnectionDetails]".into()));
        };
        let mail = match m.get("mail") {
            None | Some(Value::Null) => None,
            Some(Value::Object(c)) => Some(MailConnection {
                connection_sub_type: string_field(c, "connectionSubType")?,
                connection_details: match c.get("connectionDetails") {
                    None | Some(Value::Null) => None,
                    Some(Value::Object(d)) => Some(d.clone()),
                    Some(_) => return Err(Unreadable("Cannot deserialize connectionDetails".into())),
                },
            }),
            Some(_) => return Err(Unreadable("Cannot deserialize mail".into())),
        };
        Ok(Self { in_app: boolean_field(m, "inApp")?, mail })
    }
}

/// `NotificationUser`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NotificationUser {
    pub id: Option<i64>,
    pub client_id: Option<i64>,
    pub email_id: Option<String>,
}

impl NotificationUser {
    pub fn from_json(v: &Value) -> Result<Self, Unreadable> {
        let Value::Object(m) = v else {
            return Err(Unreadable("Cannot deserialize NotificationUser".into()));
        };
        let long = |k: &str| big_integer_field(m, k).map(|x| x.map(|n| n as i64));
        Ok(Self { id: long("id")?, client_id: long("clientId")?, email_id: string_field(m, "emailId")? })
    }
}

/// `UsersListRequest`, written as the services' `ObjectMapper` writes it (`NON_EMPTY`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsersListRequest {
    pub user_ids: Option<Vec<i64>>,
    pub client_code: Option<String>,
    pub client_id: Option<i64>,
    pub app_code: Option<String>,
    /// Only the users holding this authority expression (Rust only; sent for data
    /// notifications).
    pub filter_authorization: Option<String>,
}

impl UsersListRequest {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        if let Some(ids) = self.user_ids.as_ref().filter(|i| !i.is_empty()) {
            m.insert("userIds".into(), Value::from(ids.clone()));
        }
        if let Some(c) = self.client_code.as_ref().filter(|c| !c.is_empty()) {
            m.insert("clientCode".into(), Value::from(c.clone()));
        }
        if let Some(c) = self.client_id {
            m.insert("clientId".into(), Value::from(c));
        }
        if let Some(a) = self.app_code.as_ref().filter(|a| !a.is_empty()) {
            m.insert("appCode".into(), Value::from(a.clone()));
        }
        if let Some(f) = self.filter_authorization.as_ref().filter(|f| !f.trim().is_empty()) {
            m.insert("filterAuthorization".into(), Value::from(f.clone()));
        }
        Value::Object(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_the_message_core_publishes() {
        // As connections::mq writes it (pretty, NON_EMPTY, xdebug last).
        let body = br#"{
  "id" : "0f3c",
  "appCode" : "leadzump",
  "clientCode" : "SYSTEM",
  "urlClientCode" : "SYSTEM",
  "triggeredUserId" : 142,
  "targetId" : 7,
  "targetType" : "User Id",
  "notificationName" : "dealCreated",
  "connectionName" : "notification",
  "draft" : true,
  "payload" : { "b" : 1, "a" : "x" },
  "xdebug" : "dbg-1"
}"#;
        let q = QueueMessage::parse(body).unwrap();
        assert_eq!(q.app_code.as_deref(), Some("leadzump"));
        assert_eq!(q.target_id, Some(7));
        assert_eq!(q.triggered_user_id, Some(142));
        assert!(q.draft);
        assert_eq!(q.x_debug.as_deref(), Some("dbg-1"));
        assert_eq!(q.payload.as_ref().unwrap().keys().collect::<Vec<_>>(), ["b", "a"], "payload keeps its order");
        assert!(q.describe().contains("targetType=User Id") && q.describe().contains("xDebug=dbg-1"));
    }

    #[test]
    fn reads_a_data_notification() {
        let body = br#"{"id":"1","appCode":"leadzumptwo","targetType":"Client Id","targetId":3,"filterAuthorization":"Authorities.Calls",
            "draft":false,"kind":"DATA","eventName":"incomingCall","data":{"from":"+91","n":[1]},"expiresAt":1792634021000}"#;
        let q = QueueMessage::parse(body).unwrap();
        assert!(q.is_data());
        assert_eq!(q.event_name.as_deref(), Some("incomingCall"));
        assert_eq!(q.data, Some(json!({"from": "+91", "n": [1]})));
        assert_eq!(q.expires_at, Some(1792634021000));
        let d = q.describe();
        assert!(d.ends_with(", kind=DATA, eventName=incomingCall, expiresAt=1792634021000, data=22 bytes)"), "{d}");
        let plain = QueueMessage::parse(br#"{"data":null,"kind":null}"#).unwrap();
        assert!(!plain.is_data() && plain.data.is_none());
        assert!(!plain.describe().contains("kind="));
        assert!(QueueMessage::parse(br#"{"kind":"data"}"#).map(|q| !q.is_data()).unwrap(), "the kind is exact");
        assert!(QueueMessage::parse(br#"{"expiresAt":"soon"}"#).is_err());
        assert!(QueueMessage::parse(br#"{"eventName":{"a":1}}"#).is_err());
        assert!(QueueMessage { kind: Some("DATA".into()), ..Default::default() }.describe().contains("data=0 bytes"));
    }

    #[test]
    fn jackson_coercions_and_refusals() {
        let q = QueueMessage::parse(br#"{"targetId":"12","draft":"true","appCode":5,"xDebug":"ignored","extra":[1]}"#).unwrap();
        assert_eq!(q.target_id, Some(12));
        assert!(q.draft);
        assert_eq!(q.app_code.as_deref(), Some("5"));
        assert_eq!(q.x_debug, None, "only `xdebug` binds");
        assert_eq!(QueueMessage::parse(br#"{"targetId":2.9,"draft":1}"#).unwrap().target_id, Some(2));
        assert!(QueueMessage::parse(br#"{"draft":0}"#).map(|q| !q.draft).unwrap());
        assert!(QueueMessage::parse(br#"{"draft":null,"targetId":" "}"#).map(|q| !q.draft && q.target_id.is_none()).unwrap());
        assert!(QueueMessage::parse(br#"{"draft":false,"appCode":true}"#).map(|q| q.app_code.as_deref() == Some("true")).unwrap());
        for bad in [
            &b"not json"[..],
            b"null",
            b"[1]",
            br#"{"targetId":"x"}"#,
            br#"{"targetId":true}"#,
            br#"{"draft":"maybe"}"#,
            br#"{"draft":[1]}"#,
            br#"{"appCode":{"a":1}}"#,
            br#"{"payload":[1]}"#,
        ] {
            assert!(QueueMessage::parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        let e = QueueMessage::parse(b"[]").unwrap_err();
        assert!(e.to_string().contains("Failed to convert"));
        let empty = QueueMessage::default().describe();
        assert!(empty.contains("payload=null") && empty.contains("targetId=null"));
    }

    #[test]
    fn reads_core_definitions() {
        let n = CoreNotification::from_json(&json!({
            "id": "x", "name": "dealCreated", "notificationType": "ALERT", "defaultLanguage": "en",
            "channelTemplates": {"inapp": {"templateParts": {"en": {"title": "T", "n": 5, "z": null}, "fr": null}}, "email": null}
        }))
        .unwrap();
        assert_eq!(n.notification_type.as_deref(), Some("ALERT"));
        assert_eq!(n.has_channel("email"), Some(true));
        assert!(n.channel("email").is_none());
        let parts = n.channel("inapp").unwrap().template_parts.as_ref().unwrap();
        assert_eq!(parts[0].1.as_ref().unwrap()[1], ("n".to_string(), Some("5".to_string())));
        assert_eq!(parts[0].1.as_ref().unwrap()[2], ("z".to_string(), None));
        assert!(parts[1].1.is_none());

        let d = CoreNotification::from_json(&json!({"name": "n"})).unwrap();
        assert_eq!(d.notification_type.as_deref(), Some("INFO"), "the field's default");
        assert_eq!(d.has_channel("inapp"), None);
        assert_eq!(CoreNotification::from_json(&json!({"notificationType": null})).unwrap().notification_type, None);
        for bad in [
            json!([]),
            json!({"notificationType": "NOPE"}),
            json!({"notificationType": 3}),
            json!({"channelTemplates": []}),
            json!({"channelTemplates": {"inapp": 1}}),
            json!({"channelTemplates": {"inapp": {"templateParts": 1}}}),
            json!({"channelTemplates": {"inapp": {"templateParts": {"en": 1}}}}),
            json!({"channelTemplates": {"inapp": {"templateParts": {"en": {"t": {"x": 1}}}}}}),
        ] {
            assert!(CoreNotification::from_json(&bad).is_err(), "{bad}");
        }
        let t = CoreNotification::from_json(&json!({"channelTemplates": {"inapp": {}}})).unwrap();
        assert_eq!(t.channel("inapp").unwrap().template_parts, None);
    }

    #[test]
    fn reads_connection_details_and_users() {
        let c = NotificationConnection::from_json(&json!({
            "inApp": true,
            "mail": {"connectionType": "MAIL", "connectionSubType": "SMTP", "connectionDetails": {"username": "u"}}
        }))
        .unwrap();
        assert!(c.in_app);
        let mail = c.mail.unwrap();
        assert_eq!(mail.connection_sub_type.as_deref(), Some("SMTP"));
        assert_eq!(mail.connection_details.unwrap()["username"], "u");
        assert_eq!(NotificationConnection::from_json(&json!({"inApp": false})).unwrap(), NotificationConnection::default());
        assert!(NotificationConnection::from_json(&json!({"mail": {"connectionDetails": []}})).is_err());
        assert!(NotificationConnection::from_json(&json!({"mail": 1})).is_err());
        assert!(NotificationConnection::from_json(&json!(1)).is_err());
        assert!(NotificationConnection::from_json(&json!({"mail": {}})).unwrap().mail.is_some());

        let u = NotificationUser::from_json(&json!({"id": 142, "clientId": "1", "emailId": "a@b.c", "other": 1})).unwrap();
        assert_eq!(u, NotificationUser { id: Some(142), client_id: Some(1), email_id: Some("a@b.c".into()) });
        assert!(NotificationUser::from_json(&json!("x")).is_err());

        let r = UsersListRequest { user_ids: Some(vec![142]), app_code: Some("app".into()), ..Default::default() };
        assert_eq!(r.to_json(), json!({"userIds": [142], "appCode": "app"}));
        let r = UsersListRequest { client_code: Some("C".into()), client_id: Some(4), ..Default::default() };
        assert_eq!(r.to_json(), json!({"clientCode": "C", "clientId": 4}));
        let r = UsersListRequest { client_id: Some(4), filter_authorization: Some("Authorities.Calls".into()), ..Default::default() };
        assert_eq!(r.to_json(), json!({"clientId": 4, "filterAuthorization": "Authorities.Calls"}));
        let r = UsersListRequest { client_id: Some(4), filter_authorization: Some(" ".into()), ..Default::default() };
        assert_eq!(r.to_json(), json!({"clientId": 4}));
    }
}
