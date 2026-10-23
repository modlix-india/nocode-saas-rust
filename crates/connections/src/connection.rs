//! The `connection` document (`document/Connection` and its enums) and the read rules
//! `ConnectionService` puts on top of the overridable read.
//!
//! Connections are overridable definitions in the `core` database. This crate does not read
//! Mongo: the core crate resolves them through `crates/overridable` and hands them in, either
//! directly or through a [`ConnectionStore`]. The JSON taken is the resolved document as Java
//! sees it, with Mongo's escaped keys (`mail__d-o-t__smtp...`) already unescaped.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::context::Caller;
use crate::error::{ConnError, ConnResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConnectionType {
    AppData,
    Mail,
    RestApi,
    Notification,
    Text,
    Call,
    Ai,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionSubType {
    #[serde(rename = "MONGO")]
    Mongo,
    #[serde(rename = "MYSQL")]
    MySql,
    #[serde(rename = "OFFICE365")]
    Office365,
    #[serde(rename = "SENDGRID")]
    SendGrid,
    #[serde(rename = "WHATSAPP")]
    WhatsApp,
    #[serde(rename = "REST_API_OAUTH2")]
    RestApiOAuth2,
    #[serde(rename = "REST_API_BASIC")]
    RestApiBasic,
    #[serde(rename = "REST_API_AUTH")]
    RestApiAuth,
    #[serde(rename = "SMTP")]
    Smtp,
    #[serde(rename = "EXOTEL")]
    Exotel,
    #[serde(rename = "OPENAI")]
    OpenAi,
    #[serde(rename = "GEMINI")]
    Gemini,
    #[serde(rename = "CLAUDE")]
    Claude,
    #[serde(rename = "GROK")]
    Grok,
    #[serde(rename = "DEEP_SEEK")]
    DeepSeek,
}

impl ConnectionSubType {
    /// The constant's name, as `String.valueOf(enum)` prints it in messages.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Mongo => "MONGO",
            Self::MySql => "MYSQL",
            Self::Office365 => "OFFICE365",
            Self::SendGrid => "SENDGRID",
            Self::WhatsApp => "WHATSAPP",
            Self::RestApiOAuth2 => "REST_API_OAUTH2",
            Self::RestApiBasic => "REST_API_BASIC",
            Self::RestApiAuth => "REST_API_AUTH",
            Self::Smtp => "SMTP",
            Self::Exotel => "EXOTEL",
            Self::OpenAi => "OPENAI",
            Self::Gemini => "GEMINI",
            Self::Claude => "CLAUDE",
            Self::Grok => "GROK",
            Self::DeepSeek => "DEEP_SEEK",
        }
    }
}

impl ConnectionType {
    /// `ConnectionType.hasConnectionSubType`.
    pub fn has_sub_type(&self, sub: ConnectionSubType) -> bool {
        use ConnectionSubType::*;
        match self {
            Self::AppData => matches!(sub, Mongo | MySql),
            Self::Mail => matches!(sub, SendGrid | Smtp),
            Self::RestApi => matches!(sub, RestApiBasic | RestApiAuth | RestApiOAuth2),
            Self::Notification => false,
            Self::Text => matches!(sub, WhatsApp),
            Self::Call => matches!(sub, Exotel),
            Self::Ai => matches!(sub, OpenAi | Gemini | Claude | Grok | DeepSeek),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::AppData => "APP_DATA",
            Self::Mail => "MAIL",
            Self::RestApi => "REST_API",
            Self::Notification => "NOTIFICATION",
            Self::Text => "TEXT",
            Self::Call => "CALL",
            Self::Ai => "AI",
        }
    }

    /// `ConnectionType.valueOf(name)`, as Spring binds the `connectionType` request parameter.
    pub fn value_of(name: &str) -> Option<Self> {
        serde_json::from_value(Value::String(name.to_string())).ok()
    }
}

/// `OAuth2GrantTypes`.
pub const GRANT_CLIENT_CREDENTIALS: &str = "CLIENT_CREDENTIALS";
pub const GRANT_AUTHORIZATION_CODE: &str = "AUTHORIZATION_CODE";

/// A resolved connection document.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub app_code: Option<String>,
    #[serde(default)]
    pub client_code: Option<String>,
    #[serde(default)]
    pub connection_type: Option<ConnectionType>,
    #[serde(default)]
    pub connection_sub_type: Option<ConnectionSubType>,
    #[serde(default)]
    pub connection_details: Option<Map<String, Value>>,
    /// `Boolean isAppLevel = FALSE`: absent and null both read as false.
    #[serde(default)]
    pub is_app_level: Option<bool>,
    #[serde(default, rename = "onlyThruKIRun")]
    pub only_thru_kirun: Option<bool>,
    /// Rust only: who may start this connection's OAuth consent (`POST /oauth/evoke`), as an
    /// authority expression like a storage's `createAuth`. Absent or blank, anyone who can
    /// read the connection may, as before. Left out of the JSON when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_auth: Option<String>,
    /// Everything else the document carries (`id`, `version`, `baseClientCode`, audit fields),
    /// kept so the core crate can answer the document whole.
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

impl Connection {
    pub fn from_json(v: Value) -> ConnResult<Self> {
        serde_json::from_value(v).map_err(|e| ConnError::other(format!("Unable to read the connection: {e}")))
    }

    pub fn name(&self) -> &str {
        self.name.as_deref().unwrap_or("")
    }

    pub fn details(&self) -> Option<&Map<String, Value>> {
        self.connection_details.as_ref()
    }

    pub fn detail(&self, key: &str) -> Option<&Value> {
        self.connection_details.as_ref().and_then(|d| d.get(key))
    }

    /// A detail that Java casts to `(String)`: `None` for a missing key or a JSON null.
    pub fn detail_str(&self, key: &str) -> Option<&str> {
        self.detail(key).and_then(Value::as_str)
    }

    pub fn is_app_level(&self) -> bool {
        self.is_app_level.unwrap_or(false)
    }

    pub fn only_thru_kirun(&self) -> bool {
        self.only_thru_kirun.unwrap_or(false)
    }
}

/// The overridable read of a connection, which the core crate provides over
/// `crates/overridable`: `readInternal(name, appCode, urlClientCode, clientCode)` on the
/// caller's surface (draft or live). No type or client checks; those are applied here.
#[async_trait]
pub trait ConnectionStore: Send + Sync {
    async fn read_internal(
        &self,
        name: &str,
        app_code: &str,
        url_client_code: &str,
        client_code: &str,
    ) -> ConnResult<Option<Connection>>;
}

/// The checks `ConnectionService.read(name, appCode, clientCode, type)` puts on a resolved
/// connection: the type must match, the connection must be the client's own or app level, and
/// an `onlyThruKIRun` connection is only handed out while a KIRun runtime is running.
pub fn accept_for_read(conn: Connection, client_code: &str, wanted: ConnectionType, in_kirun: bool) -> Option<Connection> {
    if conn.connection_type != Some(wanted) {
        return None;
    }
    if conn.client_code.as_deref() != Some(client_code) && !conn.is_app_level() {
        return None;
    }
    if conn.only_thru_kirun() && !in_kirun {
        return None;
    }
    Some(conn)
}

/// `ConnectionService.read(name, appCode, clientCode, type)`.
pub async fn read(
    store: &dyn ConnectionStore,
    caller: &Caller,
    name: &str,
    app_code: &str,
    client_code: &str,
    wanted: ConnectionType,
) -> ConnResult<Option<Connection>> {
    let url_client_code = caller.url_client_code.as_deref().unwrap_or(client_code);
    let Some(conn) = store.read_internal(name, app_code, url_client_code, client_code).await? else {
        return Ok(None);
    };
    Ok(accept_for_read(conn, client_code, wanted, caller.in_kirun))
}

/// `ConnectionService.readInternalConnection`: the read without access or `onlyThruKIRun`
/// checks (used for OAuth tokens), and for a NOTIFICATION connection every detail value is
/// replaced by the connection it names.
pub async fn read_internal_connection(
    store: &dyn ConnectionStore,
    name: &str,
    app_code: &str,
    client_code: &str,
    wanted: ConnectionType,
) -> ConnResult<Option<Connection>> {
    let Some(conn) = store.read_internal(name, app_code, client_code, client_code).await? else {
        return Ok(None);
    };
    if conn.connection_type != Some(wanted) {
        return Ok(None);
    }
    if conn.client_code.as_deref() != Some(client_code) && !conn.is_app_level() {
        return Ok(None);
    }
    if conn.connection_type != Some(ConnectionType::Notification) {
        return Ok(Some(conn));
    }
    let Some(details) = conn.connection_details.clone().filter(|d| !d.is_empty()) else {
        return Ok(Some(conn));
    };
    let mut expanded = Map::new();
    for (key, value) in details {
        if crate::java::safe_is_blank(Some(&value)) {
            expanded.insert(key, Value::String(String::new()));
            continue;
        }
        let target = crate::java::to_java_string(&value);
        // A name that resolves to nothing drops the key, as the Java `collectMap` does.
        if let Some(c) = store.read_internal(&target, app_code, client_code, client_code).await? {
            let as_json = serde_json::to_value(&c).map_err(|e| ConnError::other(e.to_string()))?;
            expanded.insert(key, as_json);
        }
    }
    let mut copy = conn;
    copy.connection_details = Some(expanded);
    Ok(Some(copy))
}

/// `NotificationConnectionDetails`: whether in-app notifications are on, and the mail
/// connection a notification connection names.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationConnectionDetails {
    pub in_app: bool,
    pub mail: Option<Connection>,
}

/// `ConnectionService.getNotificationConnections` (the `/internal/notification/{name}` route).
pub async fn notification_connections(
    store: &dyn ConnectionStore,
    name: &str,
    app_code: &str,
    url_client_code: &str,
    client_code: &str,
) -> ConnResult<Option<NotificationConnectionDetails>> {
    let Some(n_conn) = store
        .read_internal(name, app_code, url_client_code, client_code)
        .await?
        .filter(|c| c.connection_type == Some(ConnectionType::Notification))
    else {
        return Ok(None);
    };
    let Some(details) = n_conn.connection_details.as_ref().filter(|d| !d.is_empty()) else {
        return Ok(None);
    };
    let mail_name = details.get("mail").filter(|v| !v.is_null()).map(crate::java::to_java_string);
    let in_app = details.contains_key("inapp");
    let Some(mail_name) = mail_name.filter(|m| !m.is_empty()) else {
        return Ok(Some(NotificationConnectionDetails { in_app, mail: None }));
    };
    let mail = store
        .read_internal(&mail_name, app_code, url_client_code, client_code)
        .await?
        .filter(|c| c.connection_type == Some(ConnectionType::Mail));
    Ok(Some(NotificationConnectionDetails { in_app, mail }))
}

/// `ConnectionService.getConnection` (the `/internal/{name}` route).
pub async fn connection_of_type(
    store: &dyn ConnectionStore,
    name: &str,
    app_code: &str,
    url_client_code: &str,
    client_code: &str,
    wanted: ConnectionType,
) -> ConnResult<Option<Connection>> {
    Ok(store
        .read_internal(name, app_code, url_client_code, client_code)
        .await?
        .filter(|c| c.connection_type == Some(wanted)))
}

/// What a credential reads as outside core: a connection read through the editor's routes
/// carries this in place of every secret, and a save that sends it back keeps the stored value.
pub const SECRET_MASK: &str = "********";

/// Detail keys known to hold credentials, compared case-insensitively with the last dotted
/// segment of the key (`mail.password` and `mail__d-o-t__password` are `password`). Taken from
/// the code that opens connections (mail, REST basic and OAuth2, app data, AI, call) and from
/// the stored connections' details.
pub const SECRET_KEYS: [&str; 22] = [
    "password",
    "clientsecret",
    "client_secret",
    "secret",
    "apikey",
    "api_key",
    "apitoken",
    "api_token",
    "accesstoken",
    "access_token",
    "refreshtoken",
    "refresh_token",
    "privatekey",
    "private_key",
    "authtoken",
    "authorization",
    "x-api-key",
    "developer-token",
    "token",
    "key",
    "keysecret",
    "appsecret",
];

/// Name endings that mark a credential key on top of [`SECRET_KEYS`], matched on the key
/// lowercased with everything but letters and digits removed. A key ending in `key` is a
/// credential only with one of these endings: `tokenKey`, `refreshTokenKey` and `expireAtKey`
/// name response fields, not secrets.
const SECRET_KEY_ENDINGS: [&str; 13] = [
    "token",
    "authorization",
    "apikey",
    "secretkey",
    "privatekey",
    "accesskey",
    "authkey",
    "signingkey",
    "encryptionkey",
    "subscriptionkey",
    "licensekey",
    "masterkey",
    "sessionkey",
];

/// Parts that mark a credential key anywhere in its name (same normalisation).
const SECRET_KEY_PARTS: [&str; 5] = ["password", "passwd", "passphrase", "secret", "credential"];

/// Whether a detail key holds a credential: one of [`SECRET_KEYS`], or a name that contains
/// `password`, `passwd`, `passphrase`, `secret` or `credential`, or ends in `token`,
/// `authorization` or one of the `...key` endings in `SECRET_KEY_ENDINGS`.
pub fn is_secret_key(key: &str) -> bool {
    let unescaped = key.replace("__d-o-t__", ".");
    let last = unescaped.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    if SECRET_KEYS.contains(&last.as_str()) {
        return true;
    }
    let plain: String = last.chars().filter(char::is_ascii_alphanumeric).collect();
    !plain.is_empty()
        && (SECRET_KEY_PARTS.iter().any(|p| plain.contains(p)) || SECRET_KEY_ENDINGS.iter().any(|e| plain.ends_with(e)))
}

/// The byte range of the password in a `scheme://user:password@host` address, if it has one.
fn url_password_range(s: &str) -> Option<(usize, usize)> {
    let start = s.find("://")? + 3;
    let authority_end = s[start..].find(['/', '?', '#']).map_or(s.len(), |i| start + i);
    let at = s[start..authority_end].rfind('@')? + start;
    let colon = s[start..at].find(':')? + start;
    (colon + 1 < at).then_some((colon + 1, at))
}

/// The address with the password of its user part masked (`mysql://app:********@db/x`), or
/// `None` when it carries no password.
pub fn mask_url_password(s: &str) -> Option<String> {
    let (from, to) = url_password_range(s)?;
    (&s[from..to] != SECRET_MASK).then(|| format!("{}{SECRET_MASK}{}", &s[..from], &s[to..]))
}

/// `incoming` with the stored password back in place of a masked one, or `None` when
/// `incoming` carries no masked password or `stored` has none to give.
pub fn restore_url_password(incoming: &str, stored: &str) -> Option<String> {
    let (from, to) = url_password_range(incoming)?;
    if &incoming[from..to] != SECRET_MASK {
        return None;
    }
    let (sf, st) = url_password_range(stored)?;
    Some(format!("{}{}{}", &incoming[..from], &stored[sf..st], &incoming[to..]))
}

/// `ConnectionService.withoutSecrets`: the details with every credential ([`is_secret_key`])
/// removed, nested maps included (lists are left as they are, as in Java).
pub fn without_secrets(details: &Map<String, Value>) -> Map<String, Value> {
    let mut out = Map::new();
    for (k, v) in details {
        if is_secret_key(k) {
            continue;
        }
        let v = match v {
            Value::Object(m) => Value::Object(without_secrets(m)),
            other => other.clone(),
        };
        out.insert(k.clone(), v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn conn(v: Value) -> Connection {
        Connection::from_json(v).unwrap()
    }

    #[test]
    fn reads_a_stored_document() {
        let c = conn(json!({
            "_id": "65f0", "name": "META_API", "appCode": "marketingai", "clientCode": "SYSTEM",
            "connectionType": "REST_API", "connectionSubType": "REST_API_OAUTH2",
            "connectionDetails": {"baseUrl": "https://graph.facebook.com/v21.0", "isLifeTimeToken": true},
            "isAppLevel": true, "onlyThruKIRun": false, "version": 3
        }));
        assert_eq!(c.connection_type, Some(ConnectionType::RestApi));
        assert_eq!(c.connection_sub_type, Some(ConnectionSubType::RestApiOAuth2));
        assert!(c.is_app_level());
        assert_eq!(c.other.get("version"), Some(&json!(3)));
        assert_eq!(serde_json::to_value(&c).unwrap()["onlyThruKIRun"], json!(false));
        assert_eq!(c.consent_auth, None);
        assert!(serde_json::to_value(&c).unwrap().get("consentAuth").is_none(), "absent stays absent");
    }

    #[test]
    fn reads_the_consent_gate() {
        let c = conn(json!({"name": "META_API", "consentAuth": "Authorities.ROLE_Owner"}));
        assert_eq!(c.consent_auth.as_deref(), Some("Authorities.ROLE_Owner"));
        assert!(!c.other.contains_key("consentAuth"));
        assert_eq!(serde_json::to_value(&c).unwrap()["consentAuth"], json!("Authorities.ROLE_Owner"));
    }

    #[test]
    fn unknown_enum_constant_is_an_error() {
        assert!(Connection::from_json(json!({"connectionType": "FAX"})).is_err());
    }

    #[test]
    fn read_rules() {
        let base = json!({"name": "c", "clientCode": "SYSTEM", "connectionType": "REST_API"});
        assert!(accept_for_read(conn(base.clone()), "SYSTEM", ConnectionType::RestApi, false).is_some());
        assert!(accept_for_read(conn(base.clone()), "SYSTEM", ConnectionType::Mail, false).is_none());
        // Another client's connection only when it is app level.
        assert!(accept_for_read(conn(base.clone()), "FIN", ConnectionType::RestApi, false).is_none());
        let mut app_level = base.clone();
        app_level["isAppLevel"] = json!(true);
        assert!(accept_for_read(conn(app_level), "FIN", ConnectionType::RestApi, false).is_some());
        let mut kirun_only = base;
        kirun_only["onlyThruKIRun"] = json!(true);
        assert!(accept_for_read(conn(kirun_only.clone()), "SYSTEM", ConnectionType::RestApi, false).is_none());
        assert!(accept_for_read(conn(kirun_only), "SYSTEM", ConnectionType::RestApi, true).is_some());
    }

    #[test]
    fn sub_types_per_type() {
        assert!(ConnectionType::Ai.has_sub_type(ConnectionSubType::DeepSeek));
        assert!(!ConnectionType::Notification.has_sub_type(ConnectionSubType::Smtp));
        assert_eq!(ConnectionType::value_of("APP_DATA"), Some(ConnectionType::AppData));
        assert_eq!(ConnectionType::value_of("app_data"), None);
    }

    /// `ConnectionSecretsTest.stripsCredentials`: the same details and expectations.
    #[test]
    fn strips_credentials() {
        let details = json!({
            "baseUrl": "https://example.com/",
            "userName": "kiran",
            "password": "p",
            "defaultHeaders": {"appCode": "appbuilder", "Authorization": "Bearer x"},
            "oauth": {"clientId": "id", "clientSecret": "s", "tokenUrl": "https://example.com/token"},
            "API_KEY": "k"
        });
        let details = details.as_object().unwrap();
        let out = without_secrets(details);
        assert_eq!(out["baseUrl"], "https://example.com/");
        assert_eq!(out["userName"], "kiran");
        assert!(!out.contains_key("password"));
        assert!(!out.contains_key("API_KEY"));
        assert_eq!(out["defaultHeaders"], json!({"appCode": "appbuilder"}));
        let o = out["oauth"].as_object().unwrap();
        assert!(o.contains_key("tokenUrl"), "a token URL is an address, not a secret");
        assert!(!o.contains_key("clientSecret"));
        assert!(details.contains_key("password"), "the stored connection is never touched");
    }

    #[test]
    fn the_secret_key_rule() {
        for k in [
            "password", "Password", "mail.password", "mail__d-o-t__smtp__d-o-t__password", "clientSecret", "client_secret",
            "apiKey", "API_KEY", "x-api-key", "apiToken", "accessToken", "refresh_token", "developer-token", "Authorization",
            "Proxy-Authorization", "privateKey", "keySecret", "webhookSecret", "appSecret", "secretAccessKey", "key",
            "subscriptionKey", "Ocp-Apim-Subscription-Key", "X-Auth-Token", "bearerToken", "token", "dbPasswd", "credentials",
        ] {
            assert!(is_secret_key(k), "{k} is a credential");
        }
        for k in [
            "userName", "username", "mail.smtp.host", "mail.smtp.auth", "baseUrl", "tokenUrl", "tokenKey", "refreshTokenKey",
            "expireAtKey", "refreshExpireAtKey", "tokenDetails", "tokenConnection", "authTokenFunctionName", "headerPrefix",
            "authHeaderPrefix", "autherization", "client_id", "clientId", "accountSid", "callerId", "metaAppId", "grantType",
            "keyId", "fromAddress", "url", "useDefaultConnection", "",
        ] {
            assert!(!is_secret_key(k), "{k} is not a credential");
        }
    }

    #[test]
    fn url_passwords_are_masked_and_restored() {
        assert_eq!(mask_url_password("mysql://app:pw@db.example.com:3306/x").as_deref(), Some("mysql://app:********@db.example.com:3306/x"));
        assert_eq!(mask_url_password("mongodb://u:p%40ss@h1,h2/db?x=1").as_deref(), Some("mongodb://u:********@h1,h2/db?x=1"));
        assert_eq!(mask_url_password("https://example.com/a@b"), None, "an @ after the host is no user part");
        assert_eq!(mask_url_password("mysql://app@db/x"), None);
        assert_eq!(mask_url_password("mysql://app:@db/x"), None);
        assert_eq!(mask_url_password("plain text"), None);
        assert_eq!(mask_url_password("mysql://app:********@db/x"), None, "already masked");
        let stored = "mysql://app:pw@db/x";
        assert_eq!(restore_url_password("mysql://app:********@db2/y", stored).as_deref(), Some("mysql://app:pw@db2/y"));
        assert_eq!(restore_url_password("mysql://app:new@db/x", stored), None, "a new password is taken as sent");
        assert_eq!(restore_url_password("mysql://app:********@db/x", "mysql://db/x"), None);
    }

    #[test]
    fn secrets_are_removed_at_depth() {
        let d = json!({"baseUrl": "x", "Password": "p", "tokenDetails": {"client_secret": "s", "url": "u"}, "list": [{"apiKey": 1}]});
        let out = without_secrets(d.as_object().unwrap());
        assert_eq!(Value::Object(out), json!({"baseUrl": "x", "tokenDetails": {"url": "u"}, "list": [{"apiKey": 1}]}));
    }
}
