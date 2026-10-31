//! notification's configuration: its MySQL schema, where security and core are, the RabbitMQ
//! queues it consumes, the SSE heartbeat, and the platform's push credentials.

use platform::config::{
    RegistryConfig, MySqlConfig, RedisConfig, SecurityConfig, ServerConfig, TelemetryConfig, UpstreamConfig,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationConfig {
    pub server: ServerConfig,
    pub telemetry: TelemetryConfig,
    pub registry: RegistryConfig,
    /// The caller's context, recipients (`users/internal/notification`) and the user checks of
    /// the preference routes.
    pub security: SecurityConfig,
    /// Publishes the `notificationPreference` eviction Java's preference writes publish, and
    /// carries the pushes to every instance's streams (`[sse] push_channel`).
    pub redis: RedisConfig,
    /// The `notification` schema (`notification_inapp`, `notification_preference`).
    pub database: MySqlConfig,
    pub core: CoreSection,
    pub mq: MqSection,
    pub notifications: QueueSection,
    pub email: EmailSection,
    pub sse: SseSection,
    pub push: PushSection,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig { port: 8114, ..Default::default() },
            telemetry: TelemetryConfig::default(),
            registry: RegistryConfig::default(),
            security: SecurityConfig::default(),
            redis: RedisConfig::default(),
            database: MySqlConfig { database: "notification".into(), max_connections: 4, ..Default::default() },
            core: CoreSection::default(),
            mq: MqSection::default(),
            notifications: QueueSection::default(),
            email: EmailSection::default(),
            sse: SseSection::default(),
            push: PushSection::default(),
        }
    }
}

/// `IFeignCoreService`: where the notification and connection definitions are read.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CoreSection {
    /// Base URL(s) or `lighthouse:CORE`, for `/api/core/notifications/internal/{name}` (and for the
    /// connection read too when `connections_upstream` is empty). Java core serves both reads;
    /// of the Rust units, core-editor serves this one.
    pub upstream: UpstreamConfig,
    /// Where `/api/core/connections/internal/notification/{name}` goes when it is not
    /// `upstream` (core-exec serves it among the Rust units).
    pub connections_upstream: UpstreamConfig,
    /// Feign's `readTimeout` (`spring.cloud.openfeign.client.config.default.readTimeout`).
    pub timeout_seconds: u64,
}

impl Default for CoreSection {
    fn default() -> Self {
        Self { upstream: UpstreamConfig::default(), connections_upstream: UpstreamConfig::default(), timeout_seconds: 60 }
    }
}

/// The broker (`spring.rabbitmq.*`).
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MqSection {
    /// Off: nothing is consumed (an HTTP-only instance).
    pub enabled: bool,
    /// `amqp://user:password@host:port/vhost`; built from the parts below when not set.
    pub uri: Option<String>,
    pub host: Option<String>,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub virtual_host: String,
}

impl Default for MqSection {
    fn default() -> Self {
        Self {
            enabled: true,
            uri: None,
            host: None,
            port: 5672,
            username: None,
            password: None,
            virtual_host: "/".into(),
        }
    }
}

impl std::fmt::Debug for MqSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MqSection")
            .field("enabled", &self.enabled)
            .field("uri", &self.uri.as_ref().map(|_| "<hidden>"))
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<hidden>"))
            .field("virtual_host", &self.virtual_host)
            .finish()
    }
}

impl MqSection {
    /// The AMQP URI: `uri` when set, else one built from the parts; `None` without a host.
    pub fn amqp_uri(&self) -> Option<String> {
        if let Some(u) = self.uri.as_ref().filter(|u| !u.is_empty()) {
            return Some(u.clone());
        }
        let host = self.host.as_ref().filter(|h| !h.is_empty())?;
        let enc = |s: &str| percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string();
        let auth = match (&self.username, &self.password) {
            (Some(u), Some(p)) => format!("{}:{}@", enc(u), enc(p)),
            (Some(u), None) => format!("{}@", enc(u)),
            _ => String::new(),
        };
        Some(format!("amqp://{auth}{host}:{}/{}", self.port, enc(&self.virtual_host)))
    }
}

/// `notifications.mq.queues` and how they are consumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct QueueSection {
    /// Comma-separated, as Java's property (`notifications1,notifications2,notifications3`).
    pub queues: String,
    /// Deliveries buffered per queue. Java's is unbounded (`prefetchCount(0)`); each queue is
    /// still worked one message at a time, as Java's one consumer per queue does.
    pub prefetch: u16,
    /// Declare `exchange` (direct) and the queues, each bound under its own name. Only for
    /// scratch setups: the real queues already exist and are not declared by Java either.
    pub declare: bool,
    /// The exchange `declare` creates and binds to.
    pub exchange: String,
}

impl Default for QueueSection {
    fn default() -> Self {
        Self {
            queues: "notifications1,notifications2,notifications3".into(),
            prefetch: 10,
            declare: false,
            exchange: "notifications".into(),
        }
    }
}

impl QueueSection {
    /// The queue names, trimmed, empty names left out.
    pub fn names(&self) -> Vec<String> {
        self.queues.split(',').map(str::trim).filter(|q| !q.is_empty()).map(str::to_string).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailSection {
    /// Where SendGrid mail is posted (Java: the fixed `https://api.sendgrid.com/v3/mail/send`).
    /// Only tests point it elsewhere.
    pub sendgrid_url: String,
    /// An SMTP host must resolve only to public addresses (core's `blockPrivateTargets`).
    pub block_private_targets: bool,
}

impl Default for EmailSection {
    fn default() -> Self {
        Self { sendgrid_url: "https://api.sendgrid.com/v3/mail/send".into(), block_private_targets: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SseSection {
    /// `@Scheduled(fixedRate = 15000)`: the keepalive comment sent to every open stream.
    pub heartbeat_seconds: u64,
    /// Events held for a stream that is not reading; a stream that falls this far behind is
    /// dropped (Java blocks the sending thread on it instead).
    pub buffer: usize,
    /// The Redis channel frames reach every instance's streams on (with `[redis] url`). Like
    /// `evictionChannel`, it carries no cache prefix.
    pub push_channel: String,
}

impl Default for SseSection {
    fn default() -> Self {
        Self { heartbeat_seconds: 15, buffer: 256, push_channel: "notificationPush".into() }
    }
}

/// The platform's push credentials (Rust only). A client's own FCM or APNs keys come from the
/// PUSH connection its NOTIFICATION connection names instead; Web Push always uses these.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PushSection {
    /// VAPID public key: the uncompressed P-256 point, base64url (what browsers subscribe with).
    pub vapid_public_key: String,
    /// VAPID private key: the 32-byte P-256 scalar, base64url.
    pub vapid_private_key: String,
    /// The contact push services see in the VAPID token (`mailto:` or `https:`).
    pub vapid_subject: String,
    /// The service account JSON of the platform's Firebase project (FCM, Android).
    pub fcm_credentials: String,
    /// The platform Apple team's APNs token key: the `.p8` PEM, or base64 of it (iOS).
    pub apns_private_key: String,
    pub apns_key_id: String,
    pub apns_team_id: String,
    /// How long an app's "has notifications" answer from core is kept.
    pub app_check_seconds: u64,
    /// Per request to FCM, APNs or a Web Push service.
    pub timeout_seconds: u64,
}

impl Default for PushSection {
    fn default() -> Self {
        Self {
            vapid_public_key: String::new(),
            vapid_private_key: String::new(),
            vapid_subject: "mailto:support@modlix.com".into(),
            fcm_credentials: String::new(),
            apns_private_key: String::new(),
            apns_key_id: String::new(),
            apns_team_id: String::new(),
            app_check_seconds: 600,
            timeout_seconds: 15,
        }
    }
}

impl std::fmt::Debug for PushSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hidden = |s: &str| if s.is_empty() { "" } else { "<hidden>" };
        f.debug_struct("PushSection")
            .field("vapid_public_key", &self.vapid_public_key)
            .field("vapid_private_key", &hidden(&self.vapid_private_key))
            .field("vapid_subject", &self.vapid_subject)
            .field("fcm_credentials", &hidden(&self.fcm_credentials))
            .field("apns_private_key", &hidden(&self.apns_private_key))
            .field("apns_key_id", &self.apns_key_id)
            .field("apns_team_id", &self.apns_team_id)
            .field("app_check_seconds", &self.app_check_seconds)
            .field("timeout_seconds", &self.timeout_seconds)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_uri() {
        let c = NotificationConfig::default();
        assert_eq!(c.server.port, 8114);
        assert_eq!(c.database.database, "notification");
        assert_eq!(c.notifications.names(), ["notifications1", "notifications2", "notifications3"]);
        assert_eq!(c.sse.heartbeat_seconds, 15);
        assert_eq!(c.sse.push_channel, "notificationPush");
        assert_eq!(c.core.timeout_seconds, 60);
        assert_eq!(c.email.sendgrid_url, "https://api.sendgrid.com/v3/mail/send");
        assert!(c.email.block_private_targets);

        let mut mq = MqSection::default();
        assert_eq!(mq.amqp_uri(), None);
        mq.host = Some("rabbit".into());
        assert_eq!(mq.amqp_uri().unwrap(), "amqp://rabbit:5672/%2F");
        mq.username = Some("u".into());
        assert_eq!(mq.amqp_uri().unwrap(), "amqp://u@rabbit:5672/%2F");
        mq.password = Some("p@ss".into());
        assert_eq!(mq.amqp_uri().unwrap(), "amqp://u:p%40ss@rabbit:5672/%2F");
        let shown = format!("{mq:?}");
        assert!(!shown.contains("p@ss") && shown.contains("<hidden>"));
        mq.uri = Some("amqp://x".into());
        assert_eq!(mq.amqp_uri().unwrap(), "amqp://x");

        let push = PushSection { vapid_private_key: "secret-scalar".into(), fcm_credentials: "{}".into(), ..Default::default() };
        let shown = format!("{push:?}");
        assert!(!shown.contains("secret-scalar") && shown.contains("<hidden>"));
        assert_eq!(push.app_check_seconds, 600);

        let q = QueueSection { queues: " a, ,b ".into(), ..Default::default() };
        assert_eq!(q.names(), ["a", "b"]);
    }
}
