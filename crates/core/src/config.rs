//! core-exec configuration: `config/core-exec.toml`; secrets (`MODLIX__DATABASE__PASSWORD`,
//! `MODLIX__REDIS__URL`, a credentialed `MODLIX__MONGO__URI`) from the environment.

use platform::config::{
    EurekaConfig, MongoConfig, MySqlConfig, RedisConfig, SecurityConfig, ServerConfig, TelemetryConfig, UpstreamConfig,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CoreConfig {
    pub server: ServerConfig,
    pub telemetry: TelemetryConfig,
    pub eureka: EurekaConfig,
    pub redis: RedisConfig,
    pub security: SecurityConfig,
    /// The `core` Mongo database (`core.mongo.uri` of the Java service).
    pub mongo: MongoConfig,
    /// The `core` MySQL database (`core.db.url`): `core_remote_repositories` and, later, the
    /// rest of core's tables.
    pub database: MySqlConfig,
    pub entity_processor: EntityProcessorConfig,
    /// The message service, for `CoreServices.Message.*` (Feign name `message`).
    pub message: MessageConfig,
    /// The files service, for `CoreServices.File.*` and REST downloads (Feign name `files`).
    pub files: FilesConfig,
    /// The ui service, for `CoreServices.Platform.CleanupTransports` (Feign name `ui`).
    pub ui: UiConfig,
    pub core: CoreSection,
    /// The storage policy layer and the app-data engines under it.
    pub appdata: AppDataSection,
    /// Outbound connections (`core.rest.*`, the provider endpoints).
    pub connections: ConnectionsSection,
    /// RabbitMQ (`spring.rabbitmq.*`, `events.mq.*`, `notification.mq.*`).
    pub mq: MqSection,
    /// The events consumer of core-events (`events.mq.queues`).
    pub events: EventsSection,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig { port: 8105, ..Default::default() },
            telemetry: TelemetryConfig::default(),
            eureka: EurekaConfig::default(),
            redis: RedisConfig { cache_prefix: "cmn".into(), ..Default::default() },
            security: SecurityConfig::default(),
            mongo: MongoConfig { database: "core".into(), ..Default::default() },
            database: MySqlConfig { database: "core".into(), ..Default::default() },
            entity_processor: EntityProcessorConfig::default(),
            message: MessageConfig::default(),
            files: FilesConfig::default(),
            ui: UiConfig::default(),
            core: CoreSection::default(),
            appdata: AppDataSection::default(),
            connections: ConnectionsSection::default(),
            mq: MqSection::default(),
            events: EventsSection::default(),
        }
    }
}

/// `events.mq.queues` and how core-events consumes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EventsSection {
    /// Comma-separated, as Java's property.
    pub queues: String,
    /// Deliveries in flight on the consumer's channel (Java's is unbounded).
    pub prefetch: u16,
    /// Declare `mq.events_exchange` (direct, durable) and the queues, each bound under its own
    /// name. Only for scratch setups: the real queues already exist.
    pub declare: bool,
}

impl Default for EventsSection {
    fn default() -> Self {
        Self { queues: "events1,events2,events3".into(), prefetch: 16, declare: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionsSection {
    /// `core.rest.blockPrivateTargets`: REST connections may not reach private addresses.
    pub block_private_targets: bool,
    /// Where SendGrid mail is posted (fixed in Java).
    pub sendgrid_url: String,
    /// The OpenAI API base (the SDK's default in Java).
    pub openai_base_url: String,
}

impl Default for ConnectionsSection {
    fn default() -> Self {
        let d = connections::ConnectionsConfig::default();
        Self { block_private_targets: d.block_private_targets, sendgrid_url: d.sendgrid_url, openai_base_url: d.openai_base_url }
    }
}

/// The broker and the two exchanges. The URI (or the password) comes from the environment
/// (`MODLIX__MQ__URI`, `MODLIX__MQ__PASSWORD`) and is never logged: `Debug` hides both.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MqSection {
    /// Off: events and notifications are dropped (logged) instead of published.
    pub enabled: bool,
    /// `amqp://user:password@host:port/vhost`; built from the parts below when not set.
    pub uri: Option<String>,
    pub host: Option<String>,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub virtual_host: String,
    /// `events.mq.exchange` / `events.mq.routingkeys`.
    pub events_exchange: String,
    pub events_routing_keys: String,
    /// `notification.mq.exchange` / `notification.mq.routingkeys`.
    pub notifications_exchange: String,
    pub notifications_routing_keys: String,
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
            events_exchange: "events".into(),
            events_routing_keys: "events1,events2,events3".into(),
            notifications_exchange: "notifications".into(),
            notifications_routing_keys: "notifications1,notifications2,notifications3".into(),
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
            .field("events_exchange", &self.events_exchange)
            .field("events_routing_keys", &self.events_routing_keys)
            .field("notifications_exchange", &self.notifications_exchange)
            .field("notifications_routing_keys", &self.notifications_routing_keys)
            .finish()
    }
}

impl MqSection {
    /// The broker's URI: `uri` as given, or one built from host, port, user, password and
    /// virtual host (Spring's `spring.rabbitmq.*`). `None` when no broker is configured.
    pub fn amqp_uri(&self) -> Option<String> {
        if let Some(u) = self.uri.as_ref().filter(|u| !u.trim().is_empty()) {
            return Some(u.clone());
        }
        let host = self.host.as_ref().filter(|h| !h.trim().is_empty())?;
        let enc = |s: &str| percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string();
        let auth = match (&self.username, &self.password) {
            (Some(u), Some(p)) => format!("{}:{}@", enc(u), enc(p)),
            (Some(u), None) => format!("{}@", enc(u)),
            _ => String::new(),
        };
        Some(format!("amqp://{auth}{host}:{}/{}", self.port, enc(&self.virtual_host)))
    }
}

/// Where entity-processor is, for the remote function and schema repositories of the apps
/// listed in `core_remote_repositories` (Feign name `entity-processor`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EntityProcessorConfig {
    pub upstream: UpstreamConfig,
}

impl Default for EntityProcessorConfig {
    fn default() -> Self {
        Self { upstream: UpstreamConfig::One("eureka:ENTITY-PROCESSOR".into()) }
    }
}

/// Where the message service is (`IFeignMessageService`, Feign name `message`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MessageConfig {
    pub upstream: UpstreamConfig,
}

impl Default for MessageConfig {
    fn default() -> Self {
        Self { upstream: UpstreamConfig::One("eureka:MESSAGE".into()) }
    }
}

/// Where the files service is (`IFeignFilesService`, Feign name `files`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FilesConfig {
    pub upstream: UpstreamConfig,
}

impl Default for FilesConfig {
    fn default() -> Self {
        Self { upstream: UpstreamConfig::One("eureka:FILES".into()) }
    }
}

/// Where the ui service is (the worker's `IFeignUIService`, Feign name `ui`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UiConfig {
    pub upstream: UpstreamConfig,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self { upstream: UpstreamConfig::One("eureka:UI".into()) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CoreSection {
    /// `DefinitionFunction`'s timeout: five minutes in Java.
    pub function_timeout_seconds: u64,
    /// The offset of the zone the Java core's JVM runs in (see the ui unit): stored dates are
    /// written shifted by it.
    pub java_zone_offset: String,
    /// `core.scheduler.*` (`[core.scheduler]`, `[core.scheduler.oneoff]`).
    pub scheduler: crate::scheduler::EventSchedulerSettings,
    /// Where the core service's internal routes are (the worker's `IFeignCoreService`, Feign
    /// name `core`): billing meter and reconcile, transport and event-run cleanup, events
    /// raise, which `CoreServices.Platform.*` call.
    pub upstream: UpstreamConfig,
    /// `core.eventRuns.*` (`[core.event_runs]`): `enabled`, true by default.
    pub event_runs: crate::event_runs::EventRunsSettings,
}

impl Default for CoreSection {
    fn default() -> Self {
        Self {
            function_timeout_seconds: 300,
            java_zone_offset: "+00:00".into(),
            scheduler: crate::scheduler::EventSchedulerSettings::default(),
            upstream: UpstreamConfig::One("eureka:CORE".into()),
            event_runs: crate::event_runs::EventRunsSettings::default(),
        }
    }
}

/// `core.storage.*` and `core.appdata.*` of the Java service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppDataSection {
    /// `core.storage.onlyThruKIRun.builderAppCodes`: the apps whose sessions may reach an
    /// `onlyThruKIRun` storage over the data API.
    pub builder_app_codes: Vec<String>,
    /// `spring.r2dbc.url` for `useDefaultConnection` MySQL apps; the `database` section's
    /// server and credentials when not set.
    pub mysql_url: Option<String>,
    /// `core.appdata.mysql.textSearch.stemming`.
    pub text_search_stemming: bool,
    /// `core.appdata.versionRetention.days` / `.count`: the history kept for a storage that
    /// declares none. Unset is 90 days / 50 versions; `0` is unlimited (0/0 keeps everything),
    /// as `VersionRetentionDefaults` reads them.
    pub version_retention_days: i32,
    pub version_retention_count: i32,
}

impl AppDataSection {
    /// `VersionRetentionDefaults.get()`: the configured pair, clamped at 0.
    pub fn version_retention(&self) -> appdata::retention::VersionRetention {
        appdata::retention::VersionRetention::clamped(self.version_retention_days, self.version_retention_count)
    }
}

impl Default for AppDataSection {
    fn default() -> Self {
        Self {
            builder_app_codes: vec!["appbuilder".into(), "sitezump".into()],
            mysql_url: None,
            text_search_stemming: true,
            version_retention_days: appdata::retention::DEFAULT_DAYS,
            version_retention_count: appdata::retention::DEFAULT_COUNT,
        }
    }
}

impl CoreSection {
    /// `+05:30` as seconds east of UTC.
    pub fn zone_offset_seconds(&self) -> anyhow::Result<i32> {
        let s = self.java_zone_offset.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("z") {
            return Ok(0);
        }
        let (sign, rest) = match s.as_bytes()[0] {
            b'+' => (1, &s[1..]),
            b'-' => (-1, &s[1..]),
            _ => (1, s),
        };
        let (h, m) = rest.split_once(':').unwrap_or((rest, "0"));
        Ok(sign * (h.parse::<i32>()? * 3600 + m.parse::<i32>()? * 60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `VersionRetentionPropertyBindingTest`: unset is the compiled 90 / 50, a configured pair
    /// replaces both, and 0/0 keeps everything (a storage declaring nothing is not trimmed).
    #[test]
    fn version_retention_binds_as_java_binds_it() {
        let unset: AppDataSection = toml::from_str("").unwrap();
        let r = unset.version_retention();
        assert_eq!((r.days, r.count), (appdata::retention::DEFAULT_DAYS, appdata::retention::DEFAULT_COUNT));
        let set: AppDataSection = toml::from_str("version_retention_days = 14\nversion_retention_count = 5").unwrap();
        let r = set.version_retention();
        assert_eq!((r.days, r.count), (14, 5));
        let off: AppDataSection = toml::from_str("version_retention_days = 0\nversion_retention_count = 0").unwrap();
        assert!(off.version_retention().keeps_everything(), "0/0 must switch trimming off");
        let storage = appdata::model::Storage::from_value(&appdata::value::Value::from_json(&serde_json::json!({"name": "s"}))).unwrap();
        assert!(appdata::retention::VersionRetention::for_storage(&storage, off.version_retention()).keeps_everything());
        let negative: AppDataSection = toml::from_str("version_retention_days = -3").unwrap();
        assert_eq!(negative.version_retention().days, 0, "a negative bound reads as unlimited");
    }

    #[test]
    fn zone_offsets() {
        let mut c = CoreSection::default();
        assert_eq!(c.zone_offset_seconds().unwrap(), 0);
        c.java_zone_offset = "+05:30".into();
        assert_eq!(c.zone_offset_seconds().unwrap(), 19_800);
        c.java_zone_offset = "-03:00".into();
        assert_eq!(c.zone_offset_seconds().unwrap(), -10_800);
        c.java_zone_offset = "Z".into();
        assert_eq!(c.zone_offset_seconds().unwrap(), 0);
        c.java_zone_offset = "02".into();
        assert_eq!(c.zone_offset_seconds().unwrap(), 7_200);
        c.java_zone_offset = "+aa:00".into();
        assert!(c.zone_offset_seconds().is_err());
    }

    #[test]
    fn the_local_files_of_the_scheduler_and_the_consumer_stay_on_scratch() {
        let read = |f: &str| -> CoreConfig {
            let text = std::fs::read_to_string(format!("{}/../../config/{f}", env!("CARGO_MANIFEST_DIR"))).unwrap();
            toml::from_str(&text).unwrap()
        };
        let s = read("core-scheduler.toml");
        assert_eq!((s.server.port, s.core.scheduler.enabled, s.mq.events_exchange.as_str()), (8108, false, "rs_scratch_events"));
        let e = read("core-events.toml");
        assert_eq!((e.server.port, e.mq.events_exchange.as_str(), e.events.declare), (8109, "rs_scratch_events", true));
        assert!(e.events.queues.split(',').all(|q| q.starts_with("rs_scratch_")));
    }

    #[test]
    fn defaults() {
        let c = CoreConfig::default();
        assert_eq!(c.server.port, 8105);
        assert_eq!((c.events.queues.as_str(), c.events.prefetch, c.events.declare), ("events1,events2,events3", 16, false));
        assert_eq!((c.core.scheduler.tick_ms, c.core.scheduler.initial_delay_ms), (30_000, 30_000));
        assert!(c.core.event_runs.enabled);
        assert_eq!(c.redis.cache_prefix, "cmn");
        assert_eq!(c.mongo.database, "core");
        assert_eq!(c.database.database, "core");
        assert_eq!(c.entity_processor.upstream.entries(), ["eureka:ENTITY-PROCESSOR"]);
        assert_eq!(c.message.upstream.entries(), ["eureka:MESSAGE"]);
        assert_eq!(c.files.upstream.entries(), ["eureka:FILES"]);
        assert_eq!(c.ui.upstream.entries(), ["eureka:UI"]);
        assert_eq!(c.core.upstream.entries(), ["eureka:CORE"]);
        assert_eq!(c.core.function_timeout_seconds, 300);
        assert_eq!(c.appdata.builder_app_codes, ["appbuilder", "sitezump"]);
        assert!(c.appdata.text_search_stemming);
        assert!(c.connections.block_private_targets);
        assert_eq!(c.mq.events_exchange, "events");
        assert_eq!(c.mq.notifications_routing_keys, "notifications1,notifications2,notifications3");
    }

    #[test]
    fn the_platform_upstreams_are_read_like_the_others() {
        // `[core] upstream = "a, b"` and `[ui] upstream = ["..."]`, as the configuration loader
        // hands them over; the rest of each section keeps its defaults.
        let c: CoreConfig = serde_json::from_value(serde_json::json!({
            "core": {"upstream": "http://core-a:8005, http://core-b:8005"},
            "ui": {"upstream": ["http://ui:8002"]}
        }))
        .unwrap();
        assert_eq!(c.core.upstream.entries(), ["http://core-a:8005", "http://core-b:8005"]);
        assert_eq!(c.ui.upstream.entries(), ["http://ui:8002"]);
        assert_eq!(c.core.function_timeout_seconds, 300);
        assert_eq!(c.files.upstream.entries(), ["eureka:FILES"]);
        let d: CoreConfig = serde_json::from_value(serde_json::json!({"core": {"function_timeout_seconds": 5}})).unwrap();
        assert_eq!((d.core.upstream.entries(), d.ui.upstream.entries()), (vec!["eureka:CORE".to_string()], vec!["eureka:UI".to_string()]));
    }

    #[test]
    fn the_broker_uri_is_built_and_never_shown() {
        let mut m = MqSection::default();
        assert_eq!(m.amqp_uri(), None);
        m.host = Some("localhost".into());
        assert_eq!(m.amqp_uri().unwrap(), "amqp://localhost:5672/%2F");
        m.username = Some("guest".into());
        assert_eq!(m.amqp_uri().unwrap(), "amqp://guest@localhost:5672/%2F");
        m.password = Some("p@ss".into());
        assert_eq!(m.amqp_uri().unwrap(), "amqp://guest:p%40ss@localhost:5672/%2F");
        m.uri = Some("amqp://u:secret@h:1/v".into());
        assert_eq!(m.amqp_uri().unwrap(), "amqp://u:secret@h:1/v");
        let shown = format!("{m:?}");
        assert!(!shown.contains("secret") && !shown.contains("p@ss"), "{shown}");
        assert!(shown.contains("<hidden>"));
    }
}
