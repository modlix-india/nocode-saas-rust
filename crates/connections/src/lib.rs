//! core's outbound integrations, as a library the core service calls: the connection
//! documents, REST calls behind the private-target guard, email, AI chat, and the RabbitMQ
//! event and notification publishers.
//!
//! Each module ports one area of `commons-core` (and `commons-mq`); the KIRun function wrappers
//! and HTTP routes live in the core crate and call into these. What the core crate supplies
//! (connection and template reads through `crates/overridable`, KIRun execution for auth-token
//! functions, the security service's hierarchy checks) comes in through the traits in
//! [`connection`], [`rest::auth`], [`email`] and [`notification`].

pub mod ai;
pub mod catalogue;
pub mod connection;
pub mod context;
pub mod controller;
pub mod email;
pub mod error;
pub mod java;
pub mod mq;
pub mod notification;
pub mod outbound;
pub mod rest;
pub mod template;
pub mod tokens;

use std::sync::Arc;

use chrono::NaiveDateTime;
use platform::cache::{CacheService, LocalCaches};

use crate::connection::ConnectionStore;
use crate::context::{AuthorityCheck, NoEvaluator};
use crate::rest::auth::AuthTokenFunction;
use crate::rest::http::HttpClient;
use crate::tokens::{CoreToken, JavaClock, TokenStore};

/// Settings the Java services read from their configuration.
#[derive(Debug, Clone)]
pub struct ConnectionsConfig {
    /// `core.rest.blockPrivateTargets` (default true).
    pub block_private_targets: bool,
    /// The offset of the Java core's JVM zone: `core_tokens` holds its wall clock.
    pub java_zone_offset_seconds: i32,
    /// Where SendGrid mail is posted (Java: the fixed `https://api.sendgrid.com/v3/mail/send`).
    pub sendgrid_url: String,
    /// The OpenAI API base (Java: the SDK's default `https://api.openai.com/v1`).
    pub openai_base_url: String,
}

impl Default for ConnectionsConfig {
    fn default() -> Self {
        Self {
            block_private_targets: true,
            java_zone_offset_seconds: 0,
            sendgrid_url: "https://api.sendgrid.com/v3/mail/send".into(),
            openai_base_url: "https://api.openai.com/v1".into(),
        }
    }
}

/// The cached auth-function token: `Tuple2<String, LocalDateTime>`.
pub type AuthTokenTuple = (Option<String>, Option<NaiveDateTime>);

/// Everything the connection services share.
pub struct Connections {
    pub config: ConnectionsConfig,
    pub store: Arc<dyn ConnectionStore>,
    pub tokens: Arc<dyn TokenStore>,
    pub cache: CacheService,
    pub auth_functions: Arc<dyn AuthTokenFunction>,
    /// Outbound REST calls, guarded as `core.rest.blockPrivateTargets` says.
    pub http: HttpClient,
    /// The fixed provider endpoints (SendGrid, OpenAI), which Java does not guard.
    pub provider_http: HttpClient,
    pub clock: JavaClock,
    /// Evaluates a connection's `consentAuth`. [`NoEvaluator`] until
    /// [`Connections::with_authority_check`] supplies one, so an unset check refuses every
    /// non-blank expression.
    pub authority_check: Arc<dyn AuthorityCheck>,
    pub(crate) oauth_cache: Arc<LocalCaches<String, CoreToken>>,
    pub(crate) auth_cache: Arc<LocalCaches<String, AuthTokenTuple>>,
}

impl Connections {
    pub fn new(
        config: ConnectionsConfig,
        store: Arc<dyn ConnectionStore>,
        tokens: Arc<dyn TokenStore>,
        cache: CacheService,
        auth_functions: Arc<dyn AuthTokenFunction>,
    ) -> Self {
        let clock = JavaClock { zone_offset_seconds: config.java_zone_offset_seconds };
        Self {
            http: HttpClient { block_private_targets: config.block_private_targets },
            provider_http: HttpClient { block_private_targets: false },
            oauth_cache: cache.family(),
            auth_cache: cache.family(),
            clock,
            authority_check: Arc::new(NoEvaluator),
            config,
            store,
            tokens,
            cache,
            auth_functions,
        }
    }

    /// Evaluates authority expressions (a connection's `consentAuth`) with `check`.
    pub fn with_authority_check(mut self, check: Arc<dyn AuthorityCheck>) -> Self {
        self.authority_check = check;
        self
    }
}
