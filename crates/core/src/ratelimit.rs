//! `[ratelimit]` on the execute routes (Rust only): a caller who is not signed in may run at most
//! `anonymous_per_minute` functions (stored and `CoreServices.*` alike) a minute from one address,
//! counted in Redis under the bucket `anon` ([`platform::ratelimit`]). Over it, 429
//! `CORE.TOO_MANY_REQUESTS` with a `Retry-After` header.
//!
//! Only requests that came through the gateway are counted here (the gateway appends
//! `X-Forwarded-For`, and an outside caller cannot reach core-exec any other way). ui-shell's
//! URI path routes call core-exec directly without it and count the same bucket themselves, so
//! one address has one budget across both and no call is counted twice. The webhook route
//! (`handlers/webhook.rs`) is internal and counted in ui-shell.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use platform::ratelimit::{RateLimiter, Verdict};

use crate::context::RequestContext;
use crate::error::CoreError;

pub use platform::ratelimit::{ANON, TOO_MANY_REQUESTS};

/// The refusal: over the limit until the window turns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooManyRequests {
    pub retry_after_secs: u64,
    pub limit: u64,
}

impl TooManyRequests {
    pub fn error(&self) -> CoreError {
        CoreError::coded(
            StatusCode::TOO_MANY_REQUESTS,
            TOO_MANY_REQUESTS,
            format!("More than {} function runs a minute from one address without signing in", self.limit),
        )
        .param("retryAfterSeconds", self.retry_after_secs)
    }
}

impl IntoResponse for TooManyRequests {
    fn into_response(self) -> Response {
        let mut resp = self.error().into_response();
        platform::ratelimit::retry_after(&mut resp, self.retry_after_secs);
        resp
    }
}

/// Whether an execute request is counted: the caller is not signed in and the request came
/// through the gateway.
pub fn counted(h: &HeaderMap, authenticated: bool) -> bool {
    !authenticated && h.contains_key("x-forwarded-for")
}

/// Counts one call from `ip` in `bucket`.
pub async fn check(limiter: &RateLimiter, bucket: &str, ip: &str) -> Result<(), TooManyRequests> {
    match limiter.check(bucket, ip).await {
        Verdict::Allow => Ok(()),
        Verdict::Limited { retry_after_secs, limit } => Err(TooManyRequests { retry_after_secs, limit }),
    }
}

/// The execute routes' gate: counts the request in `anon` when [`counted`].
pub async fn check_execute(limiter: &RateLimiter, h: &HeaderMap, ctx: &RequestContext) -> Result<(), TooManyRequests> {
    if !counted(h, ctx.auth.is_authenticated()) {
        return Ok(());
    }
    check(limiter, ANON, &ctx.client_ip).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use platform::ratelimit::{MemoryCounter, RateLimitConfig, WindowCounter};

    use super::*;

    fn limiter(per_minute: u64) -> RateLimiter {
        let cfg = RateLimitConfig { anonymous_per_minute: per_minute, ..Default::default() };
        RateLimiter::new(&cfg, Some(Arc::new(MemoryCounter::default()) as Arc<dyn WindowCounter>))
    }

    #[test]
    fn only_anonymous_calls_through_the_gateway_are_counted() {
        let mut h = HeaderMap::new();
        assert!(!counted(&h, false), "no X-Forwarded-For: ui-shell counted it");
        h.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        assert!(counted(&h, false));
        assert!(!counted(&h, true), "signed in");
    }

    #[test]
    fn the_config_defaults_to_enforcing_600() {
        let c = crate::config::CoreConfig::default();
        assert_eq!(c.ratelimit.mode, platform::ratelimit::RateLimitMode::Enforce);
        assert_eq!(c.ratelimit.anonymous_per_minute, 600);
        let parsed: crate::config::CoreConfig = toml::from_str("[ratelimit]\nmode = \"report\"\nanonymous_per_minute = 100\n").unwrap();
        assert_eq!((parsed.ratelimit.mode, parsed.ratelimit.anonymous_per_minute), (platform::ratelimit::RateLimitMode::Report, 100));
    }

    #[tokio::test]
    async fn the_refusal_is_a_coded_429_with_retry_after() {
        let resp = TooManyRequests { retry_after_secs: 42, limit: 600 }.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers()[axum::http::header::RETRY_AFTER], "42");
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["code"], TOO_MANY_REQUESTS);
        assert_eq!(v["params"]["retryAfterSeconds"], "42");
        assert_eq!(v["message"], "Too many requests to run functions without signing in, from your network. Try again in 42 seconds.");
        assert!(v["action"].as_str().is_some_and(|a| a.contains("sign in")), "{v}");
        assert!(v["debugMessage"].as_str().is_some_and(|d| d.contains("600")), "{v}");
    }

    #[tokio::test]
    async fn check_counts_and_refuses() {
        let l = limiter(2);
        assert_eq!(check(&l, ANON, "1.2.3.4").await, Ok(()));
        assert_eq!(check(&l, ANON, "1.2.3.4").await, Ok(()));
        let refused = check(&l, ANON, "1.2.3.4").await.unwrap_err();
        assert_eq!(refused.limit, 2);
        assert!((1..=60).contains(&refused.retry_after_secs));
    }

    // ------------------------------------------------------------ the execute routes over HTTP

    async fn serve_limited(per_minute: u64) -> String {
        use crate::testing::{offline_state_limited, policy, security_stub, serve, MemoryCatalog, MemoryEngine, RecordingEvents};
        let base = security_stub(&[], &["app"]).await;
        let svc = Arc::new(policy(MemoryCatalog::with(Vec::new()), Arc::new(MemoryEngine::default()), &base, Arc::new(RecordingEvents::default())));
        let state = offline_state_limited(svc, &base, None, limiter(per_minute)).await;
        serve(crate::handlers::router(state)).await
    }

    /// The status of a POST to a core function (`System.Math.Add` needs no definitions).
    async fn execute(http: &reqwest::Client, url: &str, headers: &[(&str, &str)]) -> reqwest::Response {
        let mut rb = http
            .post(format!("{url}/api/core/function/execute/System.Math/Add"))
            .header("X-Forwarded-Host", "apps.local")
            .header("X-Forwarded-Port", "80")
            .header("appCode", "app")
            .header("clientCode", "SYSTEM")
            .header("content-type", "application/json")
            .body(r#"{"value":[1,2]}"#);
        for (k, v) in headers {
            rb = rb.header(*k, *v);
        }
        rb.send().await.unwrap()
    }

    #[tokio::test]
    async fn anonymous_runs_through_the_gateway_are_limited_per_address() {
        let url = serve_limited(2).await;
        let http = reqwest::Client::new();
        let from = |ip: &'static str| [("X-Forwarded-For", "203.0.113.50, 10.0.0.9"), ("X-Real-IP", ip)];
        for _ in 0..2 {
            let r = execute(&http, &url, &from("198.51.100.1")).await;
            assert_ne!(r.status(), 429);
        }
        let r = execute(&http, &url, &from("198.51.100.1")).await;
        assert_eq!(r.status(), 429);
        let retry: u64 = r.headers()["retry-after"].to_str().unwrap().parse().unwrap();
        assert!((1..=60).contains(&retry));
        let v: serde_json::Value = r.json().await.unwrap();
        assert_eq!(v["code"], TOO_MANY_REQUESTS);
        assert_eq!(v["params"]["retryAfterSeconds"], retry.to_string());

        // Another address has its own budget.
        assert_ne!(execute(&http, &url, &from("198.51.100.2")).await.status(), 429);
        // Signed in: never counted.
        for _ in 0..3 {
            let r = execute(&http, &url, &[("X-Forwarded-For", "10.0.0.9"), ("X-Real-IP", "198.51.100.1"), ("Authorization", "Basic user")]).await;
            assert_ne!(r.status(), 429);
        }
        // No X-Forwarded-For (ui-shell's own call, counted there): not counted here.
        for _ in 0..3 {
            assert_ne!(execute(&http, &url, &[("X-Real-IP", "198.51.100.1")]).await.status(), 429);
        }
        // Without X-Real-IP, the gateway's hop (the last X-Forwarded-For entry) is the address.
        for _ in 0..2 {
            assert_ne!(execute(&http, &url, &[("X-Forwarded-For", "1.1.1.1, 192.0.2.7")]).await.status(), 429);
        }
        assert_eq!(execute(&http, &url, &[("X-Forwarded-For", "8.8.8.8, 192.0.2.7")]).await.status(), 429, "the first entry is the caller's to write");
    }
}
