//! The route table: which pool serves a path.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use axum::http::Method;

use crate::config::RouteConfig;
use crate::pool::Pool;

pub struct Route {
    /// Leaked once at startup: it labels every request's metrics.
    pub id: &'static str,
    prefix: String,
    contains: Vec<String>,
    methods: Vec<Method>,
    exact: bool,
    classifier: Option<fn(&str) -> bool>,
    pub pool: Arc<Pool>,
    pub timeout: Option<Duration>,
    /// What replaces `prefix` in the forwarded path (`RouteConfig::rewrite`).
    rewrite: Option<String>,
    /// `(appCode, clientCode)` the request always goes out for (`RouteConfig::app_code`).
    pub codes: Option<(String, String)>,
    /// `Authorization` is dropped (`RouteConfig::anonymous`).
    pub anonymous: bool,
}

impl Route {
    /// The path the instance is sent: the forwarded path with `prefix` replaced by `rewrite`.
    pub fn forward_path<'a>(&self, path: &'a str) -> Cow<'a, str> {
        match &self.rewrite {
            Some(to) if self.prefix != "/" && path.starts_with(self.prefix.as_str()) => {
                Cow::Owned(format!("{to}{}", &path[self.prefix.len()..]))
            }
            _ => Cow::Borrowed(path),
        }
    }

    fn matches(&self, path: &str, method: &Method) -> bool {
        let prefix_ok = if self.exact {
            path == self.prefix
        } else {
            self.prefix == "/"
                || path == self.prefix
                || (path.starts_with(&self.prefix) && path.as_bytes().get(self.prefix.len()) == Some(&b'/'))
        };
        prefix_ok
            && self.classifier.is_none_or(|f| f(path))
            && (self.contains.is_empty() || self.contains.iter().any(|c| path.contains(c.as_str())))
            && (self.methods.is_empty() || self.methods.iter().any(|m| m == method))
    }
}

pub struct Routes(Vec<Route>);

impl Routes {
    pub fn build(cfg: &[RouteConfig], pools: &BTreeMap<String, Arc<Pool>>) -> Result<Self> {
        let mut out = Vec::with_capacity(cfg.len());
        for r in cfg {
            let Some(pool) = pools.get(&r.pool) else {
                bail!("route {} names pool {}, which is not configured", r.id, r.pool);
            };
            let prefix = r.prefix.trim_end_matches('/');
            let methods = r
                .methods
                .iter()
                .map(|m| Method::from_bytes(m.to_ascii_uppercase().as_bytes()))
                .collect::<Result<Vec<_>, _>>()?;
            let classifier: Option<fn(&str) -> bool> = match r.classifier.as_deref() {
                None => None,
                Some("security-auth") => Some(platform::security::is_auth_route),
                Some("security-internal") => Some(platform::security::is_internal_route),
                Some(other) => bail!("route {} names classifier {other}; known: security-auth, security-internal", r.id),
            };
            let given = |v: &Option<String>| v.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
            let codes = match (given(&r.app_code), given(&r.client_code)) {
                (Some(app), Some(client)) => Some((app, client)),
                (None, None) => None,
                _ => bail!("route {} sets only one of app_code and client_code; set both or neither", r.id),
            };
            let rewrite = match given(&r.rewrite) {
                Some(to) if !to.starts_with("/api/") => bail!("route {} rewrites to {to}, which is not under /api/", r.id),
                Some(_) if prefix.is_empty() => bail!("route {} rewrites the catch-all prefix /", r.id),
                Some(to) => Some(to.trim_end_matches('/').to_string()),
                None => None,
            };
            out.push(Route {
                id: Box::leak(r.id.clone().into_boxed_str()),
                prefix: if prefix.is_empty() { "/".into() } else { prefix.to_string() },
                contains: r.contains.clone(),
                methods,
                exact: r.exact,
                classifier,
                pool: pool.clone(),
                timeout: r.timeout_seconds.map(Duration::from_secs),
                rewrite,
                codes,
                anonymous: r.anonymous,
            });
        }
        if out.is_empty() {
            bail!("no routes configured");
        }
        Ok(Self(out))
    }

    pub fn find(&self, path: &str, method: &Method) -> Option<&Route> {
        self.0.iter().find(|r| r.matches(path, method))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PoolConfig;
    use platform::config::UpstreamConfig;

    fn routes() -> Routes {
        let pool_cfg = PoolConfig { upstreams: UpstreamConfig::One("http://x:1".into()), ..Default::default() };
        let mut pools = BTreeMap::new();
        for n in ["files-serve", "files", "ui", "security"] {
            pools.insert(n.to_string(), Pool::new(n, &pool_cfg, None).unwrap());
        }
        let r = |id: &str, prefix: &str, contains: &[&str], methods: &[&str], pool: &str| RouteConfig {
            id: id.into(),
            prefix: prefix.into(),
            contains: contains.iter().map(|s| s.to_string()).collect(),
            methods: methods.iter().map(|s| s.to_string()).collect(),
            exact: false,
            classifier: None,
            pool: pool.into(),
            timeout_seconds: None,
            ..Default::default()
        };
        Routes::build(
            &[
                r("files-read", "/api/files", &["/api/files/static/file/"], &["GET", "HEAD"], "files-serve"),
                r("files", "/api/files", &[], &[], "files"),
                r("security", "/api/security", &[], &[], "security"),
                RouteConfig { exact: true, ..r("ui-delete-all", "/api/ui", &[], &["DELETE"], "security") },
                r("ui", "/", &[], &[], "ui"),
            ],
            &pools,
        )
        .unwrap()
    }

    #[test]
    fn first_match_wins() {
        let r = routes();
        assert_eq!(r.find("/api/files/static/file/SYSTEM/a.png", &Method::GET).unwrap().id, "files-read");
        assert_eq!(r.find("/api/files/static/file/SYSTEM/a.png", &Method::POST).unwrap().id, "files");
        assert_eq!(r.find("/api/files", &Method::GET).unwrap().id, "files");
        assert_eq!(r.find("/api/filesystem", &Method::GET).unwrap().id, "ui");
        assert_eq!(r.find("/api/security/authenticate", &Method::POST).unwrap().id, "security");
        assert_eq!(r.find("/page/home", &Method::GET).unwrap().id, "ui");
        assert_eq!(r.find("/api/ui", &Method::DELETE).unwrap().id, "ui-delete-all", "exact path");
        assert_eq!(r.find("/api/ui/pages/1", &Method::DELETE).unwrap().id, "ui", "exact: nothing under it");
        assert_eq!(r.find("/api/ui", &Method::GET).unwrap().id, "ui");
    }

    #[test]
    fn classifiers_split_security_like_the_units() {
        let pool_cfg = PoolConfig { upstreams: UpstreamConfig::One("http://x:1".into()), ..Default::default() };
        let mut pools = BTreeMap::new();
        for n in ["auth", "internal", "admin"] {
            pools.insert(n.to_string(), Pool::new(n, &pool_cfg, None).unwrap());
        }
        let r = |id: &str, classifier: Option<&str>, pool: &str| RouteConfig {
            id: id.into(),
            prefix: "/api/security".into(),
            classifier: classifier.map(str::to_string),
            pool: pool.into(),
            ..Default::default()
        };
        let routes = Routes::build(
            &[r("auth", Some("security-auth"), "auth"), r("internal", Some("security-internal"), "internal"), r("admin", None, "admin")],
            &pools,
        )
        .unwrap();
        let id = |p: &str| routes.find(p, &Method::GET).unwrap().id;
        assert_eq!(id("/api/security/verifyToken"), "auth");
        assert_eq!(id("/api/security/internal/securityContextAuthentication"), "auth");
        assert_eq!(id("/api/security/clients/internal/getClientNAppCodeNType"), "internal");
        assert_eq!(id("/api/security/ssl/internal/renew-certificates"), "admin", "excluded from internal");
        assert_eq!(id("/api/security/users"), "admin");
        let bad = Routes::build(&[r("x", Some("nope"), "admin")], &pools);
        assert!(bad.is_err(), "an unknown classifier is refused at startup");
    }

    #[test]
    fn rewrites_and_fixed_codes() {
        let pool_cfg = PoolConfig { upstreams: UpstreamConfig::One("http://x:1".into()), ..Default::default() };
        let mut pools = BTreeMap::new();
        pools.insert("ui".to_string(), Pool::new("ui", &pool_cfg, None).unwrap());
        let intake = |prefix: &str, exact: bool, rewrite: &str| RouteConfig {
            id: "website-intake".into(),
            prefix: prefix.into(),
            exact,
            methods: vec!["POST".into()],
            pool: "ui".into(),
            rewrite: Some(rewrite.into()),
            app_code: Some("leadzumptwo".into()),
            client_code: Some("SYSTEM".into()),
            anonymous: true,
            ..Default::default()
        };
        let plain = RouteConfig { id: "ui".into(), prefix: "/".into(), pool: "ui".into(), ..Default::default() };
        let routes = Routes::build(
            &[
                intake("/api/entity/processor/entry/website", true, "/api/open/intake/website"),
                intake("/api/entity/processor/open/tickets/req/website", false, "/api/open/tickets/req/website/"),
                plain,
            ],
            &pools,
        )
        .unwrap();
        let fwd = |p: &str, m: &Method| {
            let r = routes.find(p, m).unwrap();
            (r.id, r.forward_path(p).into_owned(), r.codes.clone(), r.anonymous)
        };
        let codes = Some(("leadzumptwo".to_string(), "SYSTEM".to_string()));
        assert_eq!(
            fwd("/api/entity/processor/entry/website", &Method::POST),
            ("website-intake", "/api/open/intake/website".to_string(), codes.clone(), true)
        );
        assert_eq!(
            fwd("/api/entity/processor/open/tickets/req/website/MP1XMGgpt6vkZUbEAd2kA", &Method::POST),
            ("website-intake", "/api/open/tickets/req/website/MP1XMGgpt6vkZUbEAd2kA".to_string(), codes, true),
            "what follows the prefix is kept; a trailing / on the rewrite is dropped"
        );
        // Another method, or a longer path under an exact prefix: the ordinary route, unchanged.
        assert_eq!(fwd("/api/entity/processor/entry/website", &Method::GET), ("ui", "/api/entity/processor/entry/website".to_string(), None, false));
        assert_eq!(fwd("/api/entity/processor/entry/website/x", &Method::POST).0, "ui");

        let bad = |cfg: RouteConfig| Routes::build(&[cfg], &pools).is_err();
        assert!(bad(RouteConfig { client_code: None, ..intake("/api/a", true, "/api/b") }), "one code alone is refused");
        assert!(bad(RouteConfig { app_code: Some(" ".into()), ..intake("/api/a", true, "/api/b") }), "a blank code is no code");
        assert!(bad(intake("/api/a", true, "/elsewhere")), "a rewrite stays under /api/");
        assert!(bad(intake("/", false, "/api/b")), "the catch-all is never rewritten");
    }
}
