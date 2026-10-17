//! The route table: which pool serves a path.

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
}

impl Route {
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
            out.push(Route {
                id: Box::leak(r.id.clone().into_boxed_str()),
                prefix: if prefix.is_empty() { "/".into() } else { prefix.to_string() },
                contains: r.contains.clone(),
                methods,
                exact: r.exact,
                classifier,
                pool: pool.clone(),
                timeout: r.timeout_seconds.map(Duration::from_secs),
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
}
