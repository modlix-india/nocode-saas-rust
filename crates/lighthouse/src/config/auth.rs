//! Who may read configuration: tokens per consumer, kept as SHA-256 hashes, each with scopes.
//!
//! - `units`: a unit's own document and version (`/v1/units/...`).
//! - `ai`: the ai and ssr env files (`/v1/env/...`) and the Spring compat endpoint.
//! - `ops`: everything above, the admin actions (refresh, the dashboard's instance management)
//!   and the config view of the dashboard. `admin_token_sha256` is an `ops` token.
//! - `peer`: calls between Lighthouse instances (the snapshot). `[registry] peer_token` is one.
//!
//! A token comes as `Authorization: Bearer <token>`, or as the password of Basic (any user), so
//! a client that can only put credentials in a URL (`http://ai:<token>@lighthouse:8761`) works.

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Units,
    Ai,
    Ops,
    Peer,
}

/// `[[auth.tokens]]`: one consumer's token.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TokenConfig {
    /// Who holds it (for the logs): `units-dev`, `ai`, `keepup`.
    pub name: String,
    /// SHA-256 of the token, in hex.
    pub sha256: String,
    pub scopes: Vec<Scope>,
    /// With `units`: the units whose documents it may read. Empty: every unit (one token per
    /// host, as `/etc/modlix/lighthouse.env` holds).
    pub units: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub tokens: Vec<TokenConfig>,
    /// Scopes served without a token (`units`, `ai`), as the Java config-server served everyone,
    /// to callers from the trusted networks only (`[allowed] trusted`: on a host, its own Docker
    /// network); anyone else needs a token for them.
    pub open: Vec<Scope>,
}

struct Token {
    name: String,
    hash: [u8; 32],
    scopes: Vec<Scope>,
    units: Vec<String>,
}

/// The tokens one instance accepts.
pub struct Auth {
    tokens: Vec<Token>,
    open: Vec<Scope>,
}

/// Why a call was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// No token, or one nobody holds: 401.
    Unknown,
    /// A known token without the scope: 403.
    Scope,
}

impl IntoResponse for Denied {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            Denied::Unknown => (StatusCode::UNAUTHORIZED, "a valid token is required"),
            Denied::Scope => (StatusCode::FORBIDDEN, "this token may not read this"),
        };
        // No WWW-Authenticate challenge: a browser would answer it with its own sign-in box over
        // the dashboard, which asks for the admin token itself; the clients that use Basic (ai,
        // from a URL with credentials) send it without being asked.
        (status, axum::Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

fn hash_of(hex_digest: &str, what: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_digest.trim()).map_err(|_| anyhow::anyhow!("{what}: sha256 is not hex"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| anyhow::anyhow!("{what}: sha256 must be 64 hex characters"))
}

impl Auth {
    /// The configured tokens, plus the admin token (`ops`) and the peer token (`peer`).
    pub fn new(cfg: &AuthConfig, admin_sha256: &str, peer_token: &str) -> anyhow::Result<Self> {
        let mut tokens = Vec::new();
        for t in &cfg.tokens {
            if t.scopes.is_empty() {
                anyhow::bail!("[auth] token {:?} has no scopes", t.name);
            }
            let hash = hash_of(&t.sha256, &format!("[auth] token {:?}", t.name))?;
            tokens.push(Token { name: t.name.clone(), hash, scopes: t.scopes.clone(), units: t.units.clone() });
        }
        if !admin_sha256.trim().is_empty() {
            tokens.push(Token { name: "admin".into(), hash: hash_of(admin_sha256, "admin_token_sha256")?, scopes: vec![Scope::Ops], units: vec![] });
        }
        if !peer_token.is_empty() {
            tokens.push(Token { name: "peer".into(), hash: Sha256::digest(peer_token.as_bytes()).into(), scopes: vec![Scope::Peer], units: vec![] });
        }
        if cfg.open.iter().any(|s| matches!(s, Scope::Ops | Scope::Peer)) {
            anyhow::bail!("[auth] open may hold units and ai only: ops and peer always need their token");
        }
        Ok(Self { tokens, open: cfg.open.clone() })
    }

    /// Whether one of `scopes` is served without a token.
    fn open_for(&self, scopes: &[Scope]) -> bool {
        scopes.iter().any(|s| self.open.contains(s))
    }

    /// Whether any token grants `scope`.
    pub fn has(&self, scope: Scope) -> bool {
        self.tokens.iter().any(|t| t.scopes.contains(&scope))
    }

    /// The name of the token presented, when it has one of `scopes`.
    pub fn check(&self, h: &HeaderMap, scopes: &[Scope]) -> Result<String, Denied> {
        match self.find(h, scopes) {
            Ok(t) => Ok(t.name.clone()),
            Err(_) if self.open_for(scopes) && crate::allowed::is_trusted(h) => Ok("open".into()),
            Err(d) => Err(d),
        }
    }

    /// Like [`Auth::check`], for one unit's document: a token limited to some units reads only
    /// theirs (an `ops` token reads any).
    pub fn check_unit(&self, h: &HeaderMap, scopes: &[Scope], unit: &str) -> Result<String, Denied> {
        let t = match self.find(h, scopes) {
            Ok(t) => t,
            Err(_) if self.open_for(scopes) && crate::allowed::is_trusted(h) => return Ok("open".into()),
            Err(d) => return Err(d),
        };
        let any = t.units.is_empty() || t.scopes.contains(&Scope::Ops);
        if any || t.units.iter().any(|u| u == unit) {
            Ok(t.name.clone())
        } else {
            Err(Denied::Scope)
        }
    }

    fn find(&self, h: &HeaderMap, scopes: &[Scope]) -> Result<&Token, Denied> {
        let Some(given) = presented(h) else { return Err(Denied::Unknown) };
        let got: [u8; 32] = Sha256::digest(given.as_bytes()).into();
        // Every token is compared, in constant time, so timing tells nothing.
        let mut found: Option<&Token> = None;
        for t in &self.tokens {
            let same = t.hash.iter().zip(got.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
            if same && found.is_none() {
                found = Some(t);
            }
        }
        match found {
            None => Err(Denied::Unknown),
            Some(t) if t.scopes.iter().any(|s| scopes.contains(s)) => Ok(t),
            Some(_) => Err(Denied::Scope),
        }
    }
}

/// The token of `Authorization`: Bearer, or Basic's password.
fn presented(h: &HeaderMap) -> Option<String> {
    let v = h.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    if let Some(t) = v.strip_prefix("Bearer ") {
        return Some(t.trim().to_string()).filter(|t| !t.is_empty());
    }
    let b64 = v.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let token = text.split_once(':').map_or(text.as_str(), |(_, p)| p);
    Some(token.to_string()).filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, v.parse().unwrap());
        h
    }

    fn sha(t: &str) -> String {
        hex::encode(Sha256::digest(t.as_bytes()))
    }

    #[test]
    fn tokens_and_scopes() {
        let cfg = AuthConfig {
            tokens: vec![
                TokenConfig { name: "units".into(), sha256: sha("u-token"), scopes: vec![Scope::Units], units: vec![] },
                TokenConfig { name: "ai".into(), sha256: sha("a-token").to_uppercase(), scopes: vec![Scope::Ai], units: vec![] },
                TokenConfig { name: "multi".into(), sha256: sha("m-token"), scopes: vec![Scope::Units], units: vec!["multi".into()] },
            ],
            open: vec![],
        };
        let auth = Auth::new(&cfg, &sha("admin"), "peer-secret").unwrap();
        assert!(auth.has(Scope::Ops) && auth.has(Scope::Peer) && auth.has(Scope::Units));
        assert_eq!(auth.check(&headers("Bearer u-token"), &[Scope::Units, Scope::Ops]), Ok("units".into()));
        assert_eq!(auth.check(&headers("Bearer u-token"), &[Scope::Ai]), Err(Denied::Scope));
        let basic = base64::engine::general_purpose::STANDARD.encode("ai:a-token");
        assert_eq!(auth.check(&headers(&format!("Basic {basic}")), &[Scope::Ai]), Ok("ai".into()));
        let bare = base64::engine::general_purpose::STANDARD.encode("admin");
        assert_eq!(auth.check(&headers(&format!("Basic {bare}")), &[Scope::Ops]), Ok("admin".into()));
        assert_eq!(auth.check(&headers("Bearer peer-secret"), &[Scope::Peer]), Ok("peer".into()));
        assert_eq!(auth.check(&headers("Bearer wrong"), &[Scope::Ops]), Err(Denied::Unknown));
        assert_eq!(auth.check(&headers("Bearer "), &[Scope::Ops]), Err(Denied::Unknown));
        assert_eq!(auth.check(&headers("Basic !!!"), &[Scope::Ops]), Err(Denied::Unknown));
        assert_eq!(auth.check(&headers("Token x"), &[Scope::Ops]), Err(Denied::Unknown));
        assert_eq!(auth.check(&HeaderMap::new(), &[Scope::Ops]), Err(Denied::Unknown));
        let units = [Scope::Units, Scope::Ops];
        assert_eq!(auth.check_unit(&headers("Bearer m-token"), &units, "multi"), Ok("multi".into()));
        assert_eq!(auth.check_unit(&headers("Bearer m-token"), &units, "core-exec"), Err(Denied::Scope));
        assert_eq!(auth.check_unit(&headers("Bearer u-token"), &units, "core-exec"), Ok("units".into()));
        let admin = format!("Bearer {}", "admin");
        assert_eq!(auth.check_unit(&headers(&admin), &units, "core-exec"), Ok("admin".into()));
        assert_eq!(auth.check_unit(&headers("Bearer nope"), &units, "multi"), Err(Denied::Unknown));
        let none = Auth::new(&AuthConfig::default(), "", "").unwrap();
        assert!(!none.has(Scope::Ops));

        // Open scopes: no token needed for them, ops still needs one.
        let open = Auth::new(&AuthConfig { tokens: vec![], open: vec![Scope::Units, Scope::Ai] }, &sha("admin"), "").unwrap();
        let trusted = |mut h: HeaderMap| {
            h.insert(crate::allowed::TRUSTED_HEADER, "1".parse().unwrap());
            h
        };
        assert_eq!(open.check(&trusted(HeaderMap::new()), &[Scope::Ai, Scope::Ops]), Ok("open".into()));
        assert_eq!(open.check_unit(&trusted(HeaderMap::new()), &units, "core-exec"), Ok("open".into()));
        assert_eq!(open.check_unit(&trusted(headers("Bearer wrong")), &units, "core-exec"), Ok("open".into()));
        assert_eq!(open.check(&headers("Bearer admin"), &[Scope::Ops]), Ok("admin".into()));
        assert_eq!(open.check(&trusted(HeaderMap::new()), &[Scope::Ops]), Err(Denied::Unknown));
        // From outside the trusted networks the open scopes need a token like any other.
        assert_eq!(open.check(&HeaderMap::new(), &[Scope::Ai]), Err(Denied::Unknown));
        assert_eq!(open.check_unit(&HeaderMap::new(), &units, "core-exec"), Err(Denied::Unknown));
        assert_eq!(open.check_unit(&headers("Bearer admin"), &units, "core-exec"), Ok("admin".into()));
        assert!(Auth::new(&AuthConfig { tokens: vec![], open: vec![Scope::Ops] }, "", "").is_err());
    }

    #[test]
    fn bad_configuration() {
        let no_scope = AuthConfig { tokens: vec![TokenConfig { name: "x".into(), sha256: sha("x"), scopes: vec![], units: vec![] }], open: vec![] };
        assert!(Auth::new(&no_scope, "", "").is_err());
        let bad_hex = AuthConfig { tokens: vec![TokenConfig { name: "x".into(), sha256: "zz".into(), scopes: vec![Scope::Ai], units: vec![] }], open: vec![] };
        assert!(Auth::new(&bad_hex, "", "").is_err());
        assert!(Auth::new(&AuthConfig::default(), "abcd", "").is_err());
    }

    #[test]
    fn refusals_answer_json() {
        let r = Denied::Unknown.into_response();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert!(r.headers().get(header::WWW_AUTHENTICATE).is_none(), "no browser sign-in box over the dashboard");
        let r = Denied::Scope.into_response();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert!(r.headers().get(header::WWW_AUTHENTICATE).is_none());
    }
}
