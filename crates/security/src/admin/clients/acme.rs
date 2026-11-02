//! The certificate authority for real: [`LetsEncrypt`] implements [`Acme`] with instant-acme,
//! one account per process, and `security-admin acme-register` makes that account.
//!
//! Every call binds the order again by its URL (acme4j's `login.bindOrder(url)`): the trait passes
//! orders around as plain [`AcmeOrder`] values, so nothing of instant-acme's lives between calls
//! but the account. What comes back is what acme4j showed Java:
//!
//! - statuses are acme4j's `Status` names (`PENDING`, `READY`, `VALID`, ...);
//! - a challenge's token and authorization are `Http01Challenge`'s token and key authorization,
//!   or for dns-01 `Dns01Challenge.toRRName(domain)` and the digest (the TXT record's name and
//!   value);
//! - an error is the text an `AcmeException` carried: the problem's detail (else its type), its
//!   subproblems in brackets; a challenge's or an order's problem in `formatProblemDetail`'s form
//!   (`Type: ... | Detail: ... | Sub-problems: [...]`, without the title instant-acme does not
//!   read);
//! - the polls are Java's: after a trigger the authorization is refreshed at most twice, three
//!   seconds apart; after finalizing the order at most ten times, three seconds apart, and an
//!   order that ends INVALID or not VALID is answered with `buildOrderDiagnostics`' text.
//!
//! The account is `[letsencrypt] credentials`: the JSON instant-acme serialises its
//! `AccountCredentials` to (account URL, PKCS#8 key, directory). Java's acme4j account has an RSA
//! key, which instant-acme cannot sign with: `acme-rollover` ([`super::rollover`]) moves that same
//! account to a new P-256 key and prints its credentials (`acme-register` makes a new account, for
//! tests and new authorities). The
//! credentials are checked at startup, and the account is connected (its directory fetched) on
//! first use, so a unit starts while the authority is unreachable.
//!
//! instant-acme's HTTP goes through reqwest ([`ReqwestHttp`]): rustls with the webpki roots, as
//! every other outbound call of the units.

use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{anyhow, bail};
use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use http_body_util::BodyExt;
use instant_acme::{
    Account, AccountCredentials, AuthorizationState, AuthorizationStatus, BodyWrapper, BytesResponse, Challenge, ChallengeType, Error, HttpClient,
    Identifier, NewAccount, NewOrder, Order, OrderStatus, Problem,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;

use super::ssl::{Acme, AcmeAuthorization, AcmeChallenge, AcmeOrder, Issued, DNS_01, HTTP_01};
use super::x509;
use crate::config::LetsEncryptConfig;

/// Java's `Thread.sleep(3000L)` between two polls.
const POLL: Duration = Duration::from_secs(3);
/// `triggerChallenge`: the authorization refreshed at most twice after the trigger.
const TRIGGER_POLLS: u32 = 2;
/// `createCertificateInternal`: the order refreshed at most ten times after `execute`.
const FINALIZE_POLLS: u32 = 10;

const ALREADY_INVALID: &str = "Authorization was already INVALID before triggering. A new certificate request with fresh challenges is needed.";
const UNKNOWN_FAILURE: &str = "Unknown error (no problem detail returned by ACME server; check that DNS TXT / HTTP-01 file matches the expected value above, and that propagation is complete from authoritative resolvers)";

// ---- HTTP ----

/// instant-acme's requests sent with reqwest.
#[derive(Clone)]
pub struct ReqwestHttp(pub reqwest::Client);

impl ReqwestHttp {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self(reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?))
    }
}

impl HttpClient for ReqwestHttp {
    fn request(&self, req: http::Request<BodyWrapper<Bytes>>) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let client = self.0.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let body = match body.collect().await {
                Ok(b) => b.to_bytes(),
                Err(never) => match never {},
            };
            let rsp = client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body)
                .send()
                .await
                .map_err(|e| Error::Other(Box::new(e)))?;
            let mut head = http::Response::new(());
            *head.status_mut() = rsp.status();
            *head.headers_mut() = rsp.headers().clone();
            let bytes = rsp.bytes().await.map_err(|e| Error::Other(Box::new(e)))?;
            Ok(BytesResponse { parts: head.into_parts().0, body: Box::new(bytes) })
        })
    }
}

// ---- the account ----

/// `[letsencrypt] credentials` checked, with the configured directory added when they name none
/// (an account lives on one server, so a directory they name wins). Errors give a position at
/// most: the text holds the account's private key.
pub fn credentials(text: &str, directory: &str) -> anyhow::Result<Value> {
    let mut v: Value = serde_json::from_str(text.trim()).map_err(|e| anyhow!("[letsencrypt] credentials is not JSON (line {}, column {})", e.line(), e.column()))?;
    let Some(obj) = v.as_object_mut() else { bail!("[letsencrypt] credentials is not a JSON object") };
    match obj.get("directory").and_then(Value::as_str) {
        Some(own) if own != directory => {
            tracing::warn!(credentials = own, configured = directory, "the account's own directory is used, not [letsencrypt] directory");
        }
        Some(_) => {}
        None => {
            obj.insert("directory".into(), Value::from(directory));
        }
    }
    let _: AccountCredentials = serde_json::from_value(v.clone()).map_err(|_| anyhow!("[letsencrypt] credentials are not instant-acme account credentials (id, key_pkcs8, directory)"))?;
    Ok(v)
}

/// Creates an account on `directory`, agreeing to its terms of service, and answers its
/// credentials as JSON.
pub async fn register(directory: &str, email: &str, http: ReqwestHttp) -> Result<String, String> {
    let contact = format!("mailto:{email}");
    let account = NewAccount { contact: &[&contact], terms_of_service_agreed: true, only_return_existing: false };
    let (_, creds) = Account::builder_with_http(Box::new(http)).create(&account, directory.to_string(), None).await.map_err(|e| message(&e))?;
    serde_json::to_string(&creds).map_err(|e| e.to_string())
}

const USAGE: &str = "Usage: security-admin acme-register --directory <url> --email <address> --agree-tos";

/// The commands besides serving: `security-admin acme-register --directory <url> --email
/// <address> --agree-tos` creates an ACME account and prints its credentials JSON (a secret) on
/// stdout for the private configuration's `[letsencrypt] credentials`; 0, 1 when the authority
/// refuses, 2 on bad arguments. `None` when the arguments name no command: a normal start.
pub async fn run_if_asked(args: &[String]) -> Option<i32> {
    match args.first().map(String::as_str) {
        Some("acme-register") => {
            let http = match ReqwestHttp::new() {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("security-admin acme-register: {e}");
                    return Some(1);
                }
            };
            Some(register_command(&args[1..], &mut std::io::stdout(), &mut std::io::stderr(), http).await)
        }
        Some("acme-rollover") => match ReqwestHttp::new() {
            Ok(h) => Some(super::rollover::rollover_command(&args[1..], &mut std::io::stdout(), &mut std::io::stderr(), h.0).await),
            Err(e) => {
                eprintln!("security-admin acme-rollover: {e}");
                Some(1)
            }
        },
        _ => None,
    }
}

pub async fn register_command(args: &[String], out: &mut dyn Write, err: &mut dyn Write, http: ReqwestHttp) -> i32 {
    let (mut directory, mut email, mut agreed) = (None, None, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--directory" => directory = it.next().cloned(),
            "--email" => email = it.next().cloned(),
            "--agree-tos" => agreed = true,
            _ => {
                let _ = writeln!(err, "{USAGE}");
                return 2;
            }
        }
    }
    let (Some(directory), Some(email)) = (directory.filter(|d| !d.trim().is_empty()), email.filter(|e| e.contains('@'))) else {
        let _ = writeln!(err, "{USAGE}");
        return 2;
    };
    if !agreed {
        let _ = writeln!(
            err,
            "Creating an account accepts the authority's terms of service (Let's Encrypt's: https://letsencrypt.org/repository/). \
             Read them, then run again with --agree-tos."
        );
        return 2;
    }
    match register(&directory, &email, http).await {
        Ok(json) => {
            let _ = writeln!(out, "{json}");
            let _ = writeln!(
                err,
                "Account created on {directory}. Its credentials are on stdout and hold the account's private key: put them in the \
                 private configuration as [letsencrypt] credentials (MODLIX__LETSENCRYPT__CREDENTIALS), nowhere else."
            );
            0
        }
        Err(e) => {
            let _ = writeln!(err, "security-admin acme-register: {e}");
            1
        }
    }
}

// ---- the authority ----

/// Let's Encrypt (or any ACME server) through one account.
pub struct LetsEncrypt {
    credentials: Value,
    http: ReqwestHttp,
    account: OnceCell<Account>,
    poll: Duration,
}

impl LetsEncrypt {
    /// From `[letsencrypt]`: `None` without credentials, an error when they cannot be read.
    pub fn from_config(cfg: &LetsEncryptConfig) -> anyhow::Result<Option<Self>> {
        if cfg.credentials.trim().is_empty() {
            return Ok(None);
        }
        Ok(Some(Self::new(credentials(&cfg.credentials, &cfg.directory)?, ReqwestHttp::new()?)))
    }

    /// Checked credentials (see [`credentials`]).
    pub fn new(credentials: Value, http: ReqwestHttp) -> Self {
        Self { credentials, http, account: OnceCell::new(), poll: POLL }
    }

    /// The directory the account lives on.
    pub fn directory(&self) -> &str {
        self.credentials.get("directory").and_then(Value::as_str).unwrap_or("")
    }

    /// The account, connected on first use; a failure is retried by the next call.
    async fn account(&self) -> Result<&Account, String> {
        self.account
            .get_or_try_init(|| async {
                let creds: AccountCredentials = serde_json::from_value(self.credentials.clone()).map_err(|_| "the account credentials cannot be read".to_string())?;
                Account::builder_with_http(Box::new(self.http.clone())).from_credentials(creds).await.map_err(|e| message(&e))
            })
            .await
    }

    async fn bind(&self, location: &str) -> Result<(Order, String), String> {
        let account = self.account().await?;
        let order = account.order(location.to_string()).await.map_err(|e| message(&e))?;
        Ok((order, account.key_thumbprint().to_string()))
    }
}

/// An `AcmeException`'s message: a problem's detail (else its type), its subproblems in brackets.
pub fn message(e: &Error) -> String {
    match e {
        Error::Api(p) => problem_text(p),
        other => other.to_string(),
    }
}

fn problem_text(p: &Problem) -> String {
    let mut s = p.detail.clone().or_else(|| p.r#type.clone()).unwrap_or_else(|| "about:blank".into());
    if !p.subproblems.is_empty() {
        let subs: Vec<String> = p.subproblems.iter().map(|sp| sp.detail.clone().or_else(|| sp.r#type.clone()).unwrap_or_default()).collect();
        s.push_str(&format!(" ({})", subs.join(", ")));
    }
    s
}

/// `formatProblemDetail(problem)`.
pub fn problem_detail(p: &Problem) -> String {
    let mut s = format!("Type: {}", p.r#type.as_deref().unwrap_or("about:blank"));
    if let Some(d) = &p.detail {
        s.push_str(&format!(" | Detail: {d}"));
    }
    if !p.subproblems.is_empty() {
        let subs: Vec<String> = p
            .subproblems
            .iter()
            .map(|sp| {
                let mut one = String::from("{");
                if let Some(id) = &sp.identifier {
                    one.push_str(&format!("domain: {}, ", id.authorized(false)));
                }
                one.push_str(&format!("type: {}", sp.r#type.as_deref().unwrap_or("about:blank")));
                if let Some(d) = &sp.detail {
                    one.push_str(&format!(", detail: {d}"));
                }
                one.push('}');
                one
            })
            .collect();
        s.push_str(&format!(" | Sub-problems: [{}]", subs.join("; ")));
    }
    s
}

/// acme4j's `Status` name.
fn status<T: std::fmt::Debug>(s: T) -> String {
    format!("{s:?}").to_uppercase()
}

fn kind(t: &ChallengeType) -> String {
    match t {
        ChallengeType::Http01 => HTTP_01.into(),
        ChallengeType::Dns01 => DNS_01.into(),
        ChallengeType::TlsAlpn01 => "tls-alpn-01".into(),
        ChallengeType::DeviceAttest01 => "device-attest-01".into(),
        ChallengeType::Unknown(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

/// `auth.getIdentifier().getDomain()`: the name without a wildcard's `*.`.
fn domain_of(a: &AuthorizationState) -> String {
    match a.identifier().identifier {
        Identifier::Dns(d) => d.clone(),
        other => other.authorized(false).to_string(),
    }
}

/// `Dns01Challenge.toRRName(domain)`.
pub fn rr_name(domain: &str) -> String {
    format!("_acme-challenge.{domain}.")
}

fn challenge(c: &Challenge, domain: &str, thumbprint: &str) -> AcmeChallenge {
    let key_authorization = format!("{}.{thumbprint}", c.token);
    let (token, authorization) = match c.r#type {
        ChallengeType::Dns01 => (rr_name(domain), base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(key_authorization.as_bytes()))),
        _ => (c.token.clone(), key_authorization),
    };
    AcmeChallenge { kind: kind(&c.r#type), token, authorization, status: status(c.status), error: c.error.as_ref().map(problem_detail) }
}

fn authorization(a: &AuthorizationState, thumbprint: &str) -> AcmeAuthorization {
    let domain = domain_of(a);
    let challenges = a.challenges.iter().map(|c| challenge(c, &domain, thumbprint)).collect();
    AcmeAuthorization { status: status(a.status), domain, challenges }
}

/// The order with every authorization (fetched when the order was just loaded or refreshed).
async fn snapshot(o: &mut Order, thumbprint: &str) -> Result<AcmeOrder, Error> {
    let location = o.url().to_string();
    let order_status = status(o.state().status);
    let mut authorizations = Vec::new();
    let mut auths = o.authorizations();
    while let Some(a) = auths.next().await {
        let a = a?;
        authorizations.push(authorization(&a, thumbprint));
    }
    Ok(AcmeOrder { location, status: order_status, authorizations })
}

/// The order refreshed, and its authorization of `domain` as it is now.
async fn fresh_authorization(o: &mut Order, domain: &str, thumbprint: &str) -> Result<Option<AcmeAuthorization>, Error> {
    o.refresh().await?;
    let mut auths = o.authorizations();
    while let Some(a) = auths.next().await {
        let a = a?;
        if domain_of(&a) == domain {
            return Ok(Some(authorization(&a, thumbprint)));
        }
    }
    Ok(None)
}

/// `extractAcmeFailureReason`: the challenge's problem, else its siblings', else Java's
/// "Unknown error" text.
fn failure_reason(auth: Option<&AcmeAuthorization>, kind: &str) -> String {
    let Some(auth) = auth else { return UNKNOWN_FAILURE.into() };
    if let Some(e) = auth.challenges.iter().find(|c| c.kind == kind).and_then(|c| c.error.clone()) {
        return e;
    }
    let siblings: Vec<String> = auth.challenges.iter().filter_map(|c| c.error.as_ref().map(|e| format!("challenge({}) {e}", c.kind))).collect();
    if siblings.is_empty() {
        UNKNOWN_FAILURE.into()
    } else {
        siblings.join(" || ")
    }
}

/// `buildOrderDiagnostics(order)`.
async fn diagnostics(o: &mut Order, thumbprint: &str) -> String {
    let mut s = format!("Order status: {}", status(o.state().status));
    if let Some(p) = o.state().error.clone() {
        s.push_str(&format!(" | Order error: {}", problem_detail(&p)));
    }
    let mut auths = o.authorizations();
    while let Some(a) = auths.next().await {
        let Ok(a) = a else { continue };
        let a = authorization(&a, thumbprint);
        s.push_str(&format!(" | Auth [{}]: status={}", a.domain, a.status));
        for c in &a.challenges {
            s.push_str(&format!(", challenge({})={}", c.kind, c.status));
            if let Some(e) = &c.error {
                s.push_str(&format!(" error={e}"));
            }
        }
    }
    s
}

#[async_trait]
impl Acme for LetsEncrypt {
    fn configured(&self) -> bool {
        true
    }

    async fn new_order(&self, domains: &[String]) -> Result<AcmeOrder, String> {
        let account = self.account().await?;
        let ids = domains.iter().map(|d| super::csr::to_ace(d).map(Identifier::Dns).map_err(|e| e.to_string())).collect::<Result<Vec<_>, _>>()?;
        let mut order = account.new_order(&NewOrder::new(&ids)).await.map_err(|e| message(&e))?;
        snapshot(&mut order, account.key_thumbprint()).await.map_err(|e| message(&e))
    }

    async fn bind_order(&self, location: &str) -> Result<AcmeOrder, String> {
        let (mut order, thumbprint) = self.bind(location).await?;
        snapshot(&mut order, &thumbprint).await.map_err(|e| message(&e))
    }

    async fn trigger(&self, order: &AcmeOrder, domain: &str, kind: &str) -> Result<(String, String), String> {
        let (mut o, thumbprint) = self.bind(&order.location).await?;
        let wanted = if kind == HTTP_01 { ChallengeType::Http01 } else { ChallengeType::Dns01 };
        let mut before = None;
        let mut auths = o.authorizations();
        while let Some(a) = auths.next().await {
            let mut a = a.map_err(|e| message(&e))?;
            if domain_of(&a) != domain || !a.challenges.iter().any(|c| c.r#type == wanted) {
                continue;
            }
            before = Some(a.status);
            tracing::info!(domain, kind, status = ?a.status, "triggering a challenge");
            if matches!(a.status, AuthorizationStatus::Valid | AuthorizationStatus::Invalid) {
                break;
            }
            if let Some(mut ch) = a.challenge(wanted.clone()) {
                ch.set_ready().await.map_err(|e| message(&e))?;
            }
            break;
        }
        let Some(before) = before else { return Err(format!("no {kind} challenge for {domain} in the order")) };
        match before {
            AuthorizationStatus::Valid => return Ok((status(before), String::new())),
            AuthorizationStatus::Invalid => {
                tracing::error!(domain, "the authorization was already INVALID before triggering");
                return Ok((status(before), ALREADY_INVALID.into()));
            }
            _ => {}
        }
        let mut current = status(before);
        let mut auth = None;
        let mut polls = TRIGGER_POLLS;
        while current != "VALID" && current != "INVALID" && polls > 0 {
            tokio::time::sleep(self.poll).await;
            auth = fresh_authorization(&mut o, domain, &thumbprint).await.map_err(|e| message(&e))?;
            current = auth.as_ref().map(|a| a.status.clone()).unwrap_or_else(|| "UNKNOWN".into());
            polls -= 1;
        }
        if current == "VALID" {
            return Ok((current, String::new()));
        }
        // The challenge's problem is often filled only after the authorization went INVALID.
        match fresh_authorization(&mut o, domain, &thumbprint).await {
            Ok(Some(a)) => auth = Some(a),
            Ok(None) => {}
            Err(e) => tracing::warn!(domain, error = %message(&e), "could not refresh the challenge after it failed"),
        }
        let reason = failure_reason(auth.as_ref(), kind);
        tracing::error!(status = %current, domain, kind, error = %reason, "challenge validation failed");
        Ok((current, reason))
    }

    async fn update(&self, order: &AcmeOrder) -> Result<AcmeOrder, String> {
        self.bind_order(&order.location).await
    }

    async fn finalize(&self, order: &AcmeOrder, csr_pem: &str) -> Result<AcmeOrder, String> {
        let Some((_, der)) = x509::pem_blocks(csr_pem).into_iter().next() else { return Err("the request has no CSR".into()) };
        let (mut o, thumbprint) = self.bind(&order.location).await?;
        o.finalize_csr(&der).await.map_err(|e| message(&e))?;
        let mut attempts = FINALIZE_POLLS;
        while o.state().status != OrderStatus::Valid && attempts > 0 {
            attempts -= 1;
            if o.state().status == OrderStatus::Invalid {
                let d = diagnostics(&mut o, &thumbprint).await;
                tracing::error!(diagnostics = %d, "the order is INVALID");
                return Err(d);
            }
            tokio::time::sleep(self.poll).await;
            o.refresh().await.map_err(|e| message(&e))?;
        }
        if o.state().status != OrderStatus::Valid {
            let d = diagnostics(&mut o, &thumbprint).await;
            tracing::error!(diagnostics = %d, "the order timed out");
            return Err(d);
        }
        snapshot(&mut o, &thumbprint).await.map_err(|e| message(&e))
    }

    async fn certificate(&self, order: &AcmeOrder) -> Result<Issued, String> {
        let (mut o, _) = self.bind(&order.location).await?;
        let pem = o.certificate().await.map_err(|e| message(&e))?.ok_or_else(|| "the certificate is not issued yet".to_string())?;
        let info = x509::certificate(&pem).ok_or_else(|| "the certificate cannot be read".to_string())?;
        Ok(Issued { pem, issuer: Some(info.issuer), not_after: info.not_after })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::clients::csr::RsaCsr;
    use crate::admin::clients::ssl::CertCrypto;
    use crate::config::LETS_ENCRYPT_DIRECTORY;
    use serde_json::json;

    fn problem(v: Value) -> Problem {
        serde_json::from_value(v).unwrap()
    }

    /// Credentials of a key made here, on a directory nobody serves.
    fn offline_credentials(directory: Option<&str>) -> String {
        let (_, der) = instant_acme::Key::generate_pkcs8().unwrap();
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(der.secret_pkcs8_der());
        let mut v = json!({"id": "https://acme.invalid/acct/1", "key_pkcs8": key});
        if let Some(d) = directory {
            v["directory"] = json!(d);
        }
        v.to_string()
    }

    #[test]
    fn credentials_are_checked_without_showing_them() {
        let creds = credentials(&offline_credentials(None), "https://pebble.test/dir").unwrap();
        assert_eq!(creds["directory"], "https://pebble.test/dir");
        let own = credentials(&offline_credentials(Some("https://acme-staging-v02.api.letsencrypt.org/directory")), LETS_ENCRYPT_DIRECTORY).unwrap();
        assert_eq!(own["directory"], "https://acme-staging-v02.api.letsencrypt.org/directory");
        let e = credentials("{\"key_pkcs8\": \"zz-secret", LETS_ENCRYPT_DIRECTORY).unwrap_err().to_string();
        assert!(e.contains("not JSON") && !e.contains("zz-secret"), "{e}");
        assert!(credentials("[1]", LETS_ENCRYPT_DIRECTORY).unwrap_err().to_string().contains("not a JSON object"));
        let e = credentials("{\"id\": \"x\", \"key_pkcs8\": 5, \"note\": \"zz-secret\"}", LETS_ENCRYPT_DIRECTORY).unwrap_err().to_string();
        assert!(e.contains("not instant-acme account credentials") && !e.contains("zz-secret"), "{e}");
    }

    #[test]
    fn settings_make_an_authority_or_none() {
        let mut cfg = LetsEncryptConfig::default();
        assert!(LetsEncrypt::from_config(&cfg).unwrap().is_none());
        cfg.credentials = "  ".into();
        assert!(LetsEncrypt::from_config(&cfg).unwrap().is_none());
        cfg.credentials = offline_credentials(None);
        let le = LetsEncrypt::from_config(&cfg).unwrap().unwrap();
        assert!(le.configured());
        assert_eq!(le.directory(), LETS_ENCRYPT_DIRECTORY);
        cfg.credentials = "not json".into();
        assert!(LetsEncrypt::from_config(&cfg).is_err());
    }

    #[tokio::test]
    async fn an_unreachable_authority_is_an_error_each_time() {
        let creds = credentials(&offline_credentials(Some("http://127.0.0.1:9/dir")), LETS_ENCRYPT_DIRECTORY).unwrap();
        let le = LetsEncrypt::new(creds, ReqwestHttp::new().unwrap());
        assert!(le.new_order(&["a.example".into()]).await.is_err());
        let o = AcmeOrder { location: "http://127.0.0.1:9/order/1".into(), status: "PENDING".into(), authorizations: vec![] };
        assert!(le.bind_order(&o.location).await.is_err());
        assert!(le.trigger(&o, "a.example", HTTP_01).await.is_err());
        assert!(le.update(&o).await.is_err());
        assert!(le.finalize(&o, "no pem").await.is_err());
        assert!(le.certificate(&o).await.is_err());
        assert!(le.account.get().is_none());
    }

    #[test]
    fn problems_read_as_acme4j_wrote_them() {
        let p = problem(json!({
            "type": "urn:ietf:params:acme:error:rejectedIdentifier",
            "detail": "Error creating new order",
            "subproblems": [
                {"type": "urn:ietf:params:acme:error:malformed", "detail": "bad name", "identifier": {"type": "dns", "value": "a.example"}},
                {"type": "urn:ietf:params:acme:error:caa"}
            ]
        }));
        assert_eq!(message(&Error::Api(p.clone())), "Error creating new order (bad name, urn:ietf:params:acme:error:caa)");
        assert_eq!(
            problem_detail(&p),
            "Type: urn:ietf:params:acme:error:rejectedIdentifier | Detail: Error creating new order | Sub-problems: \
             [{domain: a.example, type: urn:ietf:params:acme:error:malformed, detail: bad name}; {type: urn:ietf:params:acme:error:caa}]"
        );
        assert_eq!(problem_text(&problem(json!({}))), "about:blank");
        assert_eq!(problem_detail(&problem(json!({"type": "t"}))), "Type: t");
        assert_eq!(message(&Error::Str("x")), "missing data: x");
    }

    #[test]
    fn challenges_as_acme4j_showed_them() {
        let state: AuthorizationState = serde_json::from_value(json!({
            "identifier": {"type": "dns", "value": "shop.example"},
            "status": "pending",
            "wildcard": true,
            "challenges": [
                {"type": "http-01", "url": "https://ca/c/1", "token": "tok", "status": "pending"},
                {"type": "dns-01", "url": "https://ca/c/2", "token": "tok2", "status": "invalid", "error": {"type": "urn:x", "detail": "no TXT"}},
                {"type": "tls-alpn-01", "url": "https://ca/c/3", "token": "tok3", "status": "valid"}
            ]
        }))
        .unwrap();
        let a = authorization(&state, "thumb");
        assert_eq!((a.domain.as_str(), a.status.as_str()), ("shop.example", "PENDING"));
        let http = &a.challenges[0];
        assert_eq!((http.kind.as_str(), http.token.as_str(), http.authorization.as_str()), (HTTP_01, "tok", "tok.thumb"));
        let dns = &a.challenges[1];
        assert_eq!((dns.kind.as_str(), dns.token.as_str(), dns.status.as_str()), (DNS_01, "_acme-challenge.shop.example.", "INVALID"));
        let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(b"tok2.thumb"));
        assert_eq!(dns.authorization, digest);
        assert_eq!(dns.error.as_deref(), Some("Type: urn:x | Detail: no TXT"));
        assert_eq!(a.challenges[2].kind, "tls-alpn-01");
        // The failure reason: the challenge's own problem, else its siblings', else Java's text.
        assert_eq!(failure_reason(Some(&a), DNS_01), "Type: urn:x | Detail: no TXT");
        assert_eq!(failure_reason(Some(&a), HTTP_01), "challenge(dns-01) Type: urn:x | Detail: no TXT");
        let quiet = AcmeAuthorization { challenges: vec![http.clone()], ..a.clone() };
        assert_eq!(failure_reason(Some(&quiet), HTTP_01), UNKNOWN_FAILURE);
        assert_eq!(failure_reason(None, HTTP_01), UNKNOWN_FAILURE);
        assert_eq!(status(OrderStatus::Processing), "PROCESSING");
        assert_eq!(kind(&ChallengeType::Unknown("x-01".into())), "x-01");
    }

    #[tokio::test]
    async fn the_register_command_needs_explicit_agreement() {
        let http = ReqwestHttp::new().unwrap();
        let run = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let http = http.clone();
            async move {
                let (mut out, mut err) = (Vec::new(), Vec::new());
                let code = register_command(&args, &mut out, &mut err, http).await;
                (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
            }
        };
        let (code, out, err) = run(&["--directory", "http://127.0.0.1:9/dir", "--email", "a@b.c"]).await;
        assert_eq!((code, out.as_str()), (2, ""));
        assert!(err.contains("--agree-tos"), "{err}");
        assert_eq!(run(&["--directory", "http://127.0.0.1:9/dir"]).await.0, 2);
        assert_eq!(run(&["--email", "nobody", "--directory", "x", "--agree-tos"]).await.0, 2);
        assert_eq!(run(&["--what"]).await.0, 2);
        let (code, out, err) = run(&["--directory", "http://127.0.0.1:9/dir", "--email", "a@b.c", "--agree-tos"]).await;
        assert_eq!((code, out.as_str()), (1, ""));
        assert!(err.starts_with("security-admin acme-register: "), "{err}");
        assert_eq!(run_if_asked(&[]).await, None);
        assert_eq!(run_if_asked(&["serve".into()]).await, None);
        assert_eq!(run_if_asked(&["acme-register".into()]).await, Some(2));
        assert_eq!(run_if_asked(&["acme-rollover".into()]).await, Some(2));
    }

    /// The whole flow against Pebble, Let's Encrypt's test server (gated: `SECURITY_ACME_PEBBLE=1`,
    /// the directory in `SECURITY_ACME_PEBBLE_DIRECTORY`, by default `https://localhost:14000/dir`):
    ///
    /// ```sh
    /// docker run --rm -d --name pebble -p 14000:14000 -e PEBBLE_VA_ALWAYS_VALID=1 \
    ///     -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 ghcr.io/letsencrypt/pebble
    /// SECURITY_ACME_PEBBLE=1 cargo test -p security issues_a_certificate_from_pebble
    /// ```
    ///
    /// `PEBBLE_VA_ALWAYS_VALID` passes every challenge without looking, and `PEBBLE_VA_NOSLEEP`
    /// does it at once (Pebble otherwise waits up to 15 s, longer than the two polls after a
    /// trigger, and the challenge is still PENDING, as it can be with Let's Encrypt). Pebble's TLS
    /// certificate comes from its own test CA, which this test alone accepts.
    #[tokio::test]
    async fn issues_a_certificate_from_pebble() {
        if std::env::var("SECURITY_ACME_PEBBLE").is_err() {
            eprintln!("skipped: SECURITY_ACME_PEBBLE not set");
            return;
        }
        let directory = std::env::var("SECURITY_ACME_PEBBLE_DIRECTORY").unwrap_or_else(|_| "https://localhost:14000/dir".into());
        let http = ReqwestHttp(reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap());

        let args: Vec<String> = ["--directory", &directory, "--email", "zz-acme@example.com", "--agree-tos"].iter().map(|s| s.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(register_command(&args, &mut out, &mut err, http.clone()).await, 0, "{}", String::from_utf8_lossy(&err));
        let creds = credentials(&String::from_utf8(out).unwrap(), LETS_ENCRYPT_DIRECTORY).unwrap();
        assert_eq!(creds["directory"], directory.as_str());
        let le = LetsEncrypt { poll: Duration::from_secs(1), ..LetsEncrypt::new(creds, http) };

        let host = format!("zz{}.example.test", super::super::urls::random_hex().get(..10).unwrap_or("x"));
        let domains = vec![host.clone(), format!("WWW.{host}")];
        let order = le.new_order(&domains).await.unwrap();
        assert_eq!(order.status, "PENDING");
        assert_eq!(order.authorizations.len(), 2);
        for a in &order.authorizations {
            assert_eq!(a.status, "PENDING");
            let http01 = a.challenges.iter().find(|c| c.kind == HTTP_01).unwrap();
            assert!(http01.authorization.starts_with(&format!("{}.", http01.token)));
            let dns01 = a.challenges.iter().find(|c| c.kind == DNS_01).unwrap();
            assert_eq!(dns01.token, rr_name(&a.domain));
        }
        assert!(order.authorizations.iter().any(|a| a.domain == format!("www.{host}")));
        assert_eq!(le.bind_order(&order.location).await.unwrap().location, order.location);

        // One domain by http-01, the other by dns-01.
        let (first, second) = (&order.authorizations[0].domain, &order.authorizations[1].domain);
        assert_eq!(le.trigger(&order, first, HTTP_01).await.unwrap(), ("VALID".to_string(), String::new()));
        assert_eq!(le.trigger(&order, second, DNS_01).await.unwrap(), ("VALID".to_string(), String::new()));
        // Already valid: answered without a trigger.
        assert_eq!(le.trigger(&order, first, HTTP_01).await.unwrap(), ("VALID".to_string(), String::new()));
        assert!(le.trigger(&order, "elsewhere.example.test", HTTP_01).await.is_err());
        let ready = le.update(&order).await.unwrap();
        assert_eq!(ready.status, "READY");

        let (key, csr) = RsaCsr.key_and_csr(&domains, Some("ZZ Org")).unwrap();
        assert!(le.finalize(&ready, "no pem").await.is_err());
        let done = le.finalize(&ready, &csr).await.unwrap();
        assert_eq!(done.status, "VALID");
        let issued = le.certificate(&done).await.unwrap();
        assert!(x509::pem_blocks(&issued.pem).len() >= 2, "a chain: the certificate and its issuer");
        let info = x509::certificate(&issued.pem).unwrap();
        assert!(issued.not_after > chrono::Utc::now().naive_utc() + chrono::Duration::days(1));
        assert_eq!(issued.not_after, info.not_after);
        assert!(x509::matches(&info.key, &x509::private_key(&key).unwrap()), "the certificate is for the request's key");
        let issuer = issued.issuer.unwrap();
        assert!(issuer.starts_with("cn=pebble intermediate ca "), "{issuer}");
        // The upload check accepts what was issued, with its key.
        assert!(super::super::ssl::validate_crt_and_key(Some(&issued.pem), Some(&key), chrono::Utc::now().naive_utc()).is_ok());
        // A finalized order cannot be finalized again.
        assert!(le.finalize(&done, &csr).await.is_err());
        assert!(le.bind_order(&format!("{}-gone", order.location)).await.is_err());
    }
}
