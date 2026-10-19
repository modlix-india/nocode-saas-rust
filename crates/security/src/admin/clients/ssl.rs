//! `SSLCertificateController` and `SSLCertificateService`: certificate requests (ACME orders and
//! their challenges), issued and uploaded certificates, and the renewal sweep.
//!
//! | Route | Who |
//! |---|---|
//! | `GET ssl/token/{token}`, `POST ssl/internal/renew-certificates` | anyone (renewal: SYSTEM only) |
//! | `POST ssl`, `POST ssl/external`, `GET ssl`, `POST ssl/query`, `GET ssl/certificate`, `GET`/`DELETE ssl/request`, `GET ssl/request/challenge` | `Client_UPDATE` (`DELETE ssl/request`: signed in) |
//! | `POST ssl/request/challenges`, `DELETE ssl/{id}` | signed in |
//!
//! Every certificate authority call goes through [`Acme`] and every key or CSR through
//! [`CertCrypto`]. This unit runs with [`Unavailable`] for both: it has no ACME client and no RSA
//! (see DIFFERENCES.md), so the routes that would contact Let's Encrypt answer what Java answers
//! without Let's Encrypt credentials, before changing anything. Tests drive the whole flow
//! through in-process fakes; nothing here ever reaches a real authority or DNS.

use async_trait::async_trait;
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::Router;
use chrono::{Duration, NaiveDateTime};
use serde_json::{json, Value};

use crate::web::page_of;
use super::common::{cache, err, object_body, pre_authorize, Kind};
use super::common::{BAD_CERT_REQUEST, CRT_KEY_ISSUE, ERROR_KEY_CSR, LETS_ENCRYPT_CREDENTIALS, LETS_ENCRYPT_ISSUE, MISMATCH_DOMAINS};
use super::common::{OBJECT_NOT_FOUND, ONLY_SYS_USER_CERTS, REQUEST_EXISTING, TRIGGER_FAILED};
use super::entity::{self, col, extra, ignored, Col, Entity, Row, CREATED_AT, CREATED_BY, ID, UPDATED_AT, UPDATED_BY};
use super::x509;
use crate::admin::AdminState;
use crate::condition::{ColType, Cond, Filter, Table};
use crate::errors::{AuthError, AuthResult};
use crate::jackson::{json as json_resp, Obj};
use crate::model::ContextAuth;
use crate::spring::{Order as SortOrder, Pageable};
use crate::web::{self, req_u64, to_u64};
use crate::{web_route, web_route_path};

// ---- DTOs ----

static CERT_COLS: [Col; 17] = [
    ID,
    CREATED_AT,
    CREATED_BY,
    UPDATED_AT,
    UPDATED_BY,
    col("urlId", "URL_ID", Kind::U64, true),
    col("crt", "CRT", Kind::Str, true),
    col("crtChain", "CRT_CHAIN", Kind::Str, true),
    ignored("crtKey", "CRT_KEY", Kind::Str, true),
    col("csr", "CSR", Kind::Str, true),
    col("domains", "DOMAINS", Kind::Str, true),
    col("organization", "ORGANIZATION", Kind::Str, true),
    col("expiryDate", "EXPIRY_DATE", Kind::Ts, true),
    col("issuer", "ISSUER", Kind::Str, true),
    col("current", "CURRENT", Kind::Bool, true),
    col("autoRenewTill", "AUTO_RENEW_TILL", Kind::Ts, false),
    extra("crtKeyUpload", Kind::Str),
];

pub static CERTIFICATE: Entity = Entity {
    pojo: "SSLCertificate",
    table: "security_ssl_certificate",
    cols: &CERT_COLS,
    setters: &[],
    aliases: &[],
    filter: Table {
        name: "security_ssl_certificate",
        columns: &[
            ("ID", ColType::Num),
            ("URL_ID", ColType::Num),
            ("CRT", ColType::Str),
            ("CRT_CHAIN", ColType::Str),
            ("CRT_KEY", ColType::Str),
            ("CSR", ColType::Str),
            ("DOMAINS", ColType::Str),
            ("ORGANIZATION", ColType::Str),
            ("EXPIRY_DATE", ColType::Ts),
            ("ISSUER", ColType::Str),
            ("CURRENT", ColType::Num),
            ("AUTO_RENEW_TILL", ColType::Ts),
            ("CREATED_BY", ColType::Num),
            ("CREATED_AT", ColType::Ts),
            ("UPDATED_BY", ColType::Num),
            ("UPDATED_AT", ColType::Ts),
        ],
    },
    client_column: None,
};

static REQUEST_COLS: [Col; 12] = [
    ID,
    entity::extra("createdAt", Kind::Ts),
    entity::extra("createdBy", Kind::U64),
    UPDATED_AT,
    UPDATED_BY,
    col("urlId", "URL_ID", Kind::U64, true),
    col("domains", "DOMAINS", Kind::Str, true),
    col("organization", "ORGANIZATION", Kind::Str, true),
    ignored("crtKey", "CRT_KEY", Kind::Str, true),
    col("csr", "CSR", Kind::Str, true),
    col("validity", "VALIDITY", Kind::I64, true),
    col("failedReason", "FAILED_REASON", Kind::Str, false),
];

pub static REQUEST: Entity = Entity {
    pojo: "SSLRequest",
    table: "security_ssl_request",
    cols: &REQUEST_COLS,
    setters: &[],
    aliases: &[],
    filter: Table {
        name: "security_ssl_request",
        columns: &[
            ("ID", ColType::Num),
            ("URL_ID", ColType::Num),
            ("DOMAINS", ColType::Str),
            ("ORGANIZATION", ColType::Str),
            ("CRT_KEY", ColType::Str),
            ("CSR", ColType::Str),
            ("VALIDITY", ColType::Num),
            ("FAILED_REASON", ColType::Str),
            ("ORDER_URL", ColType::Str),
            ("UPDATED_BY", ColType::Num),
            ("UPDATED_AT", ColType::Ts),
        ],
    },
    client_column: None,
};

static CHALLENGE_COLS: [Col; 14] = [
    ID,
    CREATED_AT,
    CREATED_BY,
    UPDATED_AT,
    UPDATED_BY,
    col("requestId", "REQUEST_ID", Kind::U64, true),
    col("challengeType", "CHALLENGE_TYPE", Kind::Str, true),
    col("domain", "DOMAIN", Kind::Str, true),
    col("token", "TOKEN", Kind::Str, true),
    col("authorization", "AUTHORIZATION", Kind::Str, true),
    col("status", "STATUS", Kind::Str, true),
    col("failedReason", "FAILED_REASON", Kind::Str, false),
    col("lastValidatedAt", "LAST_VALIDATED_AT", Kind::Ts, false),
    col("retryCount", "RETRY_COUNT", Kind::I64, true),
];

pub static CHALLENGE: Entity = Entity {
    pojo: "SSLChallenge",
    table: "security_ssl_challenge",
    cols: &CHALLENGE_COLS,
    setters: &[],
    aliases: &[],
    filter: Table {
        name: "security_ssl_challenge",
        columns: &[
            ("ID", ColType::Num),
            ("REQUEST_ID", ColType::Num),
            ("CHALLENGE_TYPE", ColType::Str),
            ("DOMAIN", ColType::Str),
            ("TOKEN", ColType::Str),
            ("AUTHORIZATION", ColType::Str),
            ("STATUS", ColType::Str),
            ("FAILED_REASON", ColType::Str),
            ("LAST_VALIDATED_AT", ColType::Ts),
            ("RETRY_COUNT", ColType::Num),
            ("CREATED_BY", ColType::Num),
            ("CREATED_AT", ColType::Ts),
            ("UPDATED_BY", ColType::Num),
            ("UPDATED_AT", ColType::Ts),
        ],
    },
    client_column: None,
};

// ---- the certificate authority ----

pub const HTTP_01: &str = "http-01";
pub const DNS_01: &str = "dns-01";

/// One challenge of an authorization, as the authority offers it: for `http-01` the token and
/// key authorization, for `dns-01` the TXT record's name and digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeChallenge {
    pub kind: String,
    pub token: String,
    pub authorization: String,
    pub status: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeAuthorization {
    pub domain: String,
    pub status: String,
    pub challenges: Vec<AcmeChallenge>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeOrder {
    pub location: String,
    pub status: String,
    pub authorizations: Vec<AcmeAuthorization>,
}

/// An issued certificate: the chain as PEM, the issuer's canonical name, the expiry (UTC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    pub pem: String,
    pub issuer: Option<String>,
    pub not_after: NaiveDateTime,
}

/// What `SSLCertificateService` does with acme4j. `Err` carries an `AcmeException`'s message.
#[async_trait]
pub trait Acme: Send + Sync {
    /// `letsencrypt.session`, `.login` and `.key` are all set.
    fn configured(&self) -> bool;
    /// `login.getAccount().newOrder().domains(...).create()`.
    async fn new_order(&self, domains: &[String]) -> Result<AcmeOrder, String>;
    /// `login.bindOrder(url)` then `order.update()`.
    async fn bind_order(&self, location: &str) -> Result<AcmeOrder, String>;
    /// `triggerChallenge(auth, ch)`: (status, error) after the authority's answer and its polls.
    async fn trigger(&self, order: &AcmeOrder, domain: &str, kind: &str) -> Result<(String, String), String>;
    /// `order.update()` (after a trigger).
    async fn update(&self, order: &AcmeOrder) -> Result<AcmeOrder, String>;
    /// `order.execute(csr)` and the polls until VALID or INVALID (at most ten).
    async fn finalize(&self, order: &AcmeOrder, csr_pem: &str) -> Result<AcmeOrder, String>;
    /// `order.getCertificate()`.
    async fn certificate(&self, order: &AcmeOrder) -> Result<Issued, String>;
}

/// The key pair and CSR `makeRecord` builds, and the upload check.
pub trait CertCrypto: Send + Sync {
    /// A new 2048-bit RSA key (PEM) and a CSR for the domains, signed with it. `None` when it
    /// cannot (Java's `error_key_csr`).
    fn key_and_csr(&self, domains: &[String], organization: Option<&str>) -> Option<(String, String)>;
}

/// No authority and no RSA: what this unit runs with.
pub struct Unavailable;

#[async_trait]
impl Acme for Unavailable {
    fn configured(&self) -> bool {
        false
    }
    async fn new_order(&self, _: &[String]) -> Result<AcmeOrder, String> {
        Err("no ACME client".into())
    }
    async fn bind_order(&self, _: &str) -> Result<AcmeOrder, String> {
        Err("no ACME client".into())
    }
    async fn trigger(&self, _: &AcmeOrder, _: &str, _: &str) -> Result<(String, String), String> {
        Err("no ACME client".into())
    }
    async fn update(&self, _: &AcmeOrder) -> Result<AcmeOrder, String> {
        Err("no ACME client".into())
    }
    async fn finalize(&self, _: &AcmeOrder, _: &str) -> Result<AcmeOrder, String> {
        Err("no ACME client".into())
    }
    async fn certificate(&self, _: &AcmeOrder) -> Result<Issued, String> {
        Err("no ACME client".into())
    }
}

impl CertCrypto for Unavailable {
    fn key_and_csr(&self, _: &[String], _: Option<&str>) -> Option<(String, String)> {
        None
    }
}

/// The authority and crypto a call runs with.
pub struct Ssl<'a> {
    pub acme: &'a dyn Acme,
    pub crypto: &'a dyn CertCrypto,
}

impl Ssl<'static> {
    /// This unit's: neither is available.
    pub fn unit() -> Self {
        Ssl { acme: &Unavailable, crypto: &Unavailable }
    }
}

fn credentials() -> AuthError {
    err(StatusCode::INTERNAL_SERVER_ERROR, LETS_ENCRYPT_CREDENTIALS, &[])
}

fn issue(message: &str) -> AuthError {
    err(StatusCode::INTERNAL_SERVER_ERROR, LETS_ENCRYPT_ISSUE, &[message])
}

// ---- reads ----

async fn evict_last_updated(s: &AdminState) {
    s.caches().service.evict_all_everywhere(cache::CERTIFICATE_LAST_UPDATED).await;
}

async fn evict_certificates(s: &AdminState) {
    s.caches().service.evict_all_everywhere(cache::CERTIFICATE).await;
    evict_last_updated(s).await;
}

/// `SSLRequestDAO.readByURLId`.
async fn request_by_url(s: &AdminState, url_id: u64) -> AuthResult<Option<Row>> {
    let sql = format!("SELECT {} FROM security_ssl_request WHERE URL_ID = ? LIMIT 1", REQUEST.select_list());
    let r = sqlx::query(&sql).bind(url_id).fetch_optional(&s.db.pool).await?;
    r.as_ref().map(|r| REQUEST.read_row(r)).transpose()
}

/// `SSLChallengeDAO.readChallengesByRequestId`.
async fn challenges_of(s: &AdminState, request_id: u64) -> AuthResult<Vec<Row>> {
    let sql = format!("SELECT {} FROM security_ssl_challenge WHERE REQUEST_ID = ?", CHALLENGE.select_list());
    let rows = sqlx::query(&sql).bind(request_id).fetch_all(&s.db.pool).await?;
    rows.iter().map(|r| CHALLENGE.read_row(r)).collect()
}

/// `readRequestByURLId(urlId)`: `SSLCertificateOrder` (the request and its challenges), `None`
/// without a request.
pub async fn order_of_url(s: &AdminState, ca: &ContextAuth, url_id: u64) -> AuthResult<Option<Value>> {
    super::urls::read(s, ca, url_id).await?;
    let Some(request) = request_by_url(s, url_id).await? else { return Ok(None) };
    let challenges = challenges_of(s, entity::u64_of(&request, "id").unwrap_or(0)).await?;
    Ok(Some(
        Obj::new()
            .put("request", REQUEST.to_json(&request, vec![]))
            .put("challenges", Value::Array(challenges.iter().map(|c| CHALLENGE.to_json(c, vec![])).collect()))
            .build(),
    ))
}

/// `findSSLCertificates(urlId, pageable, condition)`: the URL must be readable; its certificates
/// filtered further by the condition.
pub async fn certificates_page(s: &AdminState, ca: &ContextAuth, url_id: Option<u64>, pageable: &Pageable, cond: Option<Cond>) -> AuthResult<Value> {
    let Some(url_id) = url_id else {
        return Err(err(StatusCode::NOT_FOUND, OBJECT_NOT_FOUND, &["ClientUrl", "null"]));
    };
    super::urls::read(s, ca, url_id).await?;
    let by_url = Cond::Filter(Filter::eq("urlId", url_id));
    let cond = match cond.filter(|c| !matches!(c, Cond::Complex { conditions, .. } if conditions.is_empty())) {
        None => by_url,
        Some(c) => Cond::and(vec![by_url, c]),
    };
    let sql = crate::condition::to_sql(&cond, &CERTIFICATE.filter)?;
    let (rows, count) = entity::page(&s.db, &CERTIFICATE, crate::data::crud::ClientCheck::All, sql, pageable).await?;
    Ok(page_of(rows.iter().map(|r| CERTIFICATE.to_json(r, vec![])).collect(), pageable, count))
}

/// `SSLChallengeDAO.getToken(token)`: the challenge's key authorization, `""` when unknown.
pub async fn token(s: &AdminState, token: &str) -> AuthResult<String> {
    let v: Option<String> = sqlx::query_scalar("SELECT AUTHORIZATION FROM security_ssl_challenge WHERE TOKEN = ? LIMIT 1")
        .bind(token)
        .fetch_optional(&s.db.pool)
        .await?;
    Ok(v.unwrap_or_default())
}

// ---- uploads ----

/// `validateCrtAndKey`: the messages Java answers for each problem.
pub fn validate_crt_and_key(crt: Option<&str>, key: Option<&str>, now: NaiveDateTime) -> AuthResult<()> {
    let problem = |m: &str| err(StatusCode::BAD_REQUEST, CRT_KEY_ISSUE, &[m]);
    let Some(key) = key.filter(|k| !k.trim().is_empty()) else { return Err(problem("Key is missing")) };
    let Some(crt) = crt.filter(|c| !c.trim().is_empty()) else { return Err(problem("Certificate is missing")) };
    let Some(cert) = x509::certificate(crt) else {
        let mut e = problem("Error while reading the certificate");
        // `CertificateException`'s own message is the debug text; without a PEM block Java reads
        // nothing at all.
        if x509::pem_blocks(crt).is_empty() {
            if let AuthError::Generic { debug, .. } = &mut e {
                *debug = Some("Could not parse certificate: java.io.IOException: Empty input".into());
            }
        }
        return Err(e);
    };
    if cert.not_after < now {
        return Err(problem("Certificate is expired"));
    }
    let private = match x509::private_key(key) {
        Ok(k) => k,
        Err(x509::KeyProblem::Missing) => {
            return Err(AuthError::internal("Cannot invoke \"org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getPrivateKeyAlgorithm()\" because \"keyInfo\" is null"));
        }
        Err(x509::KeyProblem::Unreadable) => return Err(problem("Error while reading the key")),
    };
    if !x509::matches(&cert.key, &private) {
        return Err(problem(
            "Error while matching the certificate and key. Either the certificate or key is incorrect, or Certificate and key are not based on RSA algorithm.",
        ));
    }
    Ok(())
}

/// `SSLCertificateDAO.create`: the certificate, then every other one of the URL no longer
/// current.
async fn insert_certificate(s: &AdminState, cert: &Row) -> AuthResult<Row> {
    let id = entity::insert(&s.db, &CERTIFICATE, cert).await?;
    let created = entity::read_by_id(&s.db, &CERTIFICATE, id).await?;
    let url = entity::u64_of(&created, "urlId");
    if let Err(e) = sqlx::query("UPDATE security_ssl_certificate SET CURRENT = 0 WHERE (ID <> ? AND URL_ID = ?)")
        .bind(id)
        .bind(url)
        .execute(&s.db.pool)
        .await
    {
        tracing::error!(error = %e, url_id = ?url, "could not mark the other certificates not current");
    }
    Ok(created)
}

/// `createExternallyIssuedCertificate(certificate)`.
pub async fn create_external(s: &AdminState, ca: &ContextAuth, mut cert: Row) -> AuthResult<Row> {
    let upload = cert.get("crtKeyUpload").cloned().unwrap_or(Value::Null);
    cert.insert("crtKey".into(), upload);
    validate_crt_and_key(entity::str_of(&cert, "crt"), entity::str_of(&cert, "crtKey"), s.auth.clock.utc())?;
    super::urls::read(s, ca, entity::u64_of(&cert, "urlId").unwrap_or(0)).await?;
    cert.insert("createdBy".into(), Value::Null);
    let created = insert_certificate(s, &cert).await?;
    evict_certificates(s).await;
    Ok(created)
}

// ---- requests and orders ----

/// The body of `POST ssl` (`SSLCertificateOrderRequest`).
#[derive(Debug, Clone, Default)]
pub struct OrderRequest {
    pub domain_names: Option<Vec<String>>,
    pub organization_name: Option<String>,
    pub url_id: Option<u64>,
    pub validity_in_months: Option<i64>,
}

pub fn order_request(body: &Value) -> AuthResult<OrderRequest> {
    use super::common::{prop_i64, prop_str, prop_u64};
    let domain_names = match body.get("domainNames") {
        None | Some(Value::Null) => None,
        Some(Value::Array(a)) => Some(
            a.iter()
                .map(|v| super::common::coerce(Kind::Str, v).map(|v| v.as_str().unwrap_or("").to_string()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| web::unreadable())?,
        ),
        Some(Value::String(s)) => Some(vec![s.clone()]),
        Some(_) => return Err(web::unreadable()),
    };
    Ok(OrderRequest {
        domain_names,
        organization_name: prop_str(body, "organizationName")?,
        url_id: prop_u64(body, "urlId")?,
        validity_in_months: if body.get("validityInMonths").is_some() { prop_i64(body, "validityInMonths")? } else { Some(12) },
    })
}

/// `validateDomainNames`: every domain must end with the URL's host.
pub fn validate_domain_names(domains: &[String], url: &str) -> AuthResult<()> {
    if url.trim().is_empty() {
        return Ok(());
    }
    let mut u = url;
    if let Some(i) = u.find("//") {
        u = &u[i + 2..];
    }
    if let Some(i) = u.find('/') {
        u = &u[..i];
    }
    let wrong: Vec<&String> = domains.iter().filter(|d| !d.ends_with(u)).collect();
    if wrong.is_empty() {
        return Ok(());
    }
    Err(err(StatusCode::BAD_REQUEST, MISMATCH_DOMAINS, &[&format!("{wrong:?}")]))
}

/// `makeRecord(request)`: a new key and CSR for the domains.
fn make_record(ssl: &Ssl<'_>, domains: &[String], organization: Option<&str>, url_id: u64, validity: Option<i64>) -> AuthResult<Row> {
    let Some((key, csr)) = ssl.crypto.key_and_csr(domains, organization) else {
        return Err(err(StatusCode::INTERNAL_SERVER_ERROR, ERROR_KEY_CSR, &[]));
    };
    Ok(json!({"crtKey": key, "organization": organization, "domains": domains.join(","), "urlId": url_id, "validity": validity, "csr": csr})
        .as_object()
        .cloned()
        .unwrap_or_default())
}

/// `loginAndCreateNewOrder`.
async fn new_order(ssl: &Ssl<'_>, request: &Row) -> AuthResult<AcmeOrder> {
    if !ssl.acme.configured() {
        return Err(credentials());
    }
    let domains: Vec<String> = entity::str_of(request, "domains").unwrap_or("").split(',').map(str::to_string).collect();
    ssl.acme.new_order(&domains).await.map_err(|m| issue(&m))
}

/// `loginAndBindOrder`: the stored order, else a new one.
async fn bind_order(s: &AdminState, ssl: &Ssl<'_>, request: &Row) -> AuthResult<AcmeOrder> {
    if !ssl.acme.configured() {
        return Err(credentials());
    }
    let id = entity::u64_of(request, "id").unwrap_or(0);
    let url: Option<Option<String>> = sqlx::query_scalar("SELECT ORDER_URL FROM security_ssl_request WHERE ID = ?").bind(id).fetch_optional(&s.db.pool).await?;
    match url.flatten().filter(|u| !u.trim().is_empty()) {
        None => new_order(ssl, request).await,
        Some(u) => match ssl.acme.bind_order(&u).await {
            Ok(o) => Ok(o),
            Err(e) => {
                tracing::warn!(order_url = %u, error = %e, "could not bind to the stored order, creating a new one");
                new_order(ssl, request).await
            }
        },
    }
}

async fn set_order_url(s: &AdminState, request_id: u64, location: &str) -> AuthResult<()> {
    sqlx::query("UPDATE security_ssl_request SET ORDER_URL = ? WHERE ID = ?").bind(location).bind(request_id).execute(&s.db.pool).await?;
    Ok(())
}

/// `makeSSLChallenge`: the http-01 challenge when offered, else the dns-01 one.
fn challenge_row(request_id: u64, auth: &AcmeAuthorization) -> Row {
    let ch = auth.challenges.iter().find(|c| c.kind == HTTP_01).or_else(|| auth.challenges.iter().find(|c| c.kind == DNS_01));
    json!({
        "challengeType": ch.map(|c| c.kind.clone()),
        "token": ch.map(|c| c.token.clone()),
        "authorization": ch.map(|c| c.authorization.clone()),
        "requestId": request_id,
        "domain": auth.domain,
        "retryCount": 0,
        "status": auth.status,
    })
    .as_object()
    .cloned()
    .unwrap_or_default()
}

/// `createChallenges(sslRequest)`: the request's challenges replaced by a new order's. Without an
/// authority nothing is deleted (see DIFFERENCES.md).
async fn create_challenges_for(s: &AdminState, ssl: &Ssl<'_>, request: &Row) -> AuthResult<Vec<Row>> {
    if !ssl.acme.configured() {
        return Err(credentials());
    }
    let id = entity::u64_of(request, "id").unwrap_or(0);
    sqlx::query("DELETE FROM security_ssl_challenge WHERE REQUEST_ID = ?").bind(id).execute(&s.db.pool).await?;
    let order = new_order(ssl, request).await?;
    set_order_url(s, id, &order.location).await?;
    let mut out = Vec::new();
    for auth in &order.authorizations {
        let row = challenge_row(id, auth);
        let cid = entity::insert(&s.db, &CHALLENGE, &row).await?;
        out.push(entity::read_by_id(&s.db, &CHALLENGE, cid).await?);
    }
    Ok(out)
}

/// `createCertificateRequest(request)`.
pub async fn create_request(s: &AdminState, ca: &ContextAuth, ssl: &Ssl<'_>, req: &OrderRequest) -> AuthResult<Option<Value>> {
    let Some(domains) = &req.domain_names else {
        return Err(AuthError::internal("Cannot invoke \"java.util.List.isEmpty()\" because the return value of \"com.fincity.security.model.SSLCertificateOrderRequest.getDomainNames()\" is null"));
    };
    let Some(url_id) = req.url_id.filter(|_| !domains.is_empty() && domains.iter().all(|d| !d.trim().is_empty())) else {
        return Err(err(StatusCode::BAD_REQUEST, BAD_CERT_REQUEST, &[]));
    };
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_ssl_request WHERE URL_ID = ?").bind(url_id).fetch_one(&s.db.pool).await?;
    if exists != 0 {
        return Err(err(StatusCode::CONFLICT, REQUEST_EXISTING, &[]));
    }
    let url = if ca.is_system_client() {
        String::new()
    } else {
        entity::str_of(&super::urls::read(s, ca, url_id).await?, "urlPattern").unwrap_or("").to_lowercase()
    };
    validate_domain_names(domains, &url)?;
    if !ssl.acme.configured() {
        return Err(credentials());
    }
    let record = make_record(ssl, domains, req.organization_name.as_deref(), url_id, req.validity_in_months)?;
    let id = entity::insert(&s.db, &REQUEST, &record).await?;
    let request = entity::read_by_id(&s.db, &REQUEST, id).await?;
    create_challenges_for(s, ssl, &request).await?;
    let order = order_of_url(s, ca, url_id).await?;
    evict_last_updated(s).await;
    Ok(order)
}

/// `createChallenges(requestId)`.
pub async fn create_challenges(s: &AdminState, ca: &ContextAuth, ssl: &Ssl<'_>, request_id: u64) -> AuthResult<Option<Value>> {
    let request = entity::read_by_id(&s.db, &REQUEST, request_id).await?;
    create_challenges_for(s, ssl, &request).await?;
    let order = order_of_url(s, ca, entity::u64_of(&request, "urlId").unwrap_or(0)).await?;
    evict_last_updated(s).await;
    Ok(order)
}

/// `triggerChallenge(challengeId)`.
pub async fn trigger_challenge(s: &AdminState, ca: &ContextAuth, ssl: &Ssl<'_>, challenge_id: u64) -> AuthResult<Option<Value>> {
    let challenge = entity::read_by_id(&s.db, &CHALLENGE, challenge_id).await?;
    let request = entity::read_by_id(&s.db, &REQUEST, entity::u64_of(&challenge, "requestId").unwrap_or(0)).await?;
    let order = bind_order(s, ssl, &request).await?;
    set_order_url(s, entity::u64_of(&request, "id").unwrap_or(0), &order.location).await?;
    let domain = entity::str_of(&challenge, "domain").unwrap_or("");
    let kind = if entity::str_of(&challenge, "challengeType") == Some(HTTP_01) { HTTP_01 } else { DNS_01 };
    let found = order
        .authorizations
        .iter()
        .filter(|a| a.domain == domain)
        .find_map(|a| a.challenges.iter().find(|c| c.kind == kind));
    let Some(ch) = found else {
        return Err(AuthError::literal(StatusCode::INTERNAL_SERVER_ERROR, "SEC.OBJECT_NOT_FOUND", crate::messages::template(OBJECT_NOT_FOUND))
            .with_param("what", "certificate challenge"));
    };
    let changed = Some(ch.token.as_str()) != entity::str_of(&challenge, "token")
        || Some(ch.authorization.as_str()) != entity::str_of(&challenge, "authorization");
    if changed {
        tracing::warn!(domain, kind, "challenge tokens changed; a published value no longer validates");
        sqlx::query("UPDATE security_ssl_challenge SET TOKEN = ?, AUTHORIZATION = ?, STATUS = 'PENDING', FAILED_REASON = NULL WHERE ID = ?")
            .bind(&ch.token)
            .bind(&ch.authorization)
            .bind(challenge_id)
            .execute(&s.db.pool)
            .await?;
    }
    let (status, error) = ssl.acme.trigger(&order, domain, kind).await.map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, TRIGGER_FAILED, &[]))?;
    ssl.acme.update(&order).await.map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, TRIGGER_FAILED, &[]))?;
    sqlx::query("UPDATE security_ssl_challenge SET STATUS = ?, FAILED_REASON = ?, LAST_VALIDATED_AT = ? WHERE ID = ?")
        .bind(&status)
        .bind(Some(error).filter(|e| !e.trim().is_empty()))
        .bind(s.auth.clock.local())
        .bind(challenge_id)
        .execute(&s.db.pool)
        .await?;
    let out = order_of_url(s, ca, entity::u64_of(&request, "urlId").unwrap_or(0)).await?;
    evict_last_updated(s).await;
    Ok(out)
}

/// `createCertificateInternal(requestId)`: the order finalized with the request's CSR, the
/// certificate stored as current.
pub async fn create_certificate(s: &AdminState, ssl: &Ssl<'_>, request_id: u64) -> AuthResult<bool> {
    let request = entity::read_by_id(&s.db, &REQUEST, request_id).await?;
    let order = bind_order(s, ssl, &request).await?;
    let order = ssl.acme.update(&order).await.map_err(|m| issue(&m))?;
    let order = ssl.acme.finalize(&order, entity::str_of(&request, "csr").unwrap_or("")).await.map_err(|m| issue(&m))?;
    if order.status != "VALID" {
        return Err(issue(&format!("Order status: {}", order.status)));
    }
    let issued = ssl.acme.certificate(&order).await.map_err(|m| issue(&m))?;
    let validity = request.get("validity").and_then(Value::as_i64).unwrap_or(0);
    let renew_till = s.auth.clock.utc() + Duration::days(validity * 30);
    let cert = json!({
        "autoRenewTill": renew_till.and_utc().timestamp(),
        "crt": issued.pem,
        "crtChain": "",
        "crtKey": request.get("crtKey"),
        "csr": request.get("csr"),
        "current": true,
        "domains": request.get("domains"),
        "issuer": issued.issuer.unwrap_or_else(|| "Lets Encrypt".into()),
        "organization": request.get("organization"),
        "urlId": request.get("urlId"),
        "expiryDate": issued.not_after.and_utc().timestamp(),
    });
    insert_certificate(s, cert.as_object().unwrap_or(&Row::new())).await?;
    evict_certificates(s).await;
    Ok(true)
}

/// `deleteRequestByURLId(urlId)`.
pub async fn delete_request(s: &AdminState, ca: &ContextAuth, url_id: u64) -> AuthResult<bool> {
    super::urls::read(s, ca, url_id).await?;
    let n = sqlx::query("DELETE FROM security_ssl_request WHERE URL_ID = ?").bind(url_id).execute(&s.db.pool).await?.rows_affected();
    evict_last_updated(s).await;
    Ok(n == 1)
}

/// `deleteCertificate(id)`.
pub async fn delete_certificate(s: &AdminState, ca: &ContextAuth, id: u64) -> AuthResult<bool> {
    let cert = entity::read_by_id(&s.db, &CERTIFICATE, id).await?;
    super::urls::read(s, ca, entity::u64_of(&cert, "urlId").unwrap_or(0)).await?;
    let n = entity::delete(&s.db, &CERTIFICATE, id).await?;
    evict_last_updated(s).await;
    Ok(n == 1)
}

// ---- renewal ----

/// Let's Encrypt keeps an order about a week; one created within six days is reused.
const ORDER_REUSE_WINDOW_DAYS: i64 = 6;

/// `renewExpiringCertificates(daysBeforeExpiry)`: `SSLCertificateRenewalResult`.
pub async fn renew(s: &AdminState, ca: &ContextAuth, ssl: &Ssl<'_>, days: i64) -> AuthResult<Value> {
    let now = s.auth.clock.utc();
    let sql = format!(
        "SELECT {} FROM security_ssl_certificate WHERE (CURRENT = 1 AND EXPIRY_DATE <= ? AND AUTO_RENEW_TILL IS NOT NULL AND AUTO_RENEW_TILL > ?)",
        CERTIFICATE.select_list()
    );
    let rows = sqlx::query(&sql).bind(now + Duration::days(days)).bind(now).fetch_all(&s.db.pool).await?;
    let (mut renewed, mut failed, mut errors) = (0i64, 0i64, Vec::<String>::new());
    for r in &rows {
        let cert = CERTIFICATE.read_row(r)?;
        let url_id = entity::u64_of(&cert, "urlId").unwrap_or(0);
        let outcome = match renew_one(s, ca, ssl, url_id).await {
            Ok(o) => o,
            Err(e) => {
                tracing::error!(url_id, error = %e, "certificate renewal failed");
                Some((false, Some(format!("urlId={url_id}: {}", e.message()))))
            }
        };
        match outcome {
            None => {}
            Some((true, _)) => renewed += 1,
            Some((false, e)) => {
                failed += 1;
                errors.extend(e);
            }
        }
    }
    Ok(Obj::new().put("renewedCount", renewed).put("failedCount", failed).put("errors", Value::from(errors)).build())
}

/// `renewSingleCertificate`: `None` when the URL has no request (Java's empty answer).
async fn renew_one(s: &AdminState, ca: &ContextAuth, ssl: &Ssl<'_>, url_id: u64) -> AuthResult<Option<(bool, Option<String>)>> {
    let Some(request) = request_by_url(s, url_id).await? else { return Ok(None) };
    let challenges = challenges_of(s, entity::u64_of(&request, "id").unwrap_or(0)).await?;
    let all_http = !challenges.is_empty() && challenges.iter().all(|c| entity::str_of(c, "challengeType") == Some(HTTP_01));
    if !all_http {
        let cutoff = s.auth.clock.local() - Duration::days(ORDER_REUSE_WINDOW_DAYS);
        let usable = challenges
            .iter()
            .filter_map(|c| c.get("createdAt").and_then(Value::as_i64))
            .any(|t| t > cutoff.and_utc().timestamp());
        if usable {
            return Ok(Some((false, None)));
        }
    }
    // Without an authority every path below ends in the credentials error; it is answered before
    // anything is deleted.
    if !ssl.acme.configured() {
        return Err(credentials());
    }
    if all_http {
        match attempt(s, ca, ssl, &request).await {
            Ok(o) => Ok(Some(o)),
            Err(e) => {
                tracing::warn!(url_id, error = %e, "renewal with the existing request failed, trying a new one");
                let fresh = replace_request(s, ssl, url_id, &request).await?;
                Ok(Some(attempt(s, ca, ssl, &fresh).await?))
            }
        }
    } else {
        match create_challenges_for(s, ssl, &request).await {
            Ok(_) => Ok(Some((false, None))),
            Err(e) => {
                tracing::warn!(url_id, error = %e, "challenge creation with the existing request failed, trying a new one");
                let fresh = replace_request(s, ssl, url_id, &request).await?;
                create_challenges_for(s, ssl, &fresh).await?;
                Ok(Some((false, None)))
            }
        }
    }
}

/// The request deleted and made again from its own domains, organization and validity.
async fn replace_request(s: &AdminState, ssl: &Ssl<'_>, url_id: u64, old: &Row) -> AuthResult<Row> {
    sqlx::query("DELETE FROM security_ssl_request WHERE URL_ID = ?").bind(url_id).execute(&s.db.pool).await?;
    let domains: Vec<String> = entity::str_of(old, "domains").unwrap_or("").split(',').map(str::to_string).collect();
    let record = make_record(ssl, &domains, entity::str_of(old, "organization"), url_id, old.get("validity").and_then(Value::as_i64))?;
    let id = entity::insert(&s.db, &REQUEST, &record).await?;
    entity::read_by_id(&s.db, &REQUEST, id).await
}

/// `attemptRenewalWithRequest`: new challenges, the pending ones triggered, the certificate made
/// once all are valid.
async fn attempt(s: &AdminState, ca: &ContextAuth, ssl: &Ssl<'_>, request: &Row) -> AuthResult<(bool, Option<String>)> {
    let challenges = create_challenges_for(s, ssl, request).await?;
    let valid = |c: &Row| entity::str_of(c, "status").is_some_and(|st| st.eq_ignore_ascii_case("VALID"));
    let request_id = entity::u64_of(request, "id").unwrap_or(0);
    let updated = if challenges.iter().all(valid) {
        challenges
    } else {
        for c in challenges.iter().filter(|c| !valid(c)) {
            trigger_challenge(s, ca, ssl, entity::u64_of(c, "id").unwrap_or(0)).await?;
        }
        challenges_of(s, request_id).await?
    };
    if updated.iter().all(valid) {
        create_certificate(s, ssl, request_id).await?;
        return Ok((true, None));
    }
    Ok((false, Some(format!("urlId={}: challenges not all valid after trigger", entity::u64_of(request, "urlId").unwrap_or(0)))))
}

// ---- routes ----

pub fn router() -> Router<AdminState> {
    Router::new()
        .route("/api/security/ssl", get(read_page).post(create_route))
        .route("/api/security/ssl/external", post(external))
        .route("/api/security/ssl/query", post(query))
        .route("/api/security/ssl/certificate", get(certificate_route))
        .route("/api/security/ssl/request", get(read_request).delete(delete_request_route))
        .route("/api/security/ssl/request/challenge", get(trigger_route))
        .route("/api/security/ssl/request/challenges", post(challenges_route))
        .route("/api/security/ssl/token/{token}", get(token_route))
        .route("/api/security/ssl/internal/renew-certificates", post(renew_route))
        .route("/api/security/ssl/{id}", delete(delete_certificate_route))
}

/// `ULong.valueOf(text)` outside the binder: Java's `NumberFormatException` is a 500.
fn ulong(text: &str) -> AuthResult<u64> {
    to_u64(text).map_err(|_| AuthError::internal(format!("For input string: \"{text}\"")))
}

web_route!(create_route, AdminState, "/ssl", true, |s, r, ca| {
    let body = object_body(&r.body)?;
    let req = order_request(&body)?;
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    Ok(match create_request(&s, &ca, &Ssl::unit(), &req).await? {
        Some(v) => json_resp(&v),
        None => web::nothing(),
    })
});

web_route!(external, AdminState, "/ssl/external", true, |s, r, ca| {
    let body = object_body(&r.body)?;
    let cert = CERTIFICATE.from_body(&body, Row::new())?;
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    Ok(json_resp(&CERTIFICATE.to_json(&create_external(&s, &ca, cert).await?, vec![])))
});

web_route!(read_page, AdminState, "/ssl", true, |s, r, ca| {
    let pageable = Pageable::from_params(&r.params);
    let url = r.params.get("urlId").map(ulong).transpose()?;
    let cond = crate::condition::from_params(&r.params.0);
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    Ok(json_resp(&certificates_page(&s, &ca, url, &pageable, cond).await?))
});

web_route!(query, AdminState, "/ssl/query", true, |s, r, ca| {
    let body: Value = crate::handlers::body(&r.body)?;
    let (mut pageable, cond) = web::query_body(&r.body)?;
    // `Query.DEFAULT_SORT` (no sort given) becomes `urlId` descending.
    if body.get("sort").is_none() {
        pageable.sort = vec![SortOrder::new("urlId", false)];
    }
    let Some(cond) = cond else {
        return Err(AuthError::internal("Cannot invoke \"com.fincity.saas.commons.model.condition.AbstractCondition.findConditionWithField(String)\" because the return value of \"com.fincity.saas.commons.model.Query.getCondition()\" is null"));
    };
    let on_url = cond.filters_on("urlId");
    let url = if on_url.len() == 1 {
        match &on_url[0].value {
            Some(v) => Some(ulong(&crate::condition::java_string(v))?),
            None => return Err(AuthError::internal("Cannot invoke \"Object.toString()\" because the return value of \"com.fincity.saas.commons.model.condition.FilterCondition.getValue()\" is null")),
        }
    } else {
        None
    };
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    Ok(json_resp(&certificates_page(&s, &ca, url, &pageable, Some(cond)).await?))
});

web_route!(certificate_route, AdminState, "/ssl/certificate", true, |s, r, ca| {
    let id = req_u64(&r.params, "requestId")?;
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    Ok(super::common::bool_json(create_certificate(&s, &Ssl::unit(), id).await?))
});

web_route!(trigger_route, AdminState, "/ssl/request/challenge", true, |s, r, ca| {
    let id = req_u64(&r.params, "challengeId")?;
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    Ok(match trigger_challenge(&s, &ca, &Ssl::unit(), id).await? {
        Some(v) => json_resp(&v),
        None => web::nothing(),
    })
});

web_route!(read_request, AdminState, "/ssl/request", true, |s, r, ca| {
    let url = req_u64(&r.params, "urlId")?;
    pre_authorize(&ca, "Authorities.Client_UPDATE")?;
    Ok(match order_of_url(&s, &ca, url).await? {
        Some(v) => json_resp(&v),
        None => web::nothing(),
    })
});

web_route!(delete_request_route, AdminState, "/ssl/request", true, |s, r, ca| {
    let url = req_u64(&r.params, "urlId")?;
    Ok(super::common::bool_json(delete_request(&s, &ca, url).await?))
});

web_route_path!(delete_certificate_route, AdminState, "/ssl/{id}", true, |s, r, ca, id| {
    let id = ulong(&id)?;
    Ok(super::common::bool_json(delete_certificate(&s, &ca, id).await?))
});

web_route!(challenges_route, AdminState, "/ssl/request/challenges", true, |s, r, ca| {
    let id = req_u64(&r.params, "requestId")?;
    Ok(match create_challenges(&s, &ca, &Ssl::unit(), id).await? {
        Some(v) => json_resp(&v),
        None => web::nothing(),
    })
});

web_route_path!(token_route, AdminState, "/ssl/token/{token}", false, |s, r, ca, t| {
    Ok(web::text(&token(&s, &t).await?))
});

web_route!(renew_route, AdminState, "/ssl/internal/renew-certificates", false, |s, r, ca| {
    let days = match r.params.get("daysBeforeExpiry") {
        None => 30,
        Some(d) => d.trim().parse::<i32>().map_err(|_| web::type_mismatch())? as i64,
    };
    if !ca.is_system_client() {
        return Err(err(StatusCode::INTERNAL_SERVER_ERROR, ONLY_SYS_USER_CERTS, &[]));
    }
    Ok(json_resp(&renew(&s, &ca, &Ssl::unit(), days).await?))
});

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    #[test]
    fn upload_checks_in_javas_order() {
        let now = at("2026-10-16 00:00:00");
        let msg = |r: AuthResult<()>| r.unwrap_err().message();
        assert_eq!(msg(validate_crt_and_key(Some("c"), None, now)), "Certificate or Key Issue : Key is missing");
        assert_eq!(msg(validate_crt_and_key(None, Some("k"), now)), "Certificate or Key Issue : Certificate is missing");
        assert_eq!(msg(validate_crt_and_key(Some("x"), Some("k"), now)), "Certificate or Key Issue : Error while reading the certificate");
        let n = [0x00, 0xC1, 0x02];
        let expired = x509::tests::fake_cert("250601000000Z", &n, true);
        assert_eq!(msg(validate_crt_and_key(Some(&expired), Some("k"), now)), "Certificate or Key Issue : Certificate is expired");
        let good = x509::tests::fake_cert("491231000000Z", &n, true);
        assert!(validate_crt_and_key(Some(&good), Some(&x509::tests::fake_pkcs1(&n)), now).is_ok());
        assert!(validate_crt_and_key(Some(&good), Some(&x509::tests::fake_pkcs8(&n, true)), now).is_ok());
        assert!(msg(validate_crt_and_key(Some(&good), Some(&x509::tests::fake_pkcs1(&[1])), now)).contains("not based on RSA algorithm"));
        assert_eq!(validate_crt_and_key(Some(&good), Some("garbage"), now).unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            msg(validate_crt_and_key(Some(&good), Some("-----BEGIN X-----\nAAAA\n-----END X-----"), now)),
            "Certificate or Key Issue : Error while reading the key"
        );
    }

    #[test]
    fn domains_and_bodies() {
        let d = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(validate_domain_names(&d(&["a.shop.com", "shop.com"]), "https://shop.com/x").is_ok());
        assert!(validate_domain_names(&d(&["x.other.com"]), "").is_ok());
        let e = validate_domain_names(&d(&["x.other.com"]), "shop.com").unwrap_err();
        assert_eq!(e.message(), "The following domain(s) are not matching with URL :");
        let r = order_request(&json!({"domainNames": ["a.com"], "urlId": "5"})).unwrap();
        assert_eq!((r.url_id, r.validity_in_months), (Some(5), Some(12)));
        assert_eq!(order_request(&json!({"domainNames": "a.com", "validityInMonths": null})).unwrap().validity_in_months, None);
        assert!(order_request(&json!({"domainNames": {}})).is_err());
        assert!(ulong("x").is_err() && ulong("7").unwrap() == 7);
    }

    #[test]
    fn challenges_prefer_http() {
        let auth = AcmeAuthorization {
            domain: "a.com".into(),
            status: "PENDING".into(),
            challenges: vec![
                AcmeChallenge { kind: DNS_01.into(), token: "_acme-challenge.a.com.".into(), authorization: "dig".into(), status: "PENDING".into(), error: None },
                AcmeChallenge { kind: HTTP_01.into(), token: "tok".into(), authorization: "tok.thumb".into(), status: "PENDING".into(), error: None },
            ],
        };
        let r = challenge_row(9, &auth);
        assert_eq!((r["challengeType"].clone(), r["token"].clone(), r["status"].clone()), (json!("http-01"), json!("tok"), json!("PENDING")));
        let only_dns = AcmeAuthorization { challenges: vec![auth.challenges[0].clone()], ..auth };
        assert_eq!(challenge_row(9, &only_dns)["challengeType"], "dns-01");
    }

    #[tokio::test]
    async fn the_unit_has_no_authority() {
        let u = Unavailable;
        assert!(!u.configured());
        assert!(u.new_order(&[]).await.is_err());
        assert!(u.bind_order("x").await.is_err());
        let o = AcmeOrder { location: String::new(), status: String::new(), authorizations: vec![] };
        assert!(u.trigger(&o, "a", HTTP_01).await.is_err());
        assert!(u.update(&o).await.is_err());
        assert!(u.finalize(&o, "").await.is_err());
        assert!(u.certificate(&o).await.is_err());
        assert!(u.key_and_csr(&[], None).is_none());
        let ssl = Ssl::unit();
        assert!(make_record(&ssl, &[], None, 1, Some(12)).is_err());
        assert_eq!(credentials().status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(issue("x").message(), "Lets encrypt connection threw the following error :");
    }

    /// An authority that never leaves the process. By default every challenge passes when
    /// triggered; the switches make it refuse, rename, or answer otherwise.
    struct FakeAcme {
        calls: std::sync::Mutex<Vec<String>>,
        fail_new_order: bool,
        fail_bind: bool,
        /// The domain a bound order answers for (another one: the challenge is not found).
        bind_domain: Option<String>,
        /// Appended to the tokens of a bound order (they changed since the challenge was made).
        bind_suffix: &'static str,
        start_status: &'static str,
        trigger_status: &'static str,
        finalize_status: &'static str,
        kind: &'static str,
    }

    impl FakeAcme {
        fn new() -> Self {
            FakeAcme {
                calls: Default::default(),
                fail_new_order: false,
                fail_bind: false,
                bind_domain: None,
                bind_suffix: "",
                start_status: "PENDING",
                trigger_status: "VALID",
                finalize_status: "VALID",
                kind: HTTP_01,
            }
        }

        fn order(&self, domains: &[String], status: &str, suffix: &str) -> AcmeOrder {
            AcmeOrder {
                location: format!("https://acme.invalid/order/{}", domains.join(",")),
                status: "PENDING".into(),
                authorizations: domains
                    .iter()
                    .map(|d| AcmeAuthorization {
                        domain: d.clone(),
                        status: status.into(),
                        challenges: vec![AcmeChallenge {
                            kind: self.kind.into(),
                            token: format!("tok-{d}{suffix}"),
                            authorization: format!("tok-{d}.thumb{suffix}"),
                            status: status.into(),
                            error: None,
                        }],
                    })
                    .collect(),
            }
        }

        fn log(&self, s: String) {
            self.calls.lock().unwrap().push(s);
        }
    }

    #[async_trait]
    impl Acme for FakeAcme {
        fn configured(&self) -> bool {
            true
        }
        async fn new_order(&self, domains: &[String]) -> Result<AcmeOrder, String> {
            self.log(format!("new {}", domains.join(",")));
            if self.fail_new_order {
                return Err("rate limited".into());
            }
            Ok(self.order(domains, self.start_status, ""))
        }
        async fn bind_order(&self, location: &str) -> Result<AcmeOrder, String> {
            self.log(format!("bind {location}"));
            if self.fail_bind {
                return Err("order gone".into());
            }
            let domains: Vec<String> = match &self.bind_domain {
                Some(d) => vec![d.clone()],
                None => location.rsplit('/').next().unwrap_or("").split(',').map(str::to_string).collect(),
            };
            Ok(self.order(&domains, "PENDING", self.bind_suffix))
        }
        async fn trigger(&self, _: &AcmeOrder, domain: &str, kind: &str) -> Result<(String, String), String> {
            self.log(format!("trigger {domain} {kind}"));
            Ok((self.trigger_status.into(), if self.trigger_status == "VALID" { String::new() } else { "refused".into() }))
        }
        async fn update(&self, order: &AcmeOrder) -> Result<AcmeOrder, String> {
            Ok(order.clone())
        }
        async fn finalize(&self, order: &AcmeOrder, csr: &str) -> Result<AcmeOrder, String> {
            self.log(format!("finalize {csr}"));
            Ok(AcmeOrder { status: self.finalize_status.into(), ..order.clone() })
        }
        async fn certificate(&self, _: &AcmeOrder) -> Result<Issued, String> {
            Ok(Issued {
                pem: "-----BEGIN CERTIFICATE-----\nZZ\n-----END CERTIFICATE-----\n".into(),
                issuer: Some("cn=fake,o=zz".into()),
                not_after: chrono::DateTime::from_timestamp(1_900_000_000, 0).unwrap().naive_utc(),
            })
        }
    }

    struct FakeCrypto;

    impl CertCrypto for FakeCrypto {
        fn key_and_csr(&self, domains: &[String], _: Option<&str>) -> Option<(String, String)> {
            Some(("ZZ KEY".into(), format!("ZZ CSR {}", domains.join(","))))
        }
    }

    fn system_caller() -> ContextAuth {
        ContextAuth {
            authenticated: true,
            client_type_code: Some("SYS".into()),
            client_code: Some("SYSTEM".into()),
            logged_in_from_client_id: Some(1),
            logged_in_from_client_code: Some("SYSTEM".into()),
            user: crate::model::ContextUser { id: Some(142), client_id: Some(1), ..Default::default() },
            ..Default::default()
        }
    }

    /// The whole order flow against a scratch app's URL, with the fakes above (gated like the
    /// other live tests: `SECURITY_AUTH_LIVE=1` and `config/local.toml`).
    #[tokio::test]
    async fn order_flow_with_a_fake_authority() {
        let (Ok(_), Ok(password), Ok(key)) =
            (std::env::var("SECURITY_AUTH_LIVE"), std::env::var("MODLIX__DATABASE__PASSWORD"), std::env::var("MODLIX__JWT__KEY"))
        else {
            return;
        };
        let mut cfg = crate::config::AuthConfig::default();
        cfg.database = platform::config::MySqlConfig { database: "security".into(), password, max_connections: 2, ..Default::default() };
        cfg.jwt.key = key;
        cfg.security.app_code_suffix = ".local".into();
        cfg.security.subdomain_endings = ".local.modlix.com".into();
        cfg.events.publish_events = false;
        let pool = platform::db::mysql_pool(&cfg.database).await.unwrap();
        let s = crate::admin::build(&cfg, pool, platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap(), None).unwrap();
        let ca = system_caller();
        // Leftovers of a run that stopped half-way.
        let left: Vec<u64> = sqlx::query_scalar("SELECT ID FROM security_app WHERE APP_CODE LIKE 'zzrustssl%'").fetch_all(&s.db.pool).await.unwrap();
        for id in left {
            super::super::apps::delete_everything(&s, &ca, id, true).await.unwrap();
        }
        let code = format!("zzrustssl{}", super::super::apps::unique_letters("").chars().take(8).collect::<String>());
        let app = super::super::apps::create(&s, &ca, json!({"appName": "ZZ SSL", "appCode": code, "appUsageType": "B2C"}).as_object().unwrap().clone())
            .await
            .unwrap();
        let app_id = entity::u64_of(&app, "id").unwrap();
        let host = format!("{code}.example.test");
        let url = super::super::urls::create(&s, &ca, json!({"appCode": code, "urlPattern": host}).as_object().unwrap().clone()).await.unwrap().unwrap();
        let url_id = entity::u64_of(&url, "id").unwrap();

        let acme = FakeAcme::new();
        let ssl = Ssl { acme: &acme, crypto: &FakeCrypto };
        let req = OrderRequest { domain_names: Some(vec![host.clone()]), organization_name: Some("ZZ".into()), url_id: Some(url_id), validity_in_months: Some(1) };
        let order = create_request(&s, &ca, &ssl, &req).await.unwrap().unwrap();
        assert_eq!(order["request"]["domains"], host);
        assert!(order["request"].get("crtKey").is_none());
        let ch = &order["challenges"][0];
        assert_eq!((ch["challengeType"].as_str(), ch["status"].as_str()), (Some(HTTP_01), Some("PENDING")));
        assert_eq!(token(&s, ch["token"].as_str().unwrap()).await.unwrap(), format!("tok-{host}.thumb"));
        // A second request on the same URL is refused.
        assert_eq!(create_request(&s, &ca, &ssl, &req).await.unwrap_err().status(), StatusCode::CONFLICT);

        let triggered = trigger_challenge(&s, &ca, &ssl, ch["id"].as_u64().unwrap()).await.unwrap().unwrap();
        assert_eq!(triggered["challenges"][0]["status"], "VALID");
        let request_id = order["request"]["id"].as_u64().unwrap();
        assert!(create_certificate(&s, &ssl, request_id).await.unwrap());
        let page = certificates_page(&s, &ca, Some(url_id), &Pageable::of(0, 10, vec![]), None).await.unwrap();
        assert_eq!(page["totalElements"], 1);
        assert_eq!((page["content"][0]["issuer"].as_str(), page["content"][0]["current"].as_bool()), (Some("cn=fake,o=zz"), Some(true)));

        // Renewal of this URL: new challenges, triggered, a new current certificate.
        assert_eq!(renew_one(&s, &ca, &ssl, url_id).await.unwrap(), Some((true, None)));
        let page = certificates_page(&s, &ca, Some(url_id), &Pageable::of(0, 10, vec![SortOrder::new("id", true)]), None).await.unwrap();
        assert_eq!(page["totalElements"], 2);
        assert_eq!((page["content"][0]["current"].as_bool(), page["content"][1]["current"].as_bool()), (Some(false), Some(true)));
        // An authority refusing new orders: the request is replaced and the error reported.
        let refusing = FakeAcme { fail_new_order: true, ..FakeAcme::new() };
        let ssl2 = Ssl { acme: &refusing, crypto: &FakeCrypto };
        let e = renew_one(&s, &ca, &ssl2, url_id).await.unwrap_err();
        assert_eq!(e.message(), "Lets encrypt connection threw the following error :");
        assert!(create_challenges(&s, &ca, &ssl2, request_id).await.is_err());

        let cert_id = page["content"][0]["id"].as_u64().unwrap();
        assert!(delete_certificate(&s, &ca, cert_id).await.unwrap());

        // No authority: refused before anything changes.
        let unit = Ssl::unit();
        let request = request_by_url(&s, url_id).await.unwrap().unwrap();
        let rid = entity::u64_of(&request, "id").unwrap();
        assert_eq!(new_order(&unit, &request).await.unwrap_err().message(), credentials().message());
        assert!(bind_order(&s, &unit, &request).await.is_err());
        assert!(create_challenges(&s, &ca, &unit, rid).await.is_err());
        // A request with no stored order binds to a new one; a stored order that is gone, too.
        let fresh = replace_request(&s, &ssl, url_id, &request).await.unwrap();
        assert!(bind_order(&s, &ssl, &fresh).await.is_ok());
        let fresh_id = entity::u64_of(&fresh, "id").unwrap();
        let chs = create_challenges(&s, &ca, &ssl, fresh_id).await.unwrap().unwrap();
        let ch_id = chs["challenges"][0]["id"].as_u64().unwrap();
        let gone = FakeAcme { fail_bind: true, ..FakeAcme::new() };
        assert!(bind_order(&s, &Ssl { acme: &gone, crypto: &FakeCrypto }, &fresh).await.is_ok());
        // The authority renamed the challenge since: stored again; another domain: not found.
        let renamed = FakeAcme { bind_suffix: "-2", ..FakeAcme::new() };
        let t = trigger_challenge(&s, &ca, &Ssl { acme: &renamed, crypto: &FakeCrypto }, ch_id).await.unwrap().unwrap();
        assert_eq!(t["challenges"][0]["token"], format!("tok-{host}-2"));
        let elsewhere = FakeAcme { bind_domain: Some("other.example.test".into()), ..FakeAcme::new() };
        assert_eq!(trigger_challenge(&s, &ca, &Ssl { acme: &elsewhere, crypto: &FakeCrypto }, ch_id).await.unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
        // An order that does not finalize.
        let stuck = FakeAcme { finalize_status: "PROCESSING", ..FakeAcme::new() };
        assert_eq!(create_certificate(&s, &Ssl { acme: &stuck, crypto: &FakeCrypto }, fresh_id).await.unwrap_err().message(), issue("").message());
        // Renewal: challenges that stay invalid; challenges valid from the start.
        let invalid = FakeAcme { trigger_status: "INVALID", ..FakeAcme::new() };
        let (ok, why) = renew_one(&s, &ca, &Ssl { acme: &invalid, crypto: &FakeCrypto }, url_id).await.unwrap().unwrap();
        assert!(!ok && why.unwrap().contains("challenges not all valid"));
        let ready = FakeAcme { start_status: "VALID", ..FakeAcme::new() };
        assert_eq!(renew_one(&s, &ca, &Ssl { acme: &ready, crypto: &FakeCrypto }, url_id).await.unwrap(), Some((true, None)));
        // DNS challenges made within the reuse window are left alone.
        let dns = FakeAcme { kind: DNS_01, ..FakeAcme::new() };
        let dns_ssl = Ssl { acme: &dns, crypto: &FakeCrypto };
        let current = request_by_url(&s, url_id).await.unwrap().unwrap();
        create_challenges(&s, &ca, &dns_ssl, entity::u64_of(&current, "id").unwrap()).await.unwrap();
        assert_eq!(renew_one(&s, &ca, &dns_ssl, url_id).await.unwrap(), Some((false, None)));
        assert!(delete_request(&s, &ca, url_id).await.unwrap());
        assert_eq!(renew_one(&s, &ca, &dns_ssl, url_id).await.unwrap(), None);

        // An uploaded certificate and key: stored as the current one.
        let n = [0x00, 0xC1, 0x02];
        let upload = json!({"urlId": url_id, "crt": x509::tests::fake_cert("491231000000Z", &n, true), "crtKeyUpload": x509::tests::fake_pkcs1(&n), "crtChain": "", "csr": "", "domains": host, "issuer": "ZZ", "organization": "ZZ", "expiryDate": 1_900_000_000});
        let made = create_external(&s, &ca, upload.as_object().unwrap().clone()).await.unwrap();
        assert_eq!(made["current"], true);
        let calls = acme.calls.lock().unwrap().clone();
        assert!(calls.iter().any(|c| c.starts_with("finalize ZZ CSR")), "{calls:?}");
        super::super::urls::delete(&s, &ca, url_id).await.unwrap();
        assert!(super::super::apps::delete_everything(&s, &ca, app_id, true).await.unwrap());
    }
}
