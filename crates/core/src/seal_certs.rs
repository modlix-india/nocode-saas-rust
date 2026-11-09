//! A client's own PDF seal certificate, per app (`core_seal_certificates`, `V10__Seal Certificates.sql`).
//!
//! The platform seals PDFs with its own certificate (the pdf-render sidecar's `PDF_SEAL_P12`, see
//! [`crate::pdf_render`]). A client may, per app, have its own instead: one the platform's private
//! document-seal CA makes for it (**generate**: protects the file; readers show "validity unknown" unless
//! they trust that CA) or one it bought from a trusted CA (**upload**: the reader's green tick with its name).
//! [`for_client`] gives the sealing code the client's certificate; without one the platform's is used.
//!
//! **Kept secret.** The `.p12` and its password are encrypted with AES-256-GCM under `[seal]
//! encryption_key` (32 bytes, base64; one per environment, never changed once clients have saved
//! certificates), with the client and app as associated data, so a row copied to another client or app does
//! not open. Nothing reads them back: the API answers only subject, issuer, validity and fingerprint.
//!
//! **Who may change it:** the same rule as the client AI settings: `Authorities.ROLE_Owner`, on a client on
//! the owner side (level `CLIENT` or `SYSTEM`); channel partners and customers never. Anyone signed in to the
//! client may read what is set.
//!
//! Routes (`/api/core/sealCertificates`, `appCode` names the app; the client is the caller's own):
//! - `GET ?appCode=`: `{appCode, clientCode, canEdit, certificate: null | {...}}`;
//! - `POST /generate {appCode, commonName, organization}`: a new certificate from the platform CA;
//! - `POST /upload {appCode, p12 (base64), password}`: the client's own, checked by the sidecar first;
//! - `DELETE ?appCode=`: back to the platform's certificate.

use std::sync::OnceLock;

use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use chrono::NaiveDateTime;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{MySqlPool, Row};

use crate::data_routes::query_params;
use crate::handlers::request_context;
use crate::state::AppState;

/// `[seal]` of the core units: everything secret about seals lives here, in the environment's config
/// (Lighthouse), never on a host or in the sidecar; the core sends a certificate to pdf-render for one call.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SealConfig {
    /// 32 bytes, base64. Empty: clients cannot keep their own certificates on this environment (generate
    /// and upload answer 503); the platform's seal still works.
    pub encryption_key: String,
    /// The platform's seal certificate: a `.p12` as base64, and its password. Empty: the sidecar's own
    /// `PDF_SEAL_P12` if it has one, else no platform seal (PDFs stay as they are).
    pub platform_p12: String,
    pub platform_password: String,
    /// The platform's private document-seal CA (`.p12` base64 + password) that makes clients' certificates
    /// (generate). Empty: clients can only upload their own.
    pub ca_p12: String,
    pub ca_password: String,
    /// An RFC 3161 timestamp server for every seal (usually the CA's). Empty: no trusted timestamp.
    pub tsa_url: String,
}

/// The authority that may change a client's seal certificate (as `AI_SETTINGS_EDIT_AUTHORITIES`).
pub const OWNER: &str = "Authorities.ROLE_Owner";
/// The client levels on the owner side (as nocode-ai `OWNER_SIDE_LEVELS`).
pub const OWNER_SIDE_LEVELS: [&str; 2] = ["CLIENT", "SYSTEM"];

pub struct SealCerts {
    pool: MySqlPool,
    key: Option<LessSafeKey>,
    platform: Option<(Vec<u8>, String)>,
    ca: Option<(Vec<u8>, String)>,
    tsa_url: String,
}

static CERTS: OnceLock<SealCerts> = OnceLock::new();

/// Sets the process's store (once, at startup, after the core pool exists).
pub fn install(pool: MySqlPool, cfg: &SealConfig) -> anyhow::Result<()> {
    let key = key_of(&cfg.encryption_key)?;
    if key.is_none() {
        tracing::info!("seal: no [seal] encryption_key: clients cannot keep their own seal certificates here");
    }
    let platform = p12_of("platform_p12", &cfg.platform_p12, &cfg.platform_password)?;
    let ca = p12_of("ca_p12", &cfg.ca_p12, &cfg.ca_password)?;
    tracing::info!(platform = platform.is_some(), ca = ca.is_some(), tsa = !cfg.tsa_url.trim().is_empty(), "seal: [seal] config");
    let _ = CERTS.set(SealCerts { pool, key, platform, ca, tsa_url: cfg.tsa_url.trim().to_string() });
    Ok(())
}

fn p12_of(name: &str, b64: &str, password: &str) -> anyhow::Result<Option<(Vec<u8>, String)>> {
    let b64: String = b64.split_whitespace().collect();
    if b64.is_empty() {
        return Ok(None);
    }
    let raw = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|e| anyhow::anyhow!("[seal] {name} is not base64: {e}"))?;
    Ok(Some((raw, password.to_string())))
}

/// The platform's seal certificate from `[seal]`, if set.
pub fn platform() -> Option<(Vec<u8>, String)> {
    CERTS.get().and_then(|c| c.platform.clone())
}

/// The platform CA from `[seal]`, if set.
pub fn ca() -> Option<(Vec<u8>, String)> {
    CERTS.get().and_then(|c| c.ca.clone())
}

/// The timestamp server from `[seal]` (empty: none).
pub fn tsa_url() -> String {
    CERTS.get().map(|c| c.tsa_url.clone()).unwrap_or_default()
}

fn key_of(b64: &str) -> anyhow::Result<Option<LessSafeKey>> {
    let b64 = b64.trim();
    if b64.is_empty() {
        return Ok(None);
    }
    let raw = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|e| anyhow::anyhow!("[seal] encryption_key is not base64: {e}"))?;
    let unbound = UnboundKey::new(&AES_256_GCM, &raw).map_err(|_| anyhow::anyhow!("[seal] encryption_key must be 32 bytes"))?;
    Ok(Some(LessSafeKey::new(unbound)))
}

fn aad(client: &str, app: &str) -> Vec<u8> {
    format!("seal-cert|{client}|{app}").into_bytes()
}

/// nonce + ciphertext (with its tag).
fn seal_bytes(key: &LessSafeKey, client: &str, app: &str, plain: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce).map_err(|_| "no randomness".to_string())?;
    let mut buf = plain.to_vec();
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad(client, app)), &mut buf)
        .map_err(|_| "encryption failed".to_string())?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&buf);
    Ok(out)
}

fn open_bytes(key: &LessSafeKey, client: &str, app: &str, stored: &[u8]) -> Result<Vec<u8>, String> {
    if stored.len() < NONCE_LEN {
        return Err("stored value too short".into());
    }
    let (nonce, rest) = stored.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| "bad nonce".to_string())?;
    let mut buf = rest.to_vec();
    let plain = key.open_in_place(nonce, Aad::from(aad(client, app)), &mut buf).map_err(|_| "cannot decrypt (other key, client or app)".to_string())?;
    Ok(plain.to_vec())
}

/// The client's own certificate for the app, decrypted, for one seal: `(p12, password, subject)`. `None`
/// when it has none, when this environment keeps none, or when the row cannot be read (logged): the caller
/// then uses the platform's certificate.
pub async fn for_client(app: &str, client: &str) -> Option<(Vec<u8>, String, String)> {
    let certs = CERTS.get()?;
    let key = certs.key.as_ref()?;
    let row = sqlx::query("SELECT P12, PASSWORD, SUBJECT FROM core_seal_certificates WHERE CLIENT_CODE = ? AND APP_CODE = ?")
        .bind(client)
        .bind(app)
        .fetch_optional(&certs.pool)
        .await;
    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => return None,
        Err(e) => {
            tracing::warn!(error = %e, client, app, "seal: cannot read the client's certificate, using the platform's");
            return None;
        }
    };
    let opened = (|| {
        let p12 = open_bytes(key, client, app, &row.try_get::<Vec<u8>, _>("P12").map_err(|e| e.to_string())?)?;
        let pw = open_bytes(key, client, app, &row.try_get::<Vec<u8>, _>("PASSWORD").map_err(|e| e.to_string())?)?;
        Ok::<_, String>((p12, String::from_utf8(pw).map_err(|e| e.to_string())?, row.try_get::<String, _>("SUBJECT").unwrap_or_default()))
    })();
    match opened {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(error = %e, client, app, "seal: cannot open the client's certificate, using the platform's");
            None
        }
    }
}

// ------------------------------------------------------------------ routes

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/core/sealCertificates", get(read).delete(remove))
        .route("/api/core/sealCertificates/generate", post(generate))
        .route("/api/core/sealCertificates/upload", post(upload))
}

fn answer(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

fn refuse(status: StatusCode, message: &str) -> Response {
    answer(status, json!({"message": message}))
}

struct Caller {
    client: String,
    user: Option<u64>,
    can_edit: bool,
}

async fn caller(st: &AppState, h: &HeaderMap) -> Result<Caller, Response> {
    let ctx = request_context(st, h).await.map_err(IntoResponse::into_response)?;
    if !ctx.auth.is_authenticated() {
        return Err(crate::unmapped::unauthorized());
    }
    let ca = &ctx.auth.ca;
    let client = ca.client_code.clone().unwrap_or_default();
    let level = ca.client_level_type.clone().unwrap_or_default();
    let can_edit = ca.has_authority(OWNER) && OWNER_SIDE_LEVELS.contains(&level.as_str());
    let user = Some(ca.user.id).filter(|id| *id != 0);
    Ok(Caller { client, user, can_edit })
}

fn app_code_of(raw: Option<&str>) -> Option<String> {
    query_params(raw).into_iter().find(|(k, _)| k == "appCode").and_then(|(_, v)| v).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn row_json(r: &sqlx::mysql::MySqlRow) -> Value {
    let dt = |c: &str| r.try_get::<NaiveDateTime, _>(c).map(|d| d.format("%Y-%m-%dT%H:%M:%S").to_string()).unwrap_or_default();
    json!({
        "kind": r.try_get::<String, _>("KIND").unwrap_or_default(),
        "subject": r.try_get::<String, _>("SUBJECT").unwrap_or_default(),
        "issuer": r.try_get::<String, _>("ISSUER").unwrap_or_default(),
        "notBefore": dt("NOT_BEFORE"),
        "notAfter": dt("NOT_AFTER"),
        "fingerprint": r.try_get::<String, _>("FINGERPRINT").unwrap_or_default(),
        "createdAt": r.try_get::<chrono::DateTime<chrono::Utc>, _>("CREATED_AT").map(|d| d.format("%Y-%m-%dT%H:%M:%S").to_string()).unwrap_or_default(),
    })
}

async fn current(pool: &MySqlPool, client: &str, app: &str) -> Result<Value, sqlx::Error> {
    let row = sqlx::query(
        "SELECT KIND, SUBJECT, ISSUER, NOT_BEFORE, NOT_AFTER, FINGERPRINT, CREATED_AT FROM core_seal_certificates WHERE CLIENT_CODE = ? AND APP_CODE = ?",
    )
    .bind(client)
    .bind(app)
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(row_json).unwrap_or(Value::Null))
}

async fn read(State(st): State<AppState>, RawQuery(raw): RawQuery, h: HeaderMap) -> Response {
    let c = match caller(&st, &h).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(app) = app_code_of(raw.as_deref()) else { return refuse(StatusCode::BAD_REQUEST, "appCode is required") };
    let Some(certs) = CERTS.get() else { return refuse(StatusCode::SERVICE_UNAVAILABLE, "seal certificates are not set up here") };
    match current(&certs.pool, &c.client, &app).await {
        Ok(cert) => answer(StatusCode::OK, json!({
            "appCode": app, "clientCode": c.client, "canEdit": c.can_edit,
            "canKeep": certs.key.is_some(), "certificate": cert,
        })),
        Err(e) => {
            tracing::warn!(error = %e, "seal: read failed");
            refuse(StatusCode::INTERNAL_SERVER_ERROR, "could not read the seal certificate")
        }
    }
}

async fn remove(State(st): State<AppState>, RawQuery(raw): RawQuery, h: HeaderMap) -> Response {
    let c = match caller(&st, &h).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !c.can_edit {
        return refuse(StatusCode::FORBIDDEN, "only the owner of the business can change its seal certificate");
    }
    let Some(app) = app_code_of(raw.as_deref()) else { return refuse(StatusCode::BAD_REQUEST, "appCode is required") };
    let Some(certs) = CERTS.get() else { return refuse(StatusCode::SERVICE_UNAVAILABLE, "seal certificates are not set up here") };
    match sqlx::query("DELETE FROM core_seal_certificates WHERE CLIENT_CODE = ? AND APP_CODE = ?").bind(&c.client).bind(&app).execute(&certs.pool).await {
        Ok(r) => answer(StatusCode::OK, json!({"removed": r.rows_affected() > 0})),
        Err(e) => {
            tracing::warn!(error = %e, "seal: delete failed");
            refuse(StatusCode::INTERNAL_SERVER_ERROR, "could not remove the seal certificate")
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateBody {
    app_code: String,
    #[serde(default)]
    common_name: String,
    #[serde(default)]
    organization: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadBody {
    app_code: String,
    p12: String,
    #[serde(default)]
    password: String,
}

async fn generate(State(st): State<AppState>, h: HeaderMap, Json(b): Json<GenerateBody>) -> Response {
    let c = match caller(&st, &h).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !c.can_edit {
        return refuse(StatusCode::FORBIDDEN, "only the owner of the business can change its seal certificate");
    }
    let app = b.app_code.trim().to_string();
    let cn = b.common_name.trim().to_string();
    if app.is_empty() || cn.is_empty() {
        return refuse(StatusCode::BAD_REQUEST, "appCode and commonName are required");
    }
    match crate::pdf_render::issue_cert(&cn, b.organization.trim()).await {
        Ok((p12, password, info)) => save(&c, &app, "GENERATED", &p12, &password, &info).await,
        Err(crate::pdf_render::CertError::NotConfigured) => {
            refuse(StatusCode::SERVICE_UNAVAILABLE, "certificates cannot be generated on this environment yet (no platform CA)")
        }
        Err(crate::pdf_render::CertError::Refused(m)) => refuse(StatusCode::BAD_REQUEST, &m),
        Err(crate::pdf_render::CertError::Failed(m)) => {
            tracing::warn!(error = %m, "seal: generate failed");
            refuse(StatusCode::BAD_GATEWAY, "could not generate the certificate; try again")
        }
    }
}

async fn upload(State(st): State<AppState>, h: HeaderMap, Json(b): Json<UploadBody>) -> Response {
    let c = match caller(&st, &h).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !c.can_edit {
        return refuse(StatusCode::FORBIDDEN, "only the owner of the business can change its seal certificate");
    }
    let app = b.app_code.trim().to_string();
    // a data URL from a file picker, or plain base64
    let b64 = b.p12.split_once("base64,").map(|(_, r)| r).unwrap_or(&b.p12).trim();
    let p12 = match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(v) if !v.is_empty() && v.len() <= 64 * 1024 => v,
        _ => return refuse(StatusCode::BAD_REQUEST, "the file must be a .p12 or .pfx (at most 64 KB)"),
    };
    if app.is_empty() {
        return refuse(StatusCode::BAD_REQUEST, "appCode is required");
    }
    match crate::pdf_render::inspect_cert(&p12, &b.password).await {
        Ok(info) => save(&c, &app, "UPLOADED", &p12, &b.password, &info).await,
        Err(crate::pdf_render::CertError::Refused(m)) => refuse(StatusCode::BAD_REQUEST, &m),
        Err(crate::pdf_render::CertError::NotConfigured) => refuse(StatusCode::SERVICE_UNAVAILABLE, "the PDF service is not set up here"),
        Err(crate::pdf_render::CertError::Failed(m)) => {
            tracing::warn!(error = %m, "seal: inspect failed");
            refuse(StatusCode::BAD_GATEWAY, "could not check the certificate; try again")
        }
    }
}

fn utc(s: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").ok()
}

async fn save(c: &Caller, app: &str, kind: &str, p12: &[u8], password: &str, info: &Value) -> Response {
    let Some(certs) = CERTS.get() else { return refuse(StatusCode::SERVICE_UNAVAILABLE, "seal certificates are not set up here") };
    let Some(key) = certs.key.as_ref() else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "this environment cannot keep certificates yet (no encryption key)");
    };
    let s = |k: &str| info.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let (Some(nb), Some(na)) = (utc(&s("notBefore")), utc(&s("notAfter"))) else {
        return refuse(StatusCode::BAD_GATEWAY, "the certificate's dates could not be read");
    };
    let (Ok(p12_enc), Ok(pw_enc)) = (seal_bytes(key, &c.client, app, p12), seal_bytes(key, &c.client, app, password.as_bytes())) else {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "could not keep the certificate");
    };
    let q = sqlx::query(
        "INSERT INTO core_seal_certificates (CLIENT_CODE, APP_CODE, KIND, SUBJECT, ISSUER, NOT_BEFORE, NOT_AFTER, FINGERPRINT, P12, PASSWORD, CREATED_BY) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE KIND = VALUES(KIND), SUBJECT = VALUES(SUBJECT), ISSUER = VALUES(ISSUER), NOT_BEFORE = VALUES(NOT_BEFORE), \
         NOT_AFTER = VALUES(NOT_AFTER), FINGERPRINT = VALUES(FINGERPRINT), P12 = VALUES(P12), PASSWORD = VALUES(PASSWORD), \
         CREATED_BY = VALUES(CREATED_BY), CREATED_AT = CURRENT_TIMESTAMP",
    )
    .bind(&c.client)
    .bind(app)
    .bind(kind)
    .bind(s("subject"))
    .bind(s("issuer"))
    .bind(nb)
    .bind(na)
    .bind(s("fingerprint"))
    .bind(p12_enc)
    .bind(pw_enc)
    .bind(c.user)
    .execute(&certs.pool)
    .await;
    if let Err(e) = q {
        tracing::warn!(error = %e, "seal: save failed");
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "could not keep the certificate");
    }
    match current(&certs.pool, &c.client, app).await {
        Ok(cert) => answer(StatusCode::OK, json!({"appCode": app, "clientCode": c.client, "canEdit": true, "canKeep": true, "certificate": cert})),
        Err(_) => answer(StatusCode::OK, json!({"saved": true})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> LessSafeKey {
        key_of(&base64::engine::general_purpose::STANDARD.encode([7u8; 32])).unwrap().unwrap()
    }

    #[test]
    fn encrypted_values_open_only_for_their_client_and_app() {
        let k = key();
        let enc = seal_bytes(&k, "FIN", "cxzump", b"secret p12").unwrap();
        assert_ne!(&enc[NONCE_LEN..], b"secret p12");
        assert_eq!(open_bytes(&k, "FIN", "cxzump", &enc).unwrap(), b"secret p12");
        assert!(open_bytes(&k, "OTHER", "cxzump", &enc).is_err(), "another client cannot open it");
        assert!(open_bytes(&k, "FIN", "leadzump", &enc).is_err(), "another app cannot open it");
        let other = key_of(&base64::engine::general_purpose::STANDARD.encode([8u8; 32])).unwrap().unwrap();
        assert!(open_bytes(&other, "FIN", "cxzump", &enc).is_err(), "another key cannot open it");
        assert_ne!(seal_bytes(&k, "FIN", "cxzump", b"x").unwrap(), seal_bytes(&k, "FIN", "cxzump", b"x").unwrap(), "fresh nonce each time");
    }

    #[test]
    fn the_key_must_be_32_bytes_of_base64() {
        assert!(key_of("").unwrap().is_none());
        assert!(key_of("not base64!").is_err());
        assert!(key_of(&base64::engine::general_purpose::STANDARD.encode([1u8; 16])).is_err());
        assert!(key_of(&base64::engine::general_purpose::STANDARD.encode([1u8; 32])).unwrap().is_some());
    }

    #[test]
    fn owner_side_rule_matches_ai_settings() {
        assert_eq!(OWNER, "Authorities.ROLE_Owner");
        assert!(OWNER_SIDE_LEVELS.contains(&"CLIENT") && OWNER_SIDE_LEVELS.contains(&"SYSTEM"));
        assert!(!OWNER_SIDE_LEVELS.contains(&"CUSTOMER"));
    }
}
