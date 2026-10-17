//! `ClientUrlDAO`, `DraftTokenDAO` and `SSLCertificateDAO` reads.

use chrono::NaiveDateTime;
use sqlx::Row;

use super::Db;
use crate::errors::AuthResult;
use crate::mysql::ts;

/// A `security_draft_token` row.
#[derive(Debug, Clone)]
pub struct DraftToken {
    pub app_code: String,
    pub client_id: u64,
    pub expires_at: NaiveDateTime,
}

/// `SSLCertificateConfiguration`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateConfig {
    pub url: Option<String>,
    pub client_code: Option<String>,
    pub app_code: Option<String>,
    pub private_key: Option<String>,
    pub certificate: Option<String>,
}

impl CertificateConfig {
    pub fn to_json(&self) -> serde_json::Value {
        use crate::jackson::{opt, Obj};
        Obj::new()
            .put("url", opt(self.url.clone()))
            .put("clientCode", opt(self.client_code.clone()))
            .put("appCode", opt(self.app_code.clone()))
            .put("privateKey", opt(self.private_key.clone()))
            .put("certificate", opt(self.certificate.clone()))
            .build()
    }
}

/// The host of a URL pattern: after `//`, before `:`.
pub fn pattern_host(pattern: &str) -> String {
    let mut p = pattern;
    if let Some(i) = p.find("//") {
        p = &p[i + 2..];
    }
    if let Some(i) = p.find(':') {
        p = &p[..i];
    }
    p.to_string()
}

/// The certificate followed by its chain, as nginx wants it; none without a chain.
pub fn full_chain(crt: Option<&str>, chain: Option<&str>) -> Option<String> {
    let chain = chain?;
    let crt = crt.unwrap_or("null");
    Some(format!("{crt}{}{chain}", if crt.ends_with('\n') { "" } else { "\n" }))
}

impl Db {
    /// `ClientUrlDAO.getLatestClientUrlBasedOnAppAndClient`: the newest LIVE URL.
    pub async fn latest_client_url(&self, app_code: &str, client_id: Option<u64>) -> AuthResult<Option<String>> {
        let mut qb = sqlx::QueryBuilder::<sqlx::MySql>::new("SELECT URL_PATTERN FROM security_client_url WHERE APP_CODE = ");
        qb.push_bind(app_code.to_string()).push(" AND URL_TYPE = 'LIVE'");
        if let Some(id) = client_id {
            qb.push(" AND CLIENT_ID = ").push_bind(id);
        }
        qb.push(" ORDER BY UPDATED_AT DESC LIMIT 1");
        let row = qb.build().fetch_optional(&self.pool).await?;
        row.map(|r| r.try_get::<String, _>(0)).transpose().map_err(Into::into)
    }

    /// `DraftTokenDAO.readByToken`.
    pub async fn draft_token(&self, token: &str) -> AuthResult<Option<DraftToken>> {
        let row = sqlx::query("SELECT APP_CODE, CLIENT_ID, EXPIRES_AT FROM security_draft_token WHERE TOKEN = ? LIMIT 1")
            .bind(token)
            .fetch_optional(&self.pool)
            .await?;
        let Some(r) = row else { return Ok(None) };
        let Some(expires_at) = ts(&r, "EXPIRES_AT")? else { return Ok(None) };
        Ok(Some(DraftToken { app_code: r.try_get("APP_CODE")?, client_id: r.try_get("CLIENT_ID")?, expires_at }))
    }

    /// `SSLCertificateDAO.readAllCertificates`: every URL with its current certificate, if any.
    pub async fn certificates(&self) -> AuthResult<Vec<CertificateConfig>> {
        let rows = sqlx::query(
            "SELECT security_ssl_certificate.CRT, security_ssl_certificate.CRT_KEY, security_ssl_certificate.CRT_CHAIN, \
             security_client_url.APP_CODE, security_client_url.URL_PATTERN, security_client.CODE FROM security_client_url \
             LEFT JOIN security_ssl_certificate ON security_client_url.ID = security_ssl_certificate.URL_ID \
             LEFT JOIN security_client ON security_client.ID = security_client_url.CLIENT_ID \
             WHERE (security_ssl_certificate.CURRENT = 1 OR security_ssl_certificate.CURRENT IS NULL)",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let crt: Option<String> = r.try_get(0)?;
                let chain: Option<String> = r.try_get(2)?;
                let pattern: Option<String> = r.try_get(4)?;
                Ok(CertificateConfig {
                    url: pattern.as_deref().map(pattern_host),
                    client_code: r.try_get(5)?,
                    app_code: r.try_get(3)?,
                    private_key: r.try_get(1)?,
                    certificate: full_chain(crt.as_deref(), chain.as_deref()),
                })
            })
            .collect()
    }

    /// `SSLCertificateDAO.getLastUpdated`: the newer of the last certificate and the last URL
    /// change, in epoch seconds; empty when neither table has rows.
    pub async fn certificates_last_updated(&self) -> AuthResult<String> {
        let one = |sql: &'static str| async move {
            let row = sqlx::query(sql).fetch_optional(&self.pool).await?;
            Ok::<_, crate::errors::AuthError>(match row {
                Some(r) => ts(&r, "UPDATED_AT")?,
                None => None,
            })
        };
        let cert = one("SELECT UPDATED_AT FROM security_ssl_certificate ORDER BY UPDATED_AT DESC LIMIT 1").await?;
        let url = one("SELECT UPDATED_AT FROM security_client_url ORDER BY UPDATED_AT DESC LIMIT 1").await?;
        Ok(last_updated(cert, url))
    }
}

/// Java's choice between the two times. A certificate without any URL is a
/// `NullPointerException` there; here it is the certificate's time.
pub fn last_updated(cert: Option<NaiveDateTime>, url: Option<NaiveDateTime>) -> String {
    let secs = |t: NaiveDateTime| t.and_utc().timestamp();
    match (cert, url) {
        (None, None) => String::new(),
        (None, Some(u)) => secs(u).to_string(),
        (Some(c), None) => secs(c).to_string(),
        (Some(c), Some(u)) => secs(c).max(secs(u)).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_shapes() {
        assert_eq!(pattern_host("https://a.b.com:443"), "a.b.com");
        assert_eq!(pattern_host("a.b.com"), "a.b.com");
        assert_eq!(full_chain(Some("CRT"), Some("CHAIN")).as_deref(), Some("CRT\nCHAIN"));
        assert_eq!(full_chain(Some("CRT\n"), Some("CHAIN")).as_deref(), Some("CRT\nCHAIN"));
        assert_eq!(full_chain(Some("CRT"), None), None);
        let at = |s: i64| chrono::DateTime::from_timestamp(s, 0).unwrap().naive_utc();
        assert_eq!(last_updated(None, None), "");
        assert_eq!(last_updated(None, Some(at(5))), "5");
        assert_eq!(last_updated(Some(at(7)), None), "7");
        assert_eq!(last_updated(Some(at(7)), Some(at(9))), "9");
        let c = CertificateConfig { url: Some("a".into()), ..Default::default() };
        assert_eq!(c.to_json(), serde_json::json!({"url": "a"}));
    }
}
