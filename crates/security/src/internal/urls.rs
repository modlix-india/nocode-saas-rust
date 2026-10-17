//! `ClientUrlService.getAppUrl` / `getAppUrlInternal` and the draft-token check.

use axum::http::StatusCode;
use serde_json::Value;

use super::Internal;
use crate::errors::{AuthError, AuthResult, MANDATORY_APP_CODE};
use crate::model::ContextAuth;

/// `AppService.APP_PROP_URL`.
pub const APP_PROP_URL: &str = "URL";
const HTTPS: &str = "https://";

/// `(allowed, expiresAtEpochSeconds, appCode, clientCode)`, as the tuple is written.
pub fn draft_tuple(allowed: bool, expiry: &str, app_code: &str, client_code: &str) -> Value {
    Value::Array(vec![Value::Bool(allowed), Value::from(expiry), Value::from(app_code), Value::from(client_code)])
}

pub fn draft_denied() -> Value {
    draft_tuple(false, "0", "", "")
}

/// `ClientUrlService.draftTokenFromHost`: the token in a `t-<32 hex>` first label.
pub fn draft_token_from_host(host: &str) -> Option<&str> {
    if host.trim().is_empty() {
        return None;
    }
    let label = host.split('.').next().unwrap_or(host);
    let token = label.strip_prefix("t-")?;
    (token.len() == 32 && token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))).then_some(token)
}

/// `ClientUrlService.trimBackSlash`, including its reach into the untrimmed string.
fn trim_back_slash(s: &str) -> AuthResult<String> {
    if s.trim().is_empty() {
        return Ok(s.to_string());
    }
    let n: Vec<char> = s.trim().chars().collect();
    if n.last() != Some(&'/') {
        return Ok(n.iter().collect());
    }
    let orig: Vec<char> = s.chars().collect();
    let mut end = orig.len() as isize - 1;
    while end >= 0 && orig[end as usize] == '/' {
        end -= 1;
    }
    let to = (end + 1) as usize;
    if to > n.len() {
        return Err(AuthError::internal(format!("begin 0, end {to}, length {}", n.len())));
    }
    Ok(n[..to].iter().collect())
}

/// `ClientUrlService.checkUrl`: no trailing slashes, and `https://` in front.
pub fn check_url(url: &str) -> AuthResult<String> {
    if url.trim().is_empty() {
        return Ok(url.to_string());
    }
    let n = trim_back_slash(url)?;
    Ok(if n.starts_with(HTTPS) { n } else { format!("{HTTPS}{n}") })
}

impl Internal {
    /// `AppService.getProperties(clientId, appId, appCode, URL)` narrowed to what `getAppUrl`
    /// reads: the client's own URL property when the caller may read it.
    async fn url_property(&self, ca: &ContextAuth, app: &crate::model::App, client_id: u64) -> AuthResult<Option<Option<String>>> {
        let ids = if ca.is_system_client() || ca.user.client_id() == client_id {
            vec![client_id]
        } else if self.caller_manages_client(ca, client_id).await? {
            vec![client_id]
        } else {
            return Ok(None);
        };
        let props = self.db.app_properties(app, APP_PROP_URL, &ids, ca.is_system_client()).await?;
        Ok(props.into_iter().find(|p| p.client_id == client_id).map(|p| p.value))
    }

    /// `getAppUrlInternal(appCode, appId, clientId)`: the URL property, else the newest LIVE URL,
    /// as `checkUrl` writes it; `""` when there is none.
    pub async fn app_url_for(&self, ca: &ContextAuth, app: &crate::model::App, client_id: u64) -> AuthResult<String> {
        let url = match self.url_property(ca, app, client_id).await? {
            Some(Some(v)) => Some(v),
            Some(None) => return Err(AuthError::internal("The mapper returned a null value.")),
            None => self.db.latest_client_url(&app.app_code, Some(client_id)).await?,
        };
        match url {
            Some(u) => check_url(&u),
            None => Ok(String::new()),
        }
    }

    /// `ClientUrlService.getAppUrl(appCode, clientCode)`.
    pub async fn app_url(&self, ca: &ContextAuth, app_code: Option<&str>, client_code: Option<&str>) -> AuthResult<String> {
        let Some(app_code) = app_code.filter(|a| !a.trim().is_empty()) else {
            return Err(AuthError::msg(StatusCode::BAD_REQUEST, MANDATORY_APP_CODE, &[]));
        };
        let Some(app) = self.dir().app_by_code(app_code).await? else { return Ok(String::new()) };
        let code = match client_code.filter(|c| !c.trim().is_empty()) {
            Some(c) => Some(c.to_string()),
            None => ca.url_client_code.clone().or_else(|| ca.logged_in_from_client_code.clone()),
        };
        let Some(code) = code else { return Ok(String::new()) };
        let Some(client) = self.client_by_code(&code).await? else { return Ok(String::new()) };
        self.app_url_for(ca, &app, client.id()).await
    }

    /// `ClientUrlService.resolveDraftToken`: any failure is a plain refusal.
    pub async fn resolve_draft_token(&self, host: &str, app_code: &str, client_code: &str) -> Value {
        self.try_resolve_draft_token(host, app_code, client_code).await.unwrap_or_else(|_| draft_denied())
    }

    async fn try_resolve_draft_token(&self, host: &str, app_code: &str, client_code: &str) -> AuthResult<Value> {
        let Some(token) = draft_token_from_host(host) else { return Ok(draft_denied()) };
        let Some(row) = self.db.draft_token(token).await? else { return Ok(draft_denied()) };
        if row.expires_at < self.auth.clock.utc() {
            return Ok(draft_denied());
        }
        if !app_code.trim().is_empty() && !row.app_code.eq_ignore_ascii_case(app_code) {
            return Ok(draft_denied());
        }
        let expiry = row.expires_at.and_utc().timestamp().to_string();
        let Some(minting) = self.dir().client(row.client_id).await? else { return Ok(draft_denied()) };
        if client_code.trim().is_empty() {
            return Ok(draft_tuple(true, &expiry, &row.app_code, minting.code()));
        }
        let Some(requested) = self.client_by_code(client_code).await? else { return Ok(draft_denied()) };
        Ok(if self.is_client_being_managed_by(row.client_id, requested.id()).await? {
            draft_tuple(true, &expiry, &row.app_code, client_code)
        } else {
            draft_denied()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_hosts() {
        let t = "0123456789abcdef0123456789abcdef";
        assert_eq!(draft_token_from_host(&format!("t-{t}.local.modlix.com")), Some(t));
        assert_eq!(draft_token_from_host(&format!("t-{t}")), Some(t));
        assert_eq!(draft_token_from_host("t-0123456789ABCDEF0123456789abcdef.x"), None);
        assert_eq!(draft_token_from_host("t-0123.x"), None);
        assert_eq!(draft_token_from_host("app.local"), None);
        assert_eq!(draft_token_from_host(" "), None);
        assert_eq!(draft_denied(), serde_json::json!([false, "0", "", ""]));
    }

    #[test]
    fn urls_like_check_url() {
        assert_eq!(check_url("appbuilder.dev.modlix.com").unwrap(), "https://appbuilder.dev.modlix.com");
        assert_eq!(check_url("https://a.com///").unwrap(), "https://a.com");
        assert_eq!(check_url("http://a.com").unwrap(), "https://http://a.com");
        assert_eq!(check_url("  ").unwrap(), "  ");
        // Java counts from the end of the untrimmed string: a leading space keeps one slash,
        // a trailing one runs past the end.
        assert_eq!(check_url(" a.com/").unwrap(), "https://a.com/");
        assert!(check_url("a.com/ ").is_err());
        assert!(check_url(" http://a.com/ ").is_err());
    }
}

#[cfg(test)]
mod live {
    use super::*;
    use crate::admin::users::testkit::{caller, fx, sys};

    #[test]
    fn blank_slashes() {
        assert_eq!(trim_back_slash("  ").unwrap(), "  ");
    }

    /// `ClientUrlServiceTest`'s draft tokens and URL properties, keyed to the scratch clients.
    #[tokio::test]
    async fn draft_tokens_and_url_properties() {
        let Some(fx) = fx().await else { return };
        let s = &fx.s;
        let a = fx.user(fx.c, "a").await;
        let token = |n: u8| format!("{:032x}", u128::from(n) + (fx.run.parse::<u128>().unwrap() << 8));
        let insert = |t: String, app: &'static str, minutes: i64| {
            let pool = s.db.pool.clone();
            let (c, u) = (fx.c, a.id);
            async move {
                sqlx::query("INSERT INTO security_draft_token (TOKEN, APP_CODE, CLIENT_ID, USER_ID, EXPIRES_AT) VALUES (?, ?, ?, ?, UTC_TIMESTAMP() + INTERVAL ? MINUTE)")
                    .bind(t)
                    .bind(app)
                    .bind(c)
                    .bind(u)
                    .bind(minutes)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
        };
        let (live, expired) = (token(1), token(2));
        insert(live.clone(), "appbuilder", 30).await;
        insert(expired.clone(), "appbuilder", -30).await;
        let host = |t: &str| format!("t-{t}.local.modlix.com");
        let granted = |v: &Value| v.to_string().contains("true");
        assert!(!granted(&s.resolve_draft_token(&host(&expired), "", "").await));
        assert!(!granted(&s.resolve_draft_token(&host(&live), "leadzump", "").await));
        let mine = s.resolve_draft_token(&host(&live), "appbuilder", "").await;
        assert!(granted(&mine) && mine.to_string().contains("ZZRUL"), "{mine}");
        assert!(granted(&s.resolve_draft_token(&host(&live), "APPBUILDER", "ZZRUM").await), "a client ZZRUL manages");
        assert!(!granted(&s.resolve_draft_token(&host(&live), "", "SYSTEM").await));
        assert!(!granted(&s.resolve_draft_token(&host(&live), "", "NOSUCH").await));
        assert!(!granted(&s.resolve_draft_token(&host(&token(3)), "", "").await), "no such token");
        // A URL property: a client's own caller and a managing caller read it; null is Java's
        // mapper failure.
        let app = s.dir().app_by_code("appbuilder").await.unwrap().unwrap();
        sqlx::query("INSERT INTO security_app_property (APP_ID, CLIENT_ID, NAME, VALUE) VALUES (2, ?, 'URL', 'zzrul.example.test/')")
            .bind(fx.m)
            .execute(&s.db.pool)
            .await
            .unwrap();
        let owner = caller(a.id, fx.c, "ZZRUL", "BUS", &["Authorities.ROLE_Owner"]);
        assert_eq!(s.app_url_for(&owner, &app, fx.m).await.unwrap(), "https://zzrul.example.test");
        let below = caller(0, fx.m, "ZZRUM", "BUS", &[]);
        assert_eq!(s.app_url_for(&below, &app, fx.m).await.unwrap(), "https://zzrul.example.test");
        let outsider = caller(0, fx.i, "ZZRUI", "BUS", &[]);
        assert_eq!(s.app_url_for(&outsider, &app, fx.m).await.unwrap(), "", "no URL of its own, no property it may read");
        sqlx::query("INSERT INTO security_app_property (APP_ID, CLIENT_ID, NAME, VALUE) VALUES (2, ?, 'URL', NULL)").bind(fx.c).execute(&s.db.pool).await.unwrap();
        assert_eq!(s.app_url_for(&sys(), &app, fx.c).await.unwrap_err().status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        fx.finish().await;
    }
}
