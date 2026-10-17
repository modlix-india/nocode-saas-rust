//! `AnalyticsService`: the dashboard's query proxy to the analytics engine. The caller must be
//! signed in, hold `Authorities.Application_UPDATE`, have write access to the app (as its own
//! client), manage the requested client, and the app must have analytics enabled. The site the
//! engine is asked about is always computed here, never taken from the body.

use axum::http::StatusCode;
use futures::future::BoxFuture;
use overridable::{JMap, JValue};
use platform::error::AppError;
use platform::security::{ContextAuthentication, SecurityClient};

use crate::authority::has_authority;

pub const CACHE_NAME_ANALYTICS_QUERY: &str = "analyticsQueryCache";
pub const AUTHORITY_APPLICATION_UPDATE: &str = "Authorities.Application_UPDATE";
pub const FALLBACK_TIME_ZONE: &str = "Asia/Kolkata";

/// The refusals' message keys (`UIMessageResourceService`; codes `UI.ANALYTICS_*`).
pub use crate::catalogue::{
    ANALYTICS_CLIENT_NOT_MANAGED as CLIENT_NOT_MANAGED, ANALYTICS_CODES_REQUIRED as CODES_REQUIRED, ANALYTICS_LOGIN_REQUIRED as LOGIN_REQUIRED,
    ANALYTICS_NOT_CONFIGURED as NOT_CONFIGURED, ANALYTICS_NOT_ENABLED as NOT_ENABLED, ANALYTICS_NO_WRITE_ACCESS as NO_WRITE_ACCESS,
    ANALYTICS_UNKNOWN_TIMEZONE as UNKNOWN_TIMEZONE,
};

/// `siteKey`: the engine's spelling, app lower case and client upper.
pub fn site_key(app_code: &str, client_code: &str) -> String {
    format!("{}_{}", app_code.to_lowercase(), client_code.to_uppercase())
}

/// `ZoneOffset.of`: `Z`, `+h`, `+hh`, `+hh:mm`, `+hhmm`, `+hh:mm:ss`, `+hhmmss`, within ±18:00.
fn offset_ok(s: &str) -> bool {
    if s == "Z" {
        return true;
    }
    let Some(rest) = s.strip_prefix(['+', '-']) else { return false };
    let num = |t: &str| -> Option<u32> { (t.len() == 2 && t.bytes().all(|b| b.is_ascii_digit())).then(|| t.parse().ok())? };
    let (h, m, sec) = match rest.len() {
        1 if rest.bytes().all(|b| b.is_ascii_digit()) => (rest.parse().unwrap_or(99), 0, 0),
        2 => match num(rest) {
            Some(h) => (h, 0, 0),
            None => return false,
        },
        4 => match (num(&rest[..2]), num(&rest[2..])) {
            (Some(h), Some(m)) => (h, m, 0),
            _ => return false,
        },
        5 if &rest[2..3] == ":" => match (num(&rest[..2]), num(&rest[3..])) {
            (Some(h), Some(m)) => (h, m, 0),
            _ => return false,
        },
        6 => match (num(&rest[..2]), num(&rest[2..4]), num(&rest[4..])) {
            (Some(h), Some(m), Some(x)) => (h, m, x),
            _ => return false,
        },
        8 if &rest[2..3] == ":" && &rest[5..6] == ":" => match (num(&rest[..2]), num(&rest[3..5]), num(&rest[6..])) {
            (Some(h), Some(m), Some(x)) => (h, m, x),
            _ => return false,
        },
        _ => return false,
    };
    h <= 18 && m < 60 && sec < 60 && (h < 18 || (m == 0 && sec == 0))
}

/// `ZoneId.of(zone)` succeeds: a tz database region, an offset, or `UTC`/`GMT`/`UT` with an
/// optional offset.
pub fn is_valid_zone(zone: &str) -> bool {
    if zone.parse::<chrono_tz::Tz>().is_ok() || offset_ok(zone) {
        return true;
    }
    for prefix in ["UTC", "GMT", "UT"] {
        if let Some(rest) = zone.strip_prefix(prefix) {
            if rest.is_empty() || (rest.starts_with(['+', '-']) && offset_ok(rest)) {
                return true;
            }
        }
    }
    false
}

/// The zone the request names, if it names one (`Err` with the zone when it is not usable).
pub fn requested_zone(body: &JMap) -> Option<Result<String, String>> {
    let requested = body.get("timezone").filter(|v| !v.is_null())?;
    let text = requested.java_to_string();
    if text.trim().is_empty() {
        return None;
    }
    let zone = text.trim().to_string();
    Some(if is_valid_zone(&zone) { Ok(zone) } else { Err(zone) })
}

/// The client record's zone, or the fallback when it is missing or unusable.
pub fn client_zone(client: Option<&serde_json::Value>) -> String {
    match client.and_then(|c| c.get("timeZone")).and_then(serde_json::Value::as_str) {
        Some(z) if !z.trim().is_empty() && is_valid_zone(z) => z.to_string(),
        _ => FALLBACK_TIME_ZONE.to_string(),
    }
}

/// `engineRequest`: the body as sent, `site` and `timezone` overwritten.
pub fn engine_request(body: &JMap, app_code: &str, client_code: &str, zone: &str) -> JMap {
    let mut r = body.clone();
    r.insert("site".into(), JValue::Str(site_key(app_code, client_code)));
    r.insert("timezone".into(), JValue::Str(zone.to_string()));
    r
}

/// `isAnalyticsEnabled`: `properties.analytics.enabled` is `true`.
pub fn analytics_enabled(app: &JMap) -> bool {
    app.get("properties")
        .and_then(JValue::as_object)
        .and_then(|p| p.get("analytics"))
        .and_then(JValue::as_object)
        .and_then(|a| a.get("enabled"))
        == Some(&JValue::Bool(true))
}

/// `resolveTimeZone` once the client record is known (`client` is `getClientByCode`'s answer):
/// the request's zone, then the client's, then Asia/Kolkata. `Err` is the 400 for a requested
/// zone that is not one.
pub fn resolve_time_zone(body: &JMap, client: Option<&serde_json::Value>) -> Result<String, AppError> {
    match requested_zone(body) {
        Some(Ok(zone)) => Ok(zone),
        Some(Err(zone)) => Err(crate::catalogue::error(StatusCode::BAD_REQUEST, UNKNOWN_TIMEZONE, &[&zone])),
        None => Ok(client_zone(client)),
    }
}

/// The two security questions the check asks, so the order can be tested without a server.
pub trait AnalyticsSecurity: Send + Sync {
    fn has_write_access<'a>(&'a self, app_code: &'a str, client_code: &'a str) -> BoxFuture<'a, anyhow::Result<bool>>;
    fn does_client_manage_client_code<'a>(&'a self, managing: &'a str, client: &'a str) -> BoxFuture<'a, anyhow::Result<bool>>;
}

impl AnalyticsSecurity for SecurityClient {
    fn has_write_access<'a>(&'a self, app_code: &'a str, client_code: &'a str) -> BoxFuture<'a, anyhow::Result<bool>> {
        Box::pin(SecurityClient::has_write_access(self, app_code, client_code))
    }
    fn does_client_manage_client_code<'a>(&'a self, managing: &'a str, client: &'a str) -> BoxFuture<'a, anyhow::Result<bool>> {
        Box::pin(SecurityClient::does_client_manage_client_code(self, managing, client))
    }
}

/// `checkConfiguredAndAuthorized` up to (not including) the app's analytics flag, in Java's
/// order; nothing is asked of security for a caller refused earlier.
pub async fn check_authorized(
    configured: bool,
    app_code: &str,
    client_code: &str,
    ca: &ContextAuthentication,
    security: &dyn AnalyticsSecurity,
) -> Result<(), AppError> {
    let refuse = |status: StatusCode, key: &str| Err(crate::catalogue::error(status, key, &[]));
    if !configured {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, NOT_CONFIGURED);
    }
    if app_code.trim().is_empty() || client_code.trim().is_empty() {
        return refuse(StatusCode::BAD_REQUEST, CODES_REQUIRED);
    }
    if !ca.authenticated {
        return refuse(StatusCode::FORBIDDEN, LOGIN_REQUIRED);
    }
    if !has_authority(Some(AUTHORITY_APPLICATION_UPDATE), &ca.user.string_authorities) {
        return refuse(StatusCode::FORBIDDEN, NO_WRITE_ACCESS);
    }
    if !security.has_write_access(app_code, ca.client_code()).await? {
        return refuse(StatusCode::FORBIDDEN, NO_WRITE_ACCESS);
    }
    if client_code != ca.client_code() && !security.does_client_manage_client_code(ca.client_code(), client_code).await? {
        return refuse(StatusCode::FORBIDDEN, CLIENT_NOT_MANAGED);
    }
    Ok(())
}

/// The cache key: SHA-256 of the request as JSON.
pub fn cache_key(request: &JMap) -> String {
    use sha2::{Digest, Sha256};
    let json = overridable::json::to_gson(&JValue::Object(request.clone()));
    Sha256::digest(json.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    //! The Java `AnalyticsServiceTest` (site keys, zones, the request the engine is sent); the
    //! authorization order is `AnalyticsAuthorizationTest`, in the shell's handler tests.
    use super::*;

    fn body(v: serde_json::Value) -> JMap {
        match overridable::json::parse(v.to_string().as_bytes()).unwrap() {
            JValue::Object(o) => o,
            _ => unreachable!(),
        }
    }

    fn client(zone: Option<&str>) -> Option<serde_json::Value> {
        zone.map(|z| serde_json::json!({"code": "SYSTEM", "timeZone": z}))
    }

    #[test]
    fn the_requests_own_zone_wins_over_the_clients() {
        let b = body(serde_json::json!({"timezone": "Europe/London"}));
        assert_eq!(resolve_time_zone(&b, client(Some("Asia/Kolkata")).as_ref()).unwrap(), "Europe/London");
    }

    #[test]
    fn the_clients_zone_is_used_when_the_request_names_none() {
        assert_eq!(resolve_time_zone(&JMap::new(), client(Some("America/New_York")).as_ref()).unwrap(), "America/New_York");
    }

    #[test]
    fn the_platform_default_is_used_when_the_client_has_no_zone() {
        assert_eq!(resolve_time_zone(&JMap::new(), client(None).as_ref()).unwrap(), "Asia/Kolkata");
        assert_eq!(resolve_time_zone(&JMap::new(), client(Some("")).as_ref()).unwrap(), "Asia/Kolkata");
    }

    #[test]
    fn an_unusable_zone_on_the_client_record_falls_back_rather_than_failing() {
        assert_eq!(resolve_time_zone(&JMap::new(), client(Some("Mars/Olympus")).as_ref()).unwrap(), "Asia/Kolkata");
        let e = resolve_time_zone(&body(serde_json::json!({"timezone": "Mars/Olympus"})), None).unwrap_err();
        assert_eq!(e.status(), StatusCode::BAD_REQUEST);
        assert_eq!(overridable::write::messages::error_message(&e), "Mars/Olympus is not a known IANA time zone.");
        assert!(matches!(&e, AppError::Coded(c) if c.code == "UI.ANALYTICS_UNKNOWN_TIMEZONE"));
    }

    #[test]
    fn the_site_key_is_canonical_and_matches_the_engine() {
        assert_eq!(site_key("modlix", "SYSTEM"), "modlix_SYSTEM");
        assert_eq!(site_key("Modlix", "system"), "modlix_SYSTEM");
        assert_eq!(site_key("THEOREM", "thrm"), "theorem_THRM");
    }

    #[test]
    fn the_callers_own_site_is_overwritten() {
        let sent = engine_request(
            &body(serde_json::json!({"widget": "topPages", "site": "someoneelse_OTHER", "timezone": "Europe/London"})),
            "modlix",
            "SYSTEM",
            "Asia/Kolkata",
        );
        assert_eq!(sent["site"], JValue::from("modlix_SYSTEM"));
        assert_eq!(sent["timezone"], JValue::from("Asia/Kolkata"));
        assert_eq!(sent["widget"], JValue::from("topPages"));
    }

    // AnalyticsAuthorizationTest

    use std::sync::Mutex;

    const APP: &str = "leadzump";
    const SYSTEM: &str = "SYSTEM";
    const OTHER: &str = "OTHERCO";

    /// Records every call; answers as configured.
    #[derive(Default)]
    struct FakeSecurity {
        write: bool,
        manages: bool,
        calls: Mutex<Vec<String>>,
    }

    impl AnalyticsSecurity for FakeSecurity {
        fn has_write_access<'a>(&'a self, app_code: &'a str, client_code: &'a str) -> BoxFuture<'a, anyhow::Result<bool>> {
            self.calls.lock().unwrap().push(format!("hasWriteAccess({app_code}, {client_code})"));
            Box::pin(async move { Ok(self.write) })
        }
        fn does_client_manage_client_code<'a>(&'a self, managing: &'a str, client: &'a str) -> BoxFuture<'a, anyhow::Result<bool>> {
            self.calls.lock().unwrap().push(format!("doesClientManageClientCode({managing}, {client})"));
            Box::pin(async move { Ok(self.manages) })
        }
    }

    fn auth_for(client_code: &str, authenticated: bool, authorities: &[&str]) -> ContextAuthentication {
        let mut ca = ContextAuthentication {
            authenticated,
            client_code: Some(client_code.into()),
            logged_in_from_client_code: Some(client_code.into()),
            client_type_code: Some("SYS".into()),
            access_token: Some("test-token".into()),
            url_client_code: Some(client_code.into()),
            url_app_code: Some(APP.into()),
            ..Default::default()
        };
        ca.user.id = 1;
        ca.user.client_id = 1;
        ca.user.user_name = Some(format!("test-{client_code}"));
        ca.user.string_authorities = authorities.iter().map(|a| a.to_string()).collect();
        ca
    }

    async fn status_of(sec: &FakeSecurity, ca: &ContextAuthentication, client_code: &str) -> Option<StatusCode> {
        check_authorized(true, APP, client_code, ca, sec).await.err().map(|e| e.status())
    }

    #[tokio::test]
    async fn anonymous_is_refused() {
        let sec = FakeSecurity::default();
        let ca = auth_for(SYSTEM, false, &["Authorities._Anonymous"]);
        assert_eq!(status_of(&sec, &ca, SYSTEM).await, Some(StatusCode::FORBIDDEN));
        assert!(sec.calls.lock().unwrap().is_empty(), "security is never consulted");
    }

    #[tokio::test]
    async fn authenticated_without_the_authority_is_refused() {
        let sec = FakeSecurity::default();
        let ca = auth_for(SYSTEM, true, &["Authorities.Logged_IN"]);
        assert_eq!(status_of(&sec, &ca, SYSTEM).await, Some(StatusCode::FORBIDDEN));
        assert!(sec.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn write_access_is_checked_for_the_caller() {
        let sec = FakeSecurity { write: false, ..Default::default() };
        let ca = auth_for(OTHER, true, &[AUTHORITY_APPLICATION_UPDATE]);
        assert_eq!(status_of(&sec, &ca, SYSTEM).await, Some(StatusCode::FORBIDDEN));
        assert_eq!(*sec.calls.lock().unwrap(), vec![format!("hasWriteAccess({APP}, {OTHER})")]);
    }

    #[tokio::test]
    async fn unmanaged_target_is_refused() {
        let sec = FakeSecurity { write: true, manages: false, ..Default::default() };
        let ca = auth_for(OTHER, true, &[AUTHORITY_APPLICATION_UPDATE]);
        assert_eq!(status_of(&sec, &ca, SYSTEM).await, Some(StatusCode::FORBIDDEN));
        assert!(sec.calls.lock().unwrap().contains(&format!("doesClientManageClientCode({OTHER}, {SYSTEM})")));
    }

    #[tokio::test]
    async fn own_client_skips_the_management_call() {
        let sec = FakeSecurity { write: true, ..Default::default() };
        let ca = auth_for(SYSTEM, true, &[AUTHORITY_APPLICATION_UPDATE]);
        // Passes this part; the analytics-enabled check that follows is the handler's.
        assert_eq!(status_of(&sec, &ca, SYSTEM).await, None);
        assert!(!sec.calls.lock().unwrap().iter().any(|c| c.starts_with("doesClientManageClientCode")));
    }

    #[tokio::test]
    async fn configuration_and_codes_come_first() {
        let sec = FakeSecurity::default();
        let ca = auth_for(SYSTEM, true, &[AUTHORITY_APPLICATION_UPDATE]);
        let e = check_authorized(false, APP, SYSTEM, &ca, &sec).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::SERVICE_UNAVAILABLE);
        let e = check_authorized(true, " ", SYSTEM, &ca, &sec).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::BAD_REQUEST);
        let managed = FakeSecurity { write: true, manages: true, ..Default::default() };
        assert!(check_authorized(true, APP, OTHER, &ca, &managed).await.is_ok());
    }

    #[test]
    fn site_key_is_lower_app_and_upper_client() {
        assert_eq!(site_key("LeadZump", "system"), "leadzump_SYSTEM");
        assert_eq!(site_key("appbuilder", "FIN1"), "appbuilder_FIN1");
    }

    #[test]
    fn the_site_is_overwritten_never_trusted() {
        let r = engine_request(&body(serde_json::json!({"widget": "topPages", "site": "other_TENANT"})), "leadzump", "system", "UTC");
        assert_eq!(r["site"], JValue::from("leadzump_SYSTEM"));
        assert_eq!(r["timezone"], JValue::from("UTC"));
        assert_eq!(r["widget"], JValue::from("topPages"));
        assert_eq!(r.keys().collect::<Vec<_>>(), vec!["widget", "site", "timezone"], "a key the body has keeps its place");
    }

    #[test]
    fn a_requested_zone_wins_and_a_bad_one_is_refused() {
        assert_eq!(requested_zone(&body(serde_json::json!({"timezone": " Europe/London "}))), Some(Ok("Europe/London".into())));
        assert_eq!(requested_zone(&body(serde_json::json!({"timezone": "Mars/Base"}))), Some(Err("Mars/Base".into())));
        assert_eq!(requested_zone(&body(serde_json::json!({"timezone": "  "}))), None);
        assert_eq!(requested_zone(&body(serde_json::json!({"timezone": null}))), None);
        assert_eq!(requested_zone(&body(serde_json::json!({}))), None);
        assert_eq!(requested_zone(&body(serde_json::json!({"timezone": 5}))), Some(Err("5".into())));
    }

    #[test]
    fn the_client_zone_then_kolkata() {
        assert_eq!(client_zone(Some(&serde_json::json!({"timeZone": "America/New_York"}))), "America/New_York");
        assert_eq!(client_zone(Some(&serde_json::json!({"timeZone": "Not/AZone"}))), FALLBACK_TIME_ZONE);
        assert_eq!(client_zone(Some(&serde_json::json!({"timeZone": ""}))), FALLBACK_TIME_ZONE);
        assert_eq!(client_zone(Some(&serde_json::json!({}))), FALLBACK_TIME_ZONE);
        assert_eq!(client_zone(None), FALLBACK_TIME_ZONE);
    }

    #[test]
    fn zones_java_accepts() {
        for z in ["Asia/Kolkata", "UTC", "GMT", "UT", "Z", "+05:30", "-08", "+5", "+0530", "+05:30:15", "+053015", "UTC+05:30", "GMT-2", "UT+01:00", "EST", "+18:00"] {
            assert!(is_valid_zone(z), "{z}");
        }
        for z in ["asia/kolkata", "Mars/Base", "+19:00", "+18:01", "+5:30", "UTC+", "GMT+x", "", "+05:60", "+05:30:61", "+ab", "+05-30", "+0a30", "+05:3x", "+05:30-15", "+0530ab", "IST+1"] {
            assert!(!is_valid_zone(z), "{z}");
        }
    }

    #[test]
    fn enabled_only_when_the_flag_is_true() {
        let app = |p: serde_json::Value| body(serde_json::json!({"properties": p}));
        assert!(analytics_enabled(&app(serde_json::json!({"analytics": {"enabled": true}}))));
        assert!(!analytics_enabled(&app(serde_json::json!({"analytics": {"enabled": "true"}}))));
        assert!(!analytics_enabled(&app(serde_json::json!({"analytics": true}))));
        assert!(!analytics_enabled(&app(serde_json::json!({}))));
        assert!(!analytics_enabled(&body(serde_json::json!({}))));
    }

    #[test]
    fn cache_keys_follow_the_request() {
        let a = engine_request(&body(serde_json::json!({"widget": "a"})), "x", "y", "UTC");
        let b = engine_request(&body(serde_json::json!({"widget": "b"})), "x", "y", "UTC");
        assert_eq!(cache_key(&a).len(), 64);
        assert_ne!(cache_key(&a), cache_key(&b));
        assert_eq!(cache_key(&a), cache_key(&a.clone()));
    }
}
