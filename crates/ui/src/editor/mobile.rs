//! The mobile apps of an application (`MobileAppService` and the `ApplicationService` methods
//! the application controller's mobile routes call): the build requests the mobile build
//! machines pick up, each with an Android keystore made on its first save and, for iOS on the
//! platform's account, a bundle id and provisioning profile from App Store Connect.

use std::sync::Arc;

use axum::http::StatusCode;
use mongodb::bson::doc;
use overridable::backend::{Backend, Directory, Find};
use overridable::pojo::{convert_json, decode_bson, map_field, str_field, to_jackson, CloneRule as C, Field, Kind as K, Pojo};
use overridable::write::messages::{self as msg, Messages};
use overridable::write::persist::{to_document, Clock};
use overridable::{JMap, JValue};
use platform::error::{AppError, AppResult};
use platform::security::ContextAuthentication;

use crate::editor::apple::Apple;
use crate::editor::jks;
use crate::editor::kinds::{INTERNAL_ONLY, MOBILE_APP_BAD_REQUEST, MOBILE_APP_UNABLE_TO_GEN_KEYSTORE};

pub const COLLECTION: &str = "mobileApp";
pub const MOBILE_APP_CREATE: &str = "Authorities.ROLE_MobileApp_CREATE";

/// `MobileApp`, its `AbstractUpdatableDTO` fields first.
pub const MOBILE_APP: Pojo = Pojo {
    name: "MobileApp",
    parts: &[
        &[
            Field::new("id", K::Str, C::Copy),
            Field::new("createdAt", K::DateTime, C::Copy),
            Field::new("createdBy", K::Str, C::Copy),
            Field::new("updatedAt", K::DateTime, C::Copy),
            Field::new("updatedBy", K::Str, C::Copy),
        ],
        &[
            Field::new("appCode", K::Str, C::Copy),
            Field::new("clientCode", K::Str, C::Copy),
            Field::new("status", K::Str, C::Copy),
            Field::new("errorMessage", K::Str, C::Copy),
            Field::new("details", K::Object, C::Copy),
            Field::new("androidAppURL", K::Str, C::Copy),
            Field::new("iosAppURL", K::Str, C::Copy),
            Field::new("androidKeystore", K::Str, C::Copy),
            Field::new("androidStorePass", K::Str, C::Copy),
            Field::new("androidKeyPass", K::Str, C::Copy),
            Field::new("androidAlias", K::Str, C::Copy),
            Field::new("iosCertificate", K::Str, C::Copy),
            Field::new("iosCertificatePassword", K::Str, C::Copy),
            Field::new("iosProvisioningProfile", K::Str, C::Copy),
            Field::new("iosTeamId", K::Str, C::Copy),
            Field::new("iosBundleId", K::Str, C::Copy),
        ],
    ],
};

/// `MobileApp.AppDetails`.
pub const APP_DETAILS: Pojo = Pojo {
    name: "AppDetails",
    parts: &[&[
        Field::new("name", K::Str, C::Copy),
        Field::new("description", K::Str, C::Copy),
        Field::new("startURL", K::Str, C::Copy),
        Field::new("android", K::PrimBool, C::Copy),
        Field::new("ios", K::PrimBool, C::Copy),
        Field::new("iosPublishMode", K::Str, C::Copy),
        Field::new("icon", K::Str, C::Copy),
        Field::new("splashScreen", K::Object, C::Copy),
        Field::new("version", K::PrimInt(0), C::Copy),
    ]],
};

/// `MobileApp.SplashScreenDetails`.
pub const SPLASH_SCREEN: Pojo = Pojo {
    name: "SplashScreenDetails",
    parts: &[&[
        Field::new("image", K::Str, C::Copy),
        Field::new("color", K::Str, C::Copy),
        Field::new("backgroundImage", K::Str, C::Copy),
        Field::new("fullScreen", K::PrimBool, C::Copy),
        Field::new("gravity", K::Str, C::Copy),
        Field::new("color_dark", K::Str, C::Copy),
        Field::new("background_image_dark", K::Str, C::Copy),
        Field::new("image_dark", K::Str, C::Copy),
    ]],
};

/// `MobileAppStatusUpdateRequest`.
pub const STATUS_UPDATE: Pojo = Pojo {
    name: "MobileAppStatusUpdateRequest",
    parts: &[&[
        Field::new("status", K::Str, C::Copy),
        Field::new("errorMessage", K::Str, C::Copy),
        Field::new("androidAppURL", K::Str, C::Copy),
        Field::new("iosAppURL", K::Str, C::Copy),
    ]],
};

const STATUSES: [&str; 4] = ["PENDING", "IN_PROGRESS", "SUCCESS", "FAILED"];
const PUBLISH_MODES: [&str; 2] = ["TENANT_ACCOUNT", "PLATFORM_ACCOUNT"];

fn bad_body() -> AppError {
    overridable::write::controller::spring_refusal(StatusCode::BAD_REQUEST, "Failed to read HTTP message")
}

/// An enum field as Jackson reads it: one of the constants or null.
fn check_enum(m: &JMap, field: &str, allowed: &[&str]) -> AppResult<()> {
    match m.get(field) {
        None | Some(JValue::Null) => Ok(()),
        Some(JValue::Str(s)) if allowed.contains(&s.as_str()) => Ok(()),
        _ => Err(bad_body()),
    }
}

/// The details as the class reads them (unknown keys dropped, defaults for the primitives).
fn details_of(v: Option<&JValue>) -> AppResult<Option<JMap>> {
    match v {
        None | Some(JValue::Null) => Ok(None),
        Some(JValue::Object(d)) => {
            let mut details = convert_json(&APP_DETAILS, d);
            check_enum(&details, "iosPublishMode", &PUBLISH_MODES)?;
            details.insert(
                "splashScreen".into(),
                match d.get("splashScreen") {
                    Some(JValue::Object(s)) => JValue::Object(convert_json(&SPLASH_SCREEN, s)),
                    None | Some(JValue::Null) => JValue::Null,
                    _ => return Err(bad_body()),
                },
            );
            Ok(Some(details))
        }
        _ => Err(bad_body()),
    }
}

/// A request body (`@RequestBody MobileApp`).
pub fn read_body(body: &[u8]) -> AppResult<JMap> {
    let Ok(JValue::Object(m)) = overridable::json::parse(body) else { return Err(bad_body()) };
    let mut app = convert_json(&MOBILE_APP, &m);
    check_enum(&app, "status", &STATUSES)?;
    let details = details_of(m.get("details"))?;
    app.insert("details".into(), details.map(JValue::Object).unwrap_or_default());
    Ok(app)
}

/// A stored mobile app as the class reads it.
pub fn decode(d: &mongodb::bson::Document) -> JMap {
    let mut app = decode_bson(&MOBILE_APP, d);
    if let Some(JValue::Object(details)) = app.get("details").cloned() {
        let mut dd = convert_json(&APP_DETAILS, &details);
        if let Some(JValue::Object(s)) = details.get("splashScreen") {
            dd.insert("splashScreen".into(), JValue::Object(convert_json(&SPLASH_SCREEN, s)));
        }
        app.insert("details".into(), JValue::Object(dd));
    }
    app
}

fn nested_jackson(pojo: &Pojo, m: &JMap) -> JMap {
    let mut out = to_jackson(pojo, m);
    if let Some(JValue::Object(s)) = out.get("splashScreen").cloned() {
        out.insert("splashScreen".into(), JValue::Object(to_jackson(&SPLASH_SCREEN, &s)));
    }
    out
}

/// The app as the ui's `ObjectMapper` writes it.
pub fn to_json(app: &JMap) -> JValue {
    let mut out = to_jackson(&MOBILE_APP, app);
    if let Some(JValue::Object(d)) = out.get("details").cloned() {
        out.insert("details".into(), JValue::Object(nested_jackson(&APP_DETAILS, &d)));
    }
    JValue::Object(out)
}

/// A nested class as Spring Data stores it: its fields in order, nulls left out.
fn stored_nested(pojo: &Pojo, m: &JMap) -> JMap {
    let mut out = JMap::new();
    for f in pojo.fields() {
        match m.get(f.name) {
            None | Some(JValue::Null) => {}
            Some(JValue::Object(s)) if f.name == "splashScreen" => {
                out.insert(f.name.into(), JValue::Object(stored_nested(&SPLASH_SCREEN, s)));
            }
            Some(v) => {
                out.insert(f.name.into(), v.clone());
            }
        }
    }
    out
}

/// `LocalDateTime.now()` (the JVM's zone, not UTC) as the response shows it.
fn local_now(clock: &Clock) -> JValue {
    JValue::Int(clock.secs() + overridable::pojo::java_zone_offset_seconds() as i64)
}

/// `MobileAppService` and the access rules `ApplicationService` puts around it.
pub struct MobileApps {
    pub backend: Arc<dyn Backend>,
    pub directory: Arc<dyn Directory>,
    pub messages: Arc<Messages>,
    pub apple: Apple,
    /// `security.appCodeSuffix`, for the default start URL.
    pub app_code_suffix: String,
    /// The RSA key size of a new keystore (2048; tests use less).
    pub key_bits: usize,
}

impl MobileApps {
    fn err(&self, status: StatusCode, id: &str, params: &[&str]) -> AppError {
        self.messages.error(status, id, params)
    }

    fn forbidden(&self) -> AppError {
        crate::catalogue::error_as("UI.APP_PERMISSION_REQUIRED", StatusCode::FORBIDDEN, msg::FORBIDDEN_PERMISSION, &["Authorities.Application_CREATE"])
    }

    async fn find_by_id(&self, id: &str) -> AppResult<Option<JMap>> {
        let d = self.backend.find_one(COLLECTION, overridable::Store::id_filter(id), None).await?;
        Ok(d.as_ref().map(decode))
    }

    async fn save(&self, app: &mut JMap) -> AppResult<()> {
        let mut stored = app.clone();
        if let Some(JValue::Object(d)) = app.get("details") {
            stored.insert("details".into(), JValue::Object(stored_nested(&APP_DETAILS, d)));
        }
        match str_field(app, "id").map(str::to_string) {
            Some(id) => {
                let prior = self.backend.find_one(COLLECTION, overridable::Store::id_filter(&id), None).await?;
                let priors: Vec<&mongodb::bson::Document> = prior.iter().collect();
                let d = to_document(&MOBILE_APP, &stored, None, &priors);
                self.backend.replace(COLLECTION, overridable::write::persist::id_bson(&id), d).await?;
            }
            None => {
                let d = to_document(&MOBILE_APP, &stored, None, &[]);
                let id = self.backend.insert(COLLECTION, d).await?;
                app.insert("id".into(), JValue::Str(overridable::write::transport::id_string(&id)));
            }
        }
        Ok(())
    }

    /// `listMobileApps`: the caller's own client's apps (Java's `nonNullValue` picks the
    /// caller's client even when another was asked for, once that one is managed).
    pub async fn list(&self, ca: &ContextAuthentication, app: &str, client: Option<&str>) -> AppResult<JValue> {
        if let Some(c) = client {
            if !self.directory.does_client_manage_client_code(ca.client_code(), c).await? {
                return Err(self.forbidden());
            }
        }
        let cc = ca.client_code.as_deref().or(client).unwrap_or("");
        let docs = self.backend.find(COLLECTION, Find::new(doc! {"appCode": app, "clientCode": cc})).await?;
        Ok(JValue::Array(docs.iter().map(|d| to_json(&decode(d))).collect()))
    }

    /// `updateMobileApp` and `MobileAppService.update`.
    /// `None` for an unknown id (Java's empty Mono: a 200 without a body).
    pub async fn update(&self, ca: &ContextAuthentication, mut app: JMap) -> AppResult<Option<JValue>> {
        if let Some(c) = str_field(&app, "clientCode") {
            if !self.directory.does_client_manage_client_code(ca.client_code(), c).await? {
                return Err(self.forbidden());
            }
        }
        if app.get("clientCode").is_none_or(JValue::is_null) {
            app.insert("clientCode".into(), ca.client_code.clone().map(JValue::Str).unwrap_or_default());
        }
        app.insert("status".into(), JValue::Str("PENDING".into()));
        let clock = Clock::now();
        let user = JValue::Str(ca.user.id.to_string());
        let is_new = app.get("id").is_none_or(JValue::is_null);
        if is_new {
            app.insert("createdAt".into(), local_now(&clock));
            app.insert("createdBy".into(), user.clone());
            app.insert("updatedAt".into(), local_now(&clock));
        } else {
            app.insert("updatedAt".into(), local_now(&clock));
        }
        let Some(mut details) = map_field(&app, "details").cloned() else {
            return Err(self.err(StatusCode::BAD_REQUEST, MOBILE_APP_BAD_REQUEST, &[]));
        };
        if str_field(&details, "startURL").is_none_or(|s| s.trim().is_empty()) {
            let env = self.app_code_suffix.replace('.', "");
            let prefix = if env.trim().is_empty() { String::new() } else { format!("{}.", env.trim()) };
            let url = format!(
                "https://{prefix}modlix.com/{}/{}/page/",
                str_field(&app, "appCode").unwrap_or("null"),
                str_field(&app, "clientCode").unwrap_or("null")
            );
            details.insert("startURL".into(), JValue::Str(url));
        }
        app.insert("details".into(), JValue::Object(details));
        app.insert("updatedBy".into(), user);
        self.store(app).await
    }

    fn keystore(&self, app: &mut JMap) -> AppResult<()> {
        match jks::create_keystore_with(self.key_bits) {
            Ok(b) => {
                app.insert("androidKeystore".into(), JValue::Str(b.jks_base64));
                app.insert("androidStorePass".into(), JValue::Str(b.store_pass));
                app.insert("androidKeyPass".into(), JValue::Str(b.key_pass));
                app.insert("androidAlias".into(), JValue::Str(b.alias));
                Ok(())
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to generate Android keystore");
                Err(self.err(StatusCode::BAD_REQUEST, MOBILE_APP_UNABLE_TO_GEN_KEYSTORE, &[]))
            }
        }
    }

    fn details<'a>(app: &'a JMap) -> Option<&'a JMap> {
        map_field(app, "details")
    }

    fn platform_ios(app: &JMap) -> bool {
        Self::details(app).is_some_and(|d| d.get("ios") == Some(&JValue::Bool(true)) && str_field(d, "iosPublishMode") == Some("PLATFORM_ACCOUNT"))
    }

    fn app_name(app: &JMap) -> String {
        Self::details(app).and_then(|d| str_field(d, "name")).unwrap_or("null").to_string()
    }

    fn set_details_version(app: &mut JMap, existing: &JMap) -> AppResult<()> {
        let old = Self::details(existing)
            .and_then(|d| d.get("version"))
            .and_then(JValue::as_i64)
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("NullPointerException: existing details")))?;
        if let Some(JValue::Object(d)) = app.get_mut("details") {
            d.insert("version".into(), JValue::Int(old + 1));
        }
        Ok(())
    }

    fn ios_failure(e: anyhow::Error, what: &str) -> AppError {
        AppError::Internal(anyhow::anyhow!("{what}: {e}"))
    }

    /// `MobileAppService.update`: a keystore for a new app (or one without), the iOS
    /// configuration when it is due, then the save.
    async fn store(&self, mut app: JMap) -> AppResult<Option<JValue>> {
        let client = str_field(&app, "clientCode").unwrap_or("null").to_string();
        let Some(id) = str_field(&app, "id").map(str::to_string) else {
            self.keystore(&mut app)?;
            if Self::platform_ios(&app) && self.apple.configured_for_bundle_id() {
                let (bundle, team, profile) = self
                    .apple
                    .setup_ios(&client, &Self::app_name(&app))
                    .await
                    .map_err(|e| Self::ios_failure(e, "Failed to setup iOS configuration for mobile app"))?;
                app.insert("iosBundleId".into(), JValue::Str(bundle));
                app.insert("iosTeamId".into(), JValue::Str(team));
                if !profile.trim().is_empty() {
                    app.insert("iosProvisioningProfile".into(), JValue::Str(profile));
                }
            }
            self.save(&mut app).await?;
            return Ok(Some(to_json(&app)));
        };
        let Some(existing) = self.find_by_id(&id).await? else { return Ok(None) };
        if existing.get("androidKeystore").is_none_or(JValue::is_null) {
            self.keystore(&mut app)?;
        } else {
            for f in ["androidKeystore", "androidStorePass", "androidKeyPass", "androidAlias"] {
                app.insert(f.into(), existing.get(f).cloned().unwrap_or_default());
            }
        }
        let has = |m: &JMap, f: &str| str_field(m, f).is_some_and(|s| !s.trim().is_empty());
        let platform = Self::platform_ios(&app);
        let configured = self.apple.configured_for_bundle_id();
        if platform && !has(&existing, "iosBundleId") && configured {
            Self::set_details_version(&mut app, &existing)?;
            let (bundle, team, profile) = self
                .apple
                .setup_ios(&client, &Self::app_name(&app))
                .await
                .map_err(|e| Self::ios_failure(e, "Failed to setup iOS configuration for mobile app"))?;
            app.insert("iosBundleId".into(), JValue::Str(bundle));
            app.insert("iosTeamId".into(), JValue::Str(team));
            if !profile.trim().is_empty() {
                app.insert("iosProvisioningProfile".into(), JValue::Str(profile));
            }
            self.save(&mut app).await?;
            return Ok(Some(to_json(&app)));
        }
        if platform && has(&existing, "iosBundleId") && !has(&existing, "iosProvisioningProfile") && configured {
            Self::set_details_version(&mut app, &existing)?;
            let name = Self::app_name(&app);
            let made = async {
                let (_, apple_id) = self.apple.get_or_create_bundle_id(&client, &name).await?;
                let profile = self.apple.provisioning_profile(&apple_id, &format!("{name} - {client} - App Store")).await?;
                if profile.trim().is_empty() && !self.apple.cfg.apple_certificate_id.trim().is_empty() {
                    anyhow::bail!("Failed to create or retrieve provisioning profile. Certificate ID is configured but no profile could be obtained.");
                }
                Ok(profile)
            }
            .await
            .map_err(|e| Self::ios_failure(e, "Failed to create provisioning profile for mobile app"))?;
            app.insert("iosBundleId".into(), existing.get("iosBundleId").cloned().unwrap_or_default());
            let team = if has(&existing, "iosTeamId") { existing["iosTeamId"].clone() } else { JValue::Str(self.apple.cfg.apple_team_id.clone()) };
            app.insert("iosTeamId".into(), team);
            if !made.trim().is_empty() {
                app.insert("iosProvisioningProfile".into(), JValue::Str(made));
            }
            self.save(&mut app).await?;
            return Ok(Some(to_json(&app)));
        }
        if Self::details(&app).is_some_and(|d| str_field(d, "iosPublishMode") == Some("PLATFORM_ACCOUNT")) {
            for f in ["iosBundleId", "iosTeamId", "iosProvisioningProfile"] {
                if has(&existing, f) {
                    app.insert(f.into(), existing[f].clone());
                }
            }
        }
        Self::set_details_version(&mut app, &existing)?;
        self.save(&mut app).await?;
        Ok(Some(to_json(&app)))
    }

    /// `deleteMobileApp`: the app's client needs write access to the app.
    pub async fn delete(&self, ca: &ContextAuthentication, id: &str) -> AppResult<bool> {
        let refused = || self.err(StatusCode::FORBIDDEN, msg::UNABLE_TO_DELETE, &["Mobile Application", id]);
        let Some(app) = self.find_by_id(id).await? else { return Err(refused()) };
        let (a, c) = (str_field(&app, "appCode").unwrap_or(""), str_field(&app, "clientCode").unwrap_or(""));
        if !self.directory.has_write_access(a, c).await? {
            return Err(refused());
        }
        // Java asks whether the caller manages the app's client and goes on whatever it hears.
        self.directory.does_client_manage_client_code(ca.client_code(), c).await?;
        self.backend.delete_one(COLLECTION, overridable::Store::id_filter(id)).await?;
        Ok(true)
    }

    /// `findNextAppToGenerate`: the oldest pending request, for the SYSTEM client's builders.
    pub async fn next(&self, ca: &ContextAuthentication) -> AppResult<Option<JValue>> {
        if !ca.is_system_client() {
            return Err(self.err(StatusCode::FORBIDDEN, INTERNAL_ONLY, &[]));
        }
        let d = self.backend.find_one(COLLECTION, doc! {"status": "PENDING"}, Some(doc! {"updatedAt": 1})).await?;
        Ok(d.as_ref().map(|d| to_json(&decode(d))))
    }

    /// `updateStatus`: a builder's report. `None` for an unknown id (an empty 200).
    pub async fn update_status(&self, ca: &ContextAuthentication, id: &str, body: &[u8]) -> AppResult<Option<bool>> {
        let Ok(JValue::Object(m)) = overridable::json::parse(body) else { return Err(bad_body()) };
        let req = convert_json(&STATUS_UPDATE, &m);
        check_enum(&req, "status", &STATUSES)?;
        if !ca.is_system_client() {
            return Err(self.err(StatusCode::FORBIDDEN, INTERNAL_ONLY, &[]));
        }
        let Some(mut app) = self.find_by_id(id).await? else { return Ok(None) };
        app.insert("updatedAt".into(), local_now(&Clock::now()));
        if str_field(&req, "errorMessage").is_some_and(|e| !e.trim().is_empty()) {
            app.insert("status".into(), JValue::Str("FAILED".into()));
            app.insert("errorMessage".into(), req["errorMessage"].clone());
        } else {
            app.insert("status".into(), req.get("status").cloned().unwrap_or_default());
            if str_field(&req, "status") == Some("SUCCESS") {
                app.insert("errorMessage".into(), JValue::Null);
            }
        }
        app.insert("androidAppURL".into(), req.get("androidAppURL").cloned().unwrap_or_default());
        app.insert("iosAppURL".into(), req.get("iosAppURL").cloned().unwrap_or_default());
        self.save(&mut app).await?;
        Ok(Some(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_as_jackson_reads_them() {
        let b = read_body(br#"{"appCode":"x","status":"SUCCESS","extra":1,"details":{"name":"N","ios":true,"iosPublishMode":"PLATFORM_ACCOUNT","splashScreen":{"color":"red","x":1}}}"#).unwrap();
        assert_eq!(b["appCode"], JValue::from("x"));
        assert!(!b.contains_key("extra"));
        let d = b["details"].as_object().unwrap();
        assert_eq!(d["android"], JValue::Bool(false));
        assert_eq!(d["version"], JValue::Int(0));
        assert_eq!(d["splashScreen"].as_object().unwrap()["fullScreen"], JValue::Bool(false));
        assert!(read_body(br#"{"status":"NOPE"}"#).is_err());
        assert!(read_body(br#"{"details":{"iosPublishMode":"X"}}"#).is_err());
        assert!(read_body(br#"{"details":3}"#).is_err());
        assert!(read_body(br#"{"details":{"splashScreen":3}}"#).is_err());
        assert!(read_body(b"[]").is_err());
        let json = to_json(&b);
        let o = json.as_object().unwrap();
        assert_eq!(o.keys().cloned().collect::<Vec<_>>(), vec!["appCode", "status", "details"]);
        let details = o["details"].as_object().unwrap();
        assert_eq!(details.keys().cloned().collect::<Vec<_>>(), vec!["name", "android", "ios", "iosPublishMode", "splashScreen", "version"]);
        assert_eq!(details["splashScreen"].as_object().unwrap().keys().cloned().collect::<Vec<_>>(), vec!["color", "fullScreen"]);
        let stored = stored_nested(&APP_DETAILS, details);
        assert!(!stored.contains_key("description"));
        assert_eq!(stored["splashScreen"].as_object().unwrap().len(), 2);
    }
}
