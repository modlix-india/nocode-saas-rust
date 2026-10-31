//! Push notifications (Rust only): to the browsers (Web Push), Android phones (FCM) and iPhones
//! (APNs) the recipients registered in the app. Not to be confused with [`crate::push`], which
//! carries SSE frames between instances.
//!
//! A notification goes out as push when its NOTIFICATION connection has `push` and it has a
//! `push` template, or, without one, an `inapp` template (whose `title`, `description`, `image`
//! and `url` are used). Each device is reached with the credentials of the account it was built
//! against: the client's own (the PUSH connection) when the account matches, otherwise the
//! platform's ([`crate::config::PushSection`]). Devices the push services call gone are
//! deleted; any other failure is logged and never stops the notification.

pub mod apns;
pub mod fcm;
pub mod keys;
pub mod webpush;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use futures::StreamExt;
use parking_lot::Mutex;
use serde_json::{json, Map, Value};

use crate::calls::CoreClient;
use crate::config::PushSection;
use crate::dao::{Dao, DeviceRow, Platform};
use crate::inapp::INAPP_TEMPLATE_NAME;
use crate::model::{CoreNotification, NotificationUser, PushConnection};
use crate::template::{language, processed_template};

use apns::{Apns, ApnsAccount};
use fcm::{Fcm, FcmAccount};
use webpush::WebPush;

pub const PUSH_TEMPLATE_NAME: &str = "push";

/// Devices reached at once for one notification.
const PARALLEL: usize = 16;

/// What a push service made of one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    Sent,
    /// The device will never take a push again (unsubscribed, uninstalled, bad token).
    Gone(String),
    Failed(String),
}

/// What every platform shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushMessage {
    pub title: String,
    pub body: String,
    pub image: Option<String>,
    /// Opened on a tap.
    pub url: Option<String>,
    /// Collapses repeats of the same notification on the device.
    pub notification_id: String,
    pub app_code: String,
}

impl PushMessage {
    /// The fields a tap needs, as strings (FCM data takes nothing else).
    pub fn data(&self) -> Vec<(&'static str, String)> {
        let mut d = vec![("notificationId", self.notification_id.clone()), ("appCode", self.app_code.clone())];
        if let Some(u) = &self.url {
            d.push(("url", u.clone()));
        }
        d
    }

    /// The Web Push payload the service worker reads.
    pub fn web_json(&self) -> Value {
        json!({"title": self.title, "body": self.body, "image": self.image, "url": self.url,
               "notificationId": self.notification_id, "appCode": self.app_code})
    }
}

fn filled(s: Option<&String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// The message from the `push` template, or from the `inapp` one when there is none; `None`
/// when it renders without a title and a body.
pub fn render(notification: &CoreNotification, payload: &Map<String, Value>, app_code: &str) -> Result<Option<PushMessage>> {
    let own = notification.channel(PUSH_TEMPLATE_NAME);
    let template = own.or_else(|| notification.channel(INAPP_TEMPLATE_NAME));
    if template.is_none() {
        return Ok(None);
    }
    let lang = language(notification, payload)?;
    let parts = processed_template(lang.as_deref(), template, payload)?;
    // `body` first in a push template, `description` first in an inapp one (what the in-app
    // channel stores); either takes the other, as the template editor writes inapp's as `body`.
    let (first, second) = if own.is_some() { ("body", "description") } else { ("description", "body") };
    let body = filled(parts.get(first)).or_else(|| filled(parts.get(second)));
    let title = filled(parts.get("title"));
    if title.is_none() && body.is_none() {
        return Ok(None);
    }
    Ok(Some(PushMessage {
        title: title.unwrap_or_default(),
        body: body.unwrap_or_default(),
        image: filled(parts.get("image")),
        url: filled(parts.get("url")),
        notification_id: uuid::Uuid::new_v4().to_string(),
        app_code: app_code.to_string(),
    }))
}

/// Where the send service hands push (tests fake it).
#[async_trait]
pub trait PushSink: Send + Sync {
    /// Answers how many devices took it.
    async fn send_push(
        &self,
        users: &[NotificationUser],
        notification: &CoreNotification,
        app_code: &str,
        connection: &PushConnection,
        payload: &Map<String, Value>,
    ) -> Result<usize>;
}

/// The client's own accounts from its PUSH connection: `fcm.credentials` (the service account
/// JSON) and `apns.{teamId, keyId, privateKey}`. A part that does not parse is logged and left
/// out, so those devices fall back to the platform's keys.
pub fn client_accounts(details: Option<&Map<String, Value>>) -> (Option<FcmAccount>, Option<ApnsAccount>) {
    let Some(d) = details else { return (None, None) };
    let fcm = d.get("fcm").and_then(|f| f.get("credentials")).and_then(|c| match FcmAccount::from_json(c) {
        Ok(a) => Some(a),
        Err(e) => {
            tracing::error!("PUSH connection fcm: {e:#}");
            None
        }
    });
    let apns = d.get("apns").and_then(Value::as_object).and_then(|a| {
        let s = |k: &str| a.get(k).and_then(Value::as_str).unwrap_or("");
        match ApnsAccount::new(s("teamId"), s("keyId"), s("privateKey")) {
            Ok(acc) => Some(acc),
            Err(e) => {
                tracing::error!("PUSH connection apns: {e:#}");
                None
            }
        }
    });
    (fcm, apns)
}

/// The account for a device built against `account`: the client's when it matches, else the
/// platform's when that matches; a device that names none takes the client's, else the
/// platform's.
pub fn pick<'a, T>(account: Option<&str>, own: Option<&'a T>, platform: Option<&'a T>, id: impl Fn(&T) -> &str) -> Option<&'a T> {
    match account.map(str::trim).filter(|a| !a.is_empty()) {
        Some(acc) => own.into_iter().chain(platform).find(|t| id(t) == acc),
        None => own.or(platform),
    }
}

pub struct PushService {
    pub dao: Dao,
    pub core: CoreClient,
    pub web: Option<WebPush>,
    pub fcm: Fcm,
    pub apns: Apns,
    pub platform_fcm: Option<Arc<FcmAccount>>,
    pub platform_apns: Option<Arc<ApnsAccount>>,
    /// Per app: whether it has notifications, and since when that is known.
    apps: Mutex<HashMap<String, (bool, Instant)>>,
    app_check: Duration,
}

impl PushService {
    /// From the `[push]` section. A credential that does not parse turns that platform off
    /// (logged), rather than stopping the unit.
    pub fn new(dao: Dao, core: CoreClient, cfg: &PushSection) -> Result<Self> {
        let timeout = Duration::from_secs(cfg.timeout_seconds.max(1));
        let web = if cfg.vapid_public_key.is_empty() || cfg.vapid_private_key.is_empty() {
            None
        } else {
            WebPush::new(&cfg.vapid_public_key, &cfg.vapid_private_key, &cfg.vapid_subject, timeout)
                .map_err(|e| tracing::error!("[push] VAPID keys: {e:#}; Web Push is off"))
                .ok()
        };
        let platform_fcm = (!cfg.fcm_credentials.trim().is_empty())
            .then(|| FcmAccount::from_json(&Value::String(cfg.fcm_credentials.clone())))
            .and_then(|r| r.map_err(|e| tracing::error!("[push] fcm_credentials: {e:#}")).ok())
            .map(Arc::new);
        let platform_apns = (!cfg.apns_private_key.trim().is_empty())
            .then(|| ApnsAccount::new(&cfg.apns_team_id, &cfg.apns_key_id, &cfg.apns_private_key))
            .and_then(|r| r.map_err(|e| tracing::error!("[push] apns keys: {e:#}")).ok())
            .map(Arc::new);
        Ok(Self {
            dao,
            core,
            web,
            fcm: Fcm::new(timeout)?,
            apns: Apns::new(timeout)?,
            platform_fcm,
            platform_apns,
            apps: Mutex::new(HashMap::new()),
            app_check: Duration::from_secs(cfg.app_check_seconds),
        })
    }

    /// The key browsers subscribe with; `None` when Web Push is not configured.
    pub fn vapid_public_key(&self) -> Option<&str> {
        self.web.as_ref().map(WebPush::public_key)
    }

    /// Whether the app has a notification that reaches the screen; push is offered only then,
    /// so a site without notifications never registers a service worker. Kept for
    /// `app_check_seconds`; a failed check answers no and is not kept.
    pub async fn app_has_notifications(&self, app_code: &str) -> bool {
        if let Some((yes, at)) = self.apps.lock().get(app_code) {
            if at.elapsed() < self.app_check {
                return *yes;
            }
        }
        match self.core.app_notification_count(app_code).await {
            Ok(n) => {
                self.apps.lock().insert(app_code.to_string(), (n > 0, Instant::now()));
                n > 0
            }
            Err(e) => {
                tracing::warn!("could not check the notifications of {app_code}: {e:#}");
                false
            }
        }
    }

    async fn deliver_to(&self, d: &DeviceRow, m: &PushMessage, own_fcm: Option<&FcmAccount>, own_apns: Option<&ApnsAccount>) -> (u64, Platform, Delivery) {
        (d.id, d.platform, self.deliver(d, m, own_fcm, own_apns).await)
    }

    async fn deliver(&self, d: &DeviceRow, m: &PushMessage, own_fcm: Option<&FcmAccount>, own_apns: Option<&ApnsAccount>) -> Delivery {
        match d.platform {
            Platform::Web => match &self.web {
                Some(w) => w.send(&d.token, d.web_p256dh.as_deref(), d.web_auth.as_deref(), m.web_json().to_string().as_bytes()).await,
                None => Delivery::Failed("Web Push is not configured".into()),
            },
            Platform::Android => {
                match pick(d.provider_account.as_deref(), own_fcm, self.platform_fcm.as_deref(), |a| a.project_id.as_str()) {
                    Some(a) => self.fcm.send(a, &d.token, m).await,
                    None => Delivery::Failed(format!("no FCM credentials for project {:?}", d.provider_account)),
                }
            }
            Platform::Ios => {
                let Some(topic) = d.app_identifier.as_deref().filter(|t| !t.is_empty()) else {
                    return Delivery::Gone("iOS device without a bundle id".into());
                };
                match pick(d.provider_account.as_deref(), own_apns, self.platform_apns.as_deref(), |a| a.team_id.as_str()) {
                    Some(a) => self.apns.send(a, &d.token, topic, d.apns_env.as_deref() == Some("sandbox"), m).await,
                    None => Delivery::Failed(format!("no APNs key for team {:?}", d.provider_account)),
                }
            }
        }
    }
}

#[async_trait]
impl PushSink for PushService {
    async fn send_push(
        &self,
        users: &[NotificationUser],
        notification: &CoreNotification,
        app_code: &str,
        connection: &PushConnection,
        payload: &Map<String, Value>,
    ) -> Result<usize> {
        let Some(message) = render(notification, payload, app_code)? else { return Ok(0) };
        let ids: Vec<u64> = users.iter().filter_map(|u| u.id).filter_map(|id| u64::try_from(id).ok()).collect();
        let devices = self.dao.devices_of(app_code, &ids).await?;
        if devices.is_empty() {
            return Ok(0);
        }
        let (own_fcm, own_apns) = client_accounts(connection.details.as_ref());
        // Collected first: a lazy `map` held across the await trips async_trait's `Send` bound.
        let sends: Vec<_> = devices.iter().map(|d| self.deliver_to(d, &message, own_fcm.as_ref(), own_apns.as_ref())).collect();
        let results: Vec<(u64, Platform, Delivery)> = futures::stream::iter(sends).buffer_unordered(PARALLEL).collect().await;

        let mut sent = 0;
        let mut gone = Vec::new();
        for (id, platform, delivery) in results {
            let label = platform.name();
            let outcome = match delivery {
                Delivery::Sent => {
                    sent += 1;
                    "sent"
                }
                Delivery::Gone(why) => {
                    tracing::info!("push device {id} ({label}) is gone: {why}");
                    gone.push(id);
                    "gone"
                }
                Delivery::Failed(why) => {
                    tracing::warn!("push to device {id} ({label}) failed: {why}");
                    "failed"
                }
            };
            metrics::counter!("notification_push_total", "platform" => label, "outcome" => outcome).increment(1);
        }
        self.dao.delete_devices(&gone).await?;
        Ok(sent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notification(v: Value) -> CoreNotification {
        CoreNotification::from_json(&v).unwrap()
    }

    fn data() -> Map<String, Value> {
        json!({"who": "Ann", "id": 7}).as_object().unwrap().clone()
    }

    #[test]
    fn own_template_first_then_inapp() {
        let both = notification(json!({"channelTemplates": {
            "inapp": {"templateParts": {"en": {"title": "In-app ${who}", "description": "long text"}}},
            "push": {"templateParts": {"en": {"title": "Push ${who}", "body": "short", "url": "/page/leads/${id}"}}}
        }}));
        let m = render(&both, &data(), "app").unwrap().unwrap();
        assert_eq!((m.title.as_str(), m.body.as_str(), m.url.as_deref()), ("Push Ann", "short", Some("/page/leads/7")));
        assert_eq!(m.app_code, "app");

        let inapp = notification(json!({"channelTemplates": {
            "inapp": {"templateParts": {"en": {"title": "Hi ${who}", "description": "3 new", "image": " ", "url": "/page/x"}}}
        }}));
        let m = render(&inapp, &data(), "app").unwrap().unwrap();
        assert_eq!((m.title.as_str(), m.body.as_str(), m.image.as_deref(), m.url.as_deref()), ("Hi Ann", "3 new", None, Some("/page/x")));

        let edited = notification(json!({"channelTemplates": {"inapp": {"templateParts": {"en": {"title": "T", "body": "from the editor"}}}}}));
        assert_eq!(render(&edited, &data(), "app").unwrap().unwrap().body, "from the editor");

        let email = notification(json!({"channelTemplates": {"email": {"templateParts": {"en": {"subject": "s"}}}}}));
        assert_eq!(render(&email, &data(), "app").unwrap(), None);
        let blank = notification(json!({"channelTemplates": {"push": {"templateParts": {"en": {"title": " ", "url": "/x"}}}}}));
        assert_eq!(render(&blank, &data(), "app").unwrap(), None);
    }

    #[test]
    fn data_has_the_tap_fields() {
        let m = PushMessage { title: "t".into(), body: "b".into(), image: None, url: None, notification_id: "n".into(), app_code: "a".into() };
        assert_eq!(m.data(), vec![("notificationId", "n".to_string()), ("appCode", "a".to_string())]);
        assert_eq!(m.web_json()["url"], Value::Null);
    }

    #[test]
    fn accounts_by_what_the_device_was_built_against() {
        let (own, platform) = ("own".to_string(), "plat".to_string());
        fn id(s: &String) -> &str {
            s
        }
        assert_eq!(pick(Some("own"), Some(&own), Some(&platform), id), Some(&own));
        assert_eq!(pick(Some("plat"), Some(&own), Some(&platform), id), Some(&platform));
        assert_eq!(pick(Some("other"), Some(&own), Some(&platform), id), None);
        assert_eq!(pick(None, Some(&own), Some(&platform), id), Some(&own));
        assert_eq!(pick(Some(" "), None, Some(&platform), id), Some(&platform));
        assert_eq!(pick::<String>(None, None, None, id), None);
    }

    #[test]
    fn client_accounts_skip_what_does_not_parse() {
        let d = json!({"fcm": {"credentials": {"project_id": "p"}}, "apns": {"teamId": "T"}});
        let (f, a) = client_accounts(d.as_object());
        assert!(f.is_none() && a.is_none());
        let (f, a) = client_accounts(None);
        assert!(f.is_none() && a.is_none());
    }
}
