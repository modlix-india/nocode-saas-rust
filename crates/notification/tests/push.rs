//! Two notification instances in one process, each with its own streams (`Hub`), joined by the
//! local Redis (gated: `NOTIFICATION_LOCAL_STACK=1` and `MODLIX__REDIS__URL`, from
//! `eval "$(tools/local-env.py)"`). A data notification and an in-app notification consumed by
//! one instance reach the streams open on both, once each; the data notification stores
//! nothing. The schema is a `RUSTTEST_notif_*` scratch one and the channel a scratch name.

mod common;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use common::{local_stack, with_scratch, Answer, Fake, CONN_PATH, NOTIF_PATH, USERS_PATH};
use futures::StreamExt;
use notification::calls::{CoreClient, DirectoryClient};
use notification::dao::Dao;
use notification::email::EmailSink;
use notification::inapp::InAppService;
use notification::model::{CoreNotification, MailConnection, NotificationUser};
use notification::push::Push;
use notification::queue::{handle, Settle};
use notification::send::{Outcome, SendService};
use notification::sse::{Hub, Subscription};
use platform::cache::CacheService;
use platform::upstream::Upstream;
use serde_json::{json, Map, Value};

struct NoMail;

#[async_trait]
impl EmailSink for NoMail {
    async fn send_email(&self, _: &NotificationUser, _: &MailConnection, _: &CoreNotification, _: &Map<String, Value>) -> Result<bool> {
        Ok(false)
    }
}

fn redis_url() -> Option<String> {
    std::env::var("MODLIX__REDIS__URL").ok().filter(|u| !u.is_empty())
}

/// The next frame of `s` within `ms`, as text.
async fn next(s: &mut Subscription, ms: u64) -> Option<String> {
    match tokio::time::timeout(Duration::from_millis(ms), s.next()).await {
        Ok(Some(Ok(b))) => Some(String::from_utf8_lossy(&b).into_owned()),
        _ => None,
    }
}

/// Waits until both instances hear the channel: a probe published by `a` reaches a probe
/// stream on each hub.
async fn wait_until_listening(a: &Push, hubs: [&Arc<Hub>; 2]) {
    let mut probes: Vec<Subscription> = hubs.iter().map(|h| h.subscribe("probe".into())).collect();
    for p in probes.iter_mut() {
        let _ = next(p, 1000).await;
    }
    let mut heard = [false, false];
    for _ in 0..100 {
        a.deliver(&["probe".to_string()], &Bytes::from_static(b":probe\n\n")).await;
        for (i, p) in probes.iter_mut().enumerate() {
            while let Some(f) = next(p, 50).await {
                heard[i] |= f == ":probe\n\n";
            }
        }
        if heard == [true, true] {
            return;
        }
    }
    panic!("the instances did not start listening: {heard:?}");
}

#[tokio::test]
#[ignore = "needs the local MySQL and Redis: NOTIFICATION_LOCAL_STACK=1"]
async fn data_and_in_app_notifications_reach_both_instances_through_redis() {
    if !local_stack() {
        return;
    }
    let Some(url) = redis_url() else { panic!("MODLIX__REDIS__URL is not set: eval \"$(tools/local-env.py)\"") };
    with_scratch(|pool, _| async move {
        let channel = format!("rusttest-notificationPush-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let (hub_a, hub_b) = (Hub::new(16), Hub::new(16));
        let push_a = Push::new(hub_a.clone(), Some(CacheService::new("cmn", "evictionChannel", Some(&url)).unwrap()), &channel);
        let push_b = Push::new(hub_b.clone(), Some(CacheService::new("cmn", "evictionChannel", Some(&url)).unwrap()), &channel);
        let listeners = [push_a.spawn_listener().unwrap(), push_b.spawn_listener().unwrap()];
        wait_until_listening(&push_a, [&hub_a, &hub_b]).await;

        let (fake, base) = Fake::start().await;
        fake.answer("GET", CONN_PATH, Answer::json(json!({"inApp": true})));
        fake.answer(
            "GET",
            NOTIF_PATH,
            Answer::json(json!({"name": "hello", "notificationType": "INFO",
                "channelTemplates": {"inapp": {"templateParts": {"en": {"title": "Hi ${who}", "description": "d"}}}}})),
        );
        fake.answer("POST", USERS_PATH, Answer::json(json!([{"id": 142, "clientId": 1}])));
        let t = Duration::from_secs(5);
        let dao = Dao::new(pool.clone());
        // Instance A consumes; the user's tabs are open on A and on B.
        let service = SendService {
            core: CoreClient::new(Upstream::fixed(&[&base]), t).unwrap(),
            directory: DirectoryClient::new(Upstream::fixed(&[&base]), t).unwrap(),
            email: Arc::new(NoMail),
            in_app: Arc::new(InAppService { dao: dao.clone(), push: push_a.clone() }),
            push: push_a.clone(),
            prefs: None,
        };
        let mut tab_a = hub_a.subscribe("142-rsapp".into());
        let mut tab_b = hub_b.subscribe("142-rsapp".into());
        for tab in [&mut tab_a, &mut tab_b] {
            assert!(next(tab, 1000).await.unwrap().starts_with("event:init"));
        }

        // A data notification, as core publishes it.
        let expires = chrono::Utc::now().timestamp_millis() + 60_000;
        let body = json!({"id": "x", "appCode": "rsapp", "clientCode": "SYSTEM", "urlClientCode": "SYSTEM", "targetType": "User Id",
            "targetId": 142, "draft": false, "kind": "DATA", "eventName": "incomingCall", "data": {"from": "+9180"}, "expiresAt": expires});
        let settled = handle(&service, Some("application/json"), body.to_string().as_bytes()).await;
        assert_eq!(settled, Settle::Ack(Some(Outcome::Pushed { users: 1 })));
        for tab in [&mut tab_a, &mut tab_b] {
            let frame = next(tab, 3000).await.expect("the data notification arrived");
            assert!(frame.starts_with("event:incomingCall\ndata:{\"event\":\"incomingCall\",\"data\":{\"from\":\"+9180\"},\"id\":"), "{frame}");
            assert_eq!(next(tab, 300).await, None, "once, not twice");
        }
        let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM notification_inapp").fetch_one(&pool).await.unwrap();
        assert_eq!(rows.0, 0, "a data notification stores nothing");
        assert!(fake.calls_to(CONN_PATH).is_empty() && fake.calls_to(NOTIF_PATH).is_empty(), "nor reads a definition");

        // An expired one is dropped: neither tab hears it.
        let mut stale = body.clone();
        stale["expiresAt"] = json!(expires - 120_000);
        let settled = handle(&service, Some("application/json"), stale.to_string().as_bytes()).await;
        assert_eq!(settled, Settle::Ack(Some(Outcome::Expired)));
        for tab in [&mut tab_a, &mut tab_b] {
            assert_eq!(next(tab, 300).await, None);
        }

        // An in-app notification: stored once, pushed to both instances' tabs (DIFFERENCES N1).
        let body = json!({"appCode": "rsapp", "clientCode": "SYSTEM", "urlClientCode": "SYSTEM", "targetType": "User Id",
            "targetId": 142, "notificationName": "hello", "connectionName": "c", "draft": false, "payload": {"who": "Ann"}});
        let settled = handle(&service, Some("application/json"), body.to_string().as_bytes()).await;
        assert_eq!(settled, Settle::Ack(Some(Outcome::Sent { emails: 0, in_app: true })));
        for tab in [&mut tab_a, &mut tab_b] {
            let frame = next(tab, 3000).await.expect("the in-app notification arrived");
            assert!(frame.starts_with("event:notification\ndata:{\n") && frame.contains("data:  \"title\" : \"Hi Ann\",\n"), "{frame}");
            assert_eq!(next(tab, 300).await, None, "once, not twice");
        }
        let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM notification_inapp").fetch_one(&pool).await.unwrap();
        assert_eq!(rows.0, 1);

        for l in listeners {
            l.abort();
        }
    })
    .await;
}
