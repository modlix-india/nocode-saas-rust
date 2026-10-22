//! The AMQP message bodies compared with what Spring AMQP's `Jackson2JsonMessageConverter`
//! made from the same objects with the services' `ObjectMapper` (recorded with JDK 21 and the
//! local core's classpath, `fixtures/mq_java21.txt`).

use connections::context::Caller;
use connections::mq::{jackson_authentication, EventMessage, NotificationMessage, Route};
use serde_json::{json, Map, Value};

fn java_bodies() -> Vec<String> {
    let text = include_str!("fixtures/mq_java21.txt");
    text.split("BODY<<").skip(1).map(|s| s.split(">>").next().unwrap().to_string()).collect()
}

/// The data map, in the order the Java harness put its entries.
fn data() -> Map<String, Value> {
    let mut d = Map::new();
    d.insert("a".into(), json!(1));
    d.insert("b".into(), Value::Null);
    d.insert("c".into(), json!(""));
    d.insert("d".into(), json!([1, "x"]));
    d.insert("e".into(), json!({}));
    let mut f = Map::new();
    f.insert("g".into(), Value::Null);
    f.insert("h".into(), json!([]));
    d.insert("f".into(), Value::Object(f));
    d.insert("h".into(), json!(1.5));
    d.insert("i".into(), json!(10000000000i64));
    d.insert("j".into(), json!(true));
    d.insert("k".into(), json!(2.5));
    let mut o1 = Map::new();
    o1.insert("zeta".into(), json!(1));
    o1.insert("alpha".into(), json!("x"));
    o1.insert("notFoundPage".into(), Value::Null);
    d.insert("arr".into(), json!([Value::Object(o1), []]));
    d.insert("defaultPage".into(), json!("home"));
    d.insert("notFoundPage".into(), json!("nf"));
    d.insert("links".into(), json!({"x": 1}));
    d.insert("esc".into(), json!("q\"u\\o\u{1}\u{2028}/\u{e9}"));
    d
}

fn caller() -> Caller {
    let raw: Value = serde_json::from_str(include_str!("fixtures/security_context_sample.json")).unwrap();
    Caller {
        present: true,
        authenticated: raw["authenticated"].as_bool().unwrap(),
        raw: raw.as_object().cloned(),
        url_client_code: None,
        url_app_code: None,
        ..Default::default()
    }
}

#[test]
fn event_messages_match_java() {
    let java = java_bodies();
    let e1 = EventMessage {
        event_name: Some("USER_CREATED".into()),
        client_code: Some("SYSTEM".into()),
        app_code: Some("appbuilder".into()),
        data: Some(data()),
        authentication: Some(jackson_authentication(&caller())),
        ..Default::default()
    };
    assert_eq!(e1.to_json(), java[0]);
    let e2 = EventMessage {
        event_name: Some("X".into()),
        client_code: Some("".into()),
        app_code: Some("app".into()),
        x_debug: Some("dbg-1".into()),
        draft: true,
        data: Some(Map::new()),
        authentication: None,
    };
    assert_eq!(e2.to_json(), java[1]);
}

fn java_id(body: &str) -> String {
    let v: Value = serde_json::from_str(body).unwrap();
    v["id"].as_str().unwrap().to_string()
}

#[test]
fn notification_messages_match_java() {
    let java = java_bodies();
    let n1 = NotificationMessage {
        id: java_id(&java[2]),
        app_code: Some("leadzump".into()),
        client_code: Some("FIN".into()),
        url_client_code: Some("FIN".into()),
        triggered_user_id: Some(142),
        target_id: Some(json!(7)),
        target_type: Some("User Id".into()),
        target_code: None,
        filter_authorization: Some("Authorities.X".into()),
        notification_name: Some("welcome".into()),
        notification_category: Some("cat".into()),
        connection_name: Some("notification".into()),
        x_debug: None,
        draft: false,
        payload: Some(data()),
        ..Default::default()
    };
    assert_eq!(n1.to_json(), java[2]);
    let n2 = NotificationMessage {
        id: java_id(&java[3]),
        app_code: Some("a".into()),
        x_debug: Some("d".into()),
        draft: true,
        ..Default::default()
    };
    assert_eq!(n2.to_json(), java[3]);
}

#[test]
fn routing_keys_rotate_like_java() {
    let r = Route::notifications();
    let keys: Vec<String> = (0..4).map(|_| r.next_key().to_string()).collect();
    assert_eq!(keys, ["notifications2", "notifications3", "notifications1", "notifications2"]);
}

// --- `DraftEventPropagationTest` and `DraftNotificationPropagationTest` (core), ported: the
// draft marker of the caller's surface is stamped at publish time and is in the JSON the
// broker carries. Java's third case round-trips the message through Spring's converter; here
// the body is read back as the JSON a consumer reads.

struct Allow;

#[async_trait::async_trait]
impl connections::notification::HierarchyChecks for Allow {
    async fn is_user_part_of_hierarchy(&self, _: i128, _: &str) -> connections::error::ConnResult<bool> {
        Ok(true)
    }
    async fn does_client_manage_client(&self, _: u64, _: i128) -> connections::error::ConnResult<bool> {
        Ok(true)
    }
    async fn does_client_manage_client_code(&self, _: &str, _: &str) -> connections::error::ConnResult<bool> {
        Ok(true)
    }
}

fn surface_caller(draft: bool) -> Caller {
    Caller {
        present: true,
        authenticated: true,
        user_id: Some(142),
        client_code: Some("SYSTEM".into()),
        url_client_code: Some("SYSTEM".into()),
        url_app_code: Some("appbuilder".into()),
        system_client: true,
        draft,
        ..Default::default()
    }
}

fn event_on(draft: bool) -> Value {
    let event = EventMessage { event_name: Some("OrderPlaced".into()), app_code: Some("appbuilder".into()), ..Default::default() };
    let (_, body) = connections::mq::prepare_event(&Route::events(), &surface_caller(draft), event);
    serde_json::from_str(&body).unwrap()
}

async fn notification_on(draft: bool) -> Value {
    let req = connections::notification::NotificationRequest {
        target_type: "User Id".into(),
        target_id: Some(7),
        notification_name: Some("welcome".into()),
        ..Default::default()
    };
    let (_, m) = connections::notification::prepare(&Route::notifications(), &Allow, &surface_caller(draft), req).await.unwrap().unwrap();
    serde_json::from_str(&m.to_json()).unwrap()
}

#[test]
fn draft_event_carries_marker() {
    let sent = event_on(true);
    assert_eq!(sent["draft"], true, "the marker was lost at publish time, so the consumer would write to the live database");
    assert_eq!(sent["eventName"], "OrderPlaced");
}

#[test]
fn live_event_carries_no_marker() {
    assert_eq!(event_on(false)["draft"], false, "a live event must not be marked as draft");
}

#[tokio::test]
async fn draft_notification_carries_marker() {
    let sent = notification_on(true).await;
    assert_eq!(sent["draft"], true);
    assert_eq!(sent["notificationName"], "welcome");
}

#[tokio::test]
async fn live_notification_carries_no_marker() {
    assert_eq!(notification_on(false).await["draft"], false, "a live notification must not be marked as draft");
}
