//! The Eureka API's edges: formats, ETags, warming up, validation, and who may call.

mod common;

use std::time::Duration;

use common::*;
use lighthouse_client::replication::{Digest, REPLICATION_HEADER};
use lighthouse_client::wire::{ApplicationEnvelope, ApplicationsEnvelope, InstanceEnvelope};
use serde_json::{json, Value};

async fn single() -> TestNode {
    let (l, url) = bind().await;
    let n = TestNode::start(l, config(&url, &[]));
    wait_ready(&[&n]).await;
    n
}

#[tokio::test]
async fn formats_etags_and_lookups() {
    let n = single().await;
    let (e, c) = (n.eureka(), http());
    assert_eq!(register(&n.url, "files", "f1", 1).await, 204);

    // XML unless Accept names JSON; /apps/ is /apps.
    let r = c.get(format!("{e}/apps/")).header("accept", "*/*").send().await.unwrap();
    assert_eq!(r.headers()["content-type"], "application/xml");
    let r = c.get(format!("{e}/apps")).header("accept", "application/json, text/plain").send().await.unwrap();
    assert_eq!(r.headers()["content-type"], "application/json");
    let tag = r.headers()["etag"].to_str().unwrap().to_string();
    let apps: ApplicationsEnvelope = r.json().await.unwrap();
    assert_eq!(apps.applications.apps_hashcode, "UP_1_");

    // If-None-Match: 304 while nothing changed, the body again after a change.
    let r = c.get(format!("{e}/apps")).header("accept", "application/json").header("if-none-match", &tag).send().await.unwrap();
    assert_eq!(r.status(), 304);
    assert_eq!(r.headers()["etag"], tag.as_str());
    let x = c.get(format!("{e}/apps")).header("if-none-match", &tag).send().await.unwrap();
    assert_eq!(x.status(), 200, "the XML has its own tag");
    assert_eq!(heartbeat(&n.url, "FILES", "f1", 1).await, 200);
    let r = c.get(format!("{e}/apps")).header("accept", "application/json").header("if-none-match", &tag).send().await.unwrap();
    assert_eq!(r.status(), 304, "a heartbeat is not a change");
    assert_eq!(register(&n.url, "files", "f2", 1).await, 204);
    let r = c.get(format!("{e}/apps")).header("accept", "application/json").header("if-none-match", &tag).send().await.unwrap();
    assert_eq!(r.status(), 200);

    // Delta, an app (any case), an instance.
    let d = c.get(format!("{e}/apps/delta")).header("accept", "application/json").send().await.unwrap();
    let dtag = d.headers()["etag"].to_str().unwrap().to_string();
    let delta: ApplicationsEnvelope = d.json().await.unwrap();
    assert_eq!(delta.applications.applications[0].instances.len(), 2);
    let d = c.get(format!("{e}/apps/delta")).header("accept", "application/json").header("if-none-match", &dtag).send().await.unwrap();
    assert_eq!(d.status(), 304);
    let a: ApplicationEnvelope = c.get(format!("{e}/apps/files")).header("accept", "application/json").send().await.unwrap().json().await.unwrap();
    assert_eq!((a.application.name.as_str(), a.application.instances.len()), ("FILES", 2));
    let x = c.get(format!("{e}/apps/FILES")).send().await.unwrap().text().await.unwrap();
    assert!(x.starts_with("<application>\n  <name>FILES</name>"));
    let i: InstanceEnvelope = c.get(format!("{e}/apps/FILES/f1")).header("accept", "application/json").send().await.unwrap().json().await.unwrap();
    assert_eq!(i.instance.instance_id, "f1");
    let x = c.get(format!("{e}/apps/FILES/f1")).send().await.unwrap().text().await.unwrap();
    assert!(x.starts_with("<instance>"));

    // Not found: Spring's error shape.
    let r = c.get(format!("{e}/apps/NOBODY")).send().await.unwrap();
    assert_eq!(r.status(), 404);
    let v: Value = r.json().await.unwrap();
    assert_eq!((v["status"].as_u64(), v["path"].as_str()), (Some(404), Some("/eureka/apps/NOBODY")));
    for (method, path) in [("GET", "apps/FILES/nope"), ("PUT", "apps/FILES/nope"), ("DELETE", "apps/FILES/nope"),
        ("PUT", "apps/FILES/nope/status?value=UP"), ("DELETE", "apps/FILES/nope/status")]
    {
        let r = c.request(method.parse().unwrap(), format!("{e}/{path}")).send().await.unwrap();
        assert_eq!(r.status(), 404, "{method} {path}");
    }

    // A stale replicated heartbeat gets our copy back, in the format asked for.
    let r = c.put(format!("{e}/apps/FILES/f1?lastDirtyTimestamp=0")).header(REPLICATION_HEADER, "true").send().await.unwrap();
    assert_eq!(r.status(), 409);
    assert!(r.text().await.unwrap().starts_with("<instance>"));
    let r = c
        .put(format!("{e}/apps/FILES/f1?lastDirtyTimestamp=0&overriddenStatus=UNKNOWN"))
        .header(REPLICATION_HEADER, "true")
        .header("accept", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    let mine: InstanceEnvelope = r.json().await.unwrap();
    assert_eq!(mine.instance.last_dirty_timestamp, 1);

    // The digest and the operator view.
    let d: Digest = c.get(format!("{}/v1/peer/digest", n.url)).send().await.unwrap().json().await.unwrap();
    assert_eq!(d.instances.len(), 2);
    let v = operator(&n.url).await;
    assert_eq!(v["apps"][0]["instances"].as_array().unwrap().len(), 2);
    assert_eq!(v["instance"]["peers"], 0);
}

#[tokio::test]
async fn registrations_are_checked() {
    let (l, url) = bind().await;
    let mut cfg = config(&url, &[]);
    cfg.allowed.apps = vec!["files".into()];
    let n = TestNode::start(l, cfg);
    wait_ready(&[&n]).await;
    let (e, c) = (n.eureka(), http());
    let post = |app: &str, body: Value| c.post(format!("{e}/apps/{app}")).json(&body).send();

    let mut b = body("files", "f1", 1, 1);
    // A bare instance (no "instance" wrapper) is read too, and the app comes from the path.
    let mut bare = b["instance"].clone();
    bare.as_object_mut().unwrap().remove("app");
    assert_eq!(post("files", bare).await.unwrap().status(), 204);
    assert!(n.node.registry.instance("FILES", "f1").is_some());

    let message = |r: reqwest::Response| async move { r.json::<Value>().await.unwrap()["message"].as_str().unwrap().to_string() };
    b["instance"]["hostName"] = json!("");
    assert_eq!(message(post("files", b.clone()).await.unwrap()).await, "Missing hostname");
    b["instance"]["hostName"] = json!("h");
    b["instance"]["ipAddr"] = json!(null);
    assert_eq!(message(post("files", b.clone()).await.unwrap()).await, "Missing ip address");
    b["instance"]["ipAddr"] = json!("1.2.3.4");
    let r = post("other", b.clone()).await.unwrap();
    assert_eq!(r.status(), 400);
    assert_eq!(message(r).await, "Mismatched appName, expecting OTHER but was FILES");
    let r = c.post(format!("{e}/apps/FILES")).body("<instance/>").send().await.unwrap();
    assert_eq!(r.status(), 400);

    // [allowed] apps: OTHER may not register.
    let r = post("other", body("other", "o1", 1, 1)).await.unwrap();
    assert_eq!(r.status(), 403);
    // A peer's replication of it is not the client's call: it is taken.
    let r = c.post(format!("{e}/apps/OTHER")).header(REPLICATION_HEADER, "true").json(&body("other", "o1", 1, 1)).send().await.unwrap();
    assert_eq!(r.status(), 204);

    // Query values.
    let r = c.put(format!("{e}/apps/FILES/f1?lastDirtyTimestamp=soon")).send().await.unwrap();
    assert_eq!(r.status(), 400);
    let r = c.put(format!("{e}/apps/FILES/f1?lastDirtyTimestamp=")).send().await.unwrap();
    assert_eq!(r.status(), 200, "an empty value is no value");
    for bad in ["", "?value=SIDEWAYS", "?value=UP&lastDirtyTimestamp=x"] {
        let r = c.put(format!("{e}/apps/FILES/f1/status{bad}")).send().await.unwrap();
        assert_eq!(r.status(), 400, "{bad}");
    }
    let r = c.delete(format!("{e}/apps/FILES/f1/status?lastDirtyTimestamp=x")).send().await.unwrap();
    assert_eq!(r.status(), 400);
    let r = c.put(format!("{e}/apps/FILES/f1/status?value=out_of_service")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let r = c.delete(format!("{e}/apps/FILES/f1/status?value=UP")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(n.node.registry.instance("FILES", "f1").unwrap().status, lighthouse_client::Status::Up);
}

#[tokio::test]
async fn warming_answers_503_to_discovery_only() {
    let (l, url) = bind().await;
    // A peer that does not exist and a long wait: this instance stays warm for the test.
    let (dead, dead_url) = bind().await;
    drop(dead);
    let mut cfg = config(&url, &[dead_url]);
    cfg.registry.startup_wait_seconds = 30;
    // The digest comparison waits for readiness too.
    cfg.registry.digest_interval_seconds = 1;
    let n = TestNode::start(l, cfg);
    let c = http();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(c.get(format!("{url}/eureka/apps")).send().await.unwrap().status(), 503);
    assert_eq!(register(&url, "files", "f1", 1).await, 204);
    assert_eq!(heartbeat(&url, "FILES", "f1", 1).await, 200);
    // A peer may read single instances (digest repair) while warming.
    let r = c.get(format!("{url}/eureka/apps/FILES/f1")).header(REPLICATION_HEADER, "true").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(c.get(format!("{url}/eureka/apps/FILES/f1")).send().await.unwrap().status(), 503);
    assert_eq!(operator(&url).await["ready"], false);
    drop(n);
}

#[tokio::test]
async fn networks_and_the_peer_token() {
    // Only 10.0.0.0/8 may call: this test's 127.0.0.1 is refused.
    let (l, url) = bind().await;
    let mut cfg = config(&url, &[]);
    cfg.allowed.networks = vec!["10.0.0.0/8".into()];
    let _closed = TestNode::start(l, cfg);
    let r = http().get(format!("{url}/eureka/apps")).send().await.unwrap();
    assert_eq!(r.status(), 403);

    // With a peer token, peer routes and replicated calls need it.
    let (l, url) = bind().await;
    let mut cfg = config(&url, &[]);
    cfg.registry.peer_token = "s3cret".into();
    let n = TestNode::start(l, cfg);
    wait_ready(&[&n]).await;
    let c = http();
    let batch = json!({"replicationList": []});
    let r = c.post(format!("{url}/eureka/peerreplication/batch")).json(&batch).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let r = c.post(format!("{url}/eureka/peerreplication/batch")).bearer_auth("wrong").json(&batch).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let r = c.post(format!("{url}/eureka/peerreplication/batch")).bearer_auth("s3cret").json(&batch).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(c.get(format!("{url}/v1/peer/digest")).send().await.unwrap().status(), 401);
    let r = c.post(format!("{url}/eureka/apps/FILES")).header(REPLICATION_HEADER, "true").json(&body("files", "f", 1, 1)).send().await.unwrap();
    assert_eq!(r.status(), 401, "no client may pass for a peer");
    assert_eq!(register(&url, "files", "f", 1).await, 204, "clients need no token");
}

#[tokio::test]
async fn the_dashboard_and_its_views() {
    let (l, url) = bind().await;
    let (dead, dead_url) = bind().await;
    drop(dead);
    let mut cfg = config(&url, &[dead_url.clone()]);
    cfg.registry.startup_wait_seconds = 0;
    let n = TestNode::start(l, cfg);
    wait_ready(&[&n]).await;
    let c = http();
    for path in ["/", "/dashboard"] {
        let r = c.get(format!("{url}{path}")).send().await.unwrap();
        assert_eq!(r.status(), 200, "{path}");
        assert_eq!(r.headers()["content-type"], "text/html; charset=utf-8");
        assert!(r.headers()["content-security-policy"].to_str().unwrap().contains("default-src 'none'"));
        let html = r.text().await.unwrap();
        assert!(html.contains("<title>Lighthouse</title>") && html.contains("id=\"config-units\""));
    }

    assert_eq!(register(&url, "files", "f1", 1).await, 204);
    let mut b = body("files", "f2", 2, 1);
    b["instance"]["metadata"]["configVersion"] = json!("abc123");
    assert_eq!(c.post(format!("{url}/eureka/apps/FILES")).json(&b).send().await.unwrap().status(), 204);
    let v: Value = c.get(format!("{url}/v1/registry")).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["manageable"], true);
    assert_eq!(v["instance"]["ready"], true);
    assert_eq!(v["instance"]["id"], url.as_str());
    assert_eq!(v["instance"]["version"], env!("CARGO_PKG_VERSION"));
    assert!(v["instance"]["renewalThreshold"].as_f64().unwrap() > 0.0);
    assert_eq!(v["counts"], json!({"UP": 2}));
    let f2 = &v["apps"][0]["instances"][1];
    assert_eq!((f2["port"].as_u64(), f2["metadata"]["configVersion"].as_str()), (Some(2), Some("abc123")));

    let p: Value = c.get(format!("{url}/v1/peers")).send().await.unwrap().json().await.unwrap();
    let peer = &p["peers"][0];
    assert_eq!((peer["url"].as_str(), peer["reachable"].as_bool()), (Some(dead_url.as_str()), Some(false)));
    assert!(peer["lastSuccessAgoMs"].is_null());

    // Management: the token, and the usual answers.
    let m = |rest: &str| format!("{url}/v1/admin/apps/FILES/{rest}");
    assert_eq!(admin("PUT", m("f1/status"), None).await, 401);
    assert_eq!(admin("PUT", m("f1/status"), Some("nope")).await, 401);
    assert_eq!(admin("PUT", m("f1/status?value=SIDEWAYS"), Some(ADMIN_TOKEN)).await, 400);
    assert_eq!(admin("PUT", m("f1/status"), Some(ADMIN_TOKEN)).await, 200, "OUT_OF_SERVICE by default");
    assert_eq!(n.node.registry.instance("FILES", "f1").unwrap().status, lighthouse_client::Status::OutOfService);
    assert_eq!(admin("DELETE", m("f1/status?value=UP"), Some(ADMIN_TOKEN)).await, 200);
    assert_eq!(n.node.registry.instance("FILES", "f1").unwrap().status, lighthouse_client::Status::Up);
    assert_eq!(admin("DELETE", m("f1"), Some(ADMIN_TOKEN)).await, 200);
    assert!(n.node.registry.instance("FILES", "f1").is_none());
    for (method, rest) in [("PUT", "zz/status"), ("DELETE", "zz/status"), ("DELETE", "zz")] {
        assert_eq!(admin(method, m(rest), Some(ADMIN_TOKEN)).await, 404, "{method} {rest}");
    }

    // Without a configured hash the page is read-only and management is refused.
    let (l, url) = bind().await;
    let mut cfg = config(&url, &[]);
    cfg.admin_token_sha256 = String::new();
    let ro = TestNode::start(l, cfg);
    wait_ready(&[&ro]).await;
    assert_eq!(register(&url, "files", "f1", 1).await, 204);
    let v: Value = c.get(format!("{url}/v1/registry")).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["manageable"], false);
    assert_eq!(admin("PUT", format!("{url}/v1/admin/apps/FILES/f1/status"), Some(ADMIN_TOKEN)).await, 403);
    assert_eq!(admin("DELETE", format!("{url}/v1/admin/apps/FILES/f1"), Some(ADMIN_TOKEN)).await, 403);
    let p: Value = c.get(format!("{url}/v1/peers")).send().await.unwrap().json().await.unwrap();
    assert_eq!(p["peers"], json!([]));
}
