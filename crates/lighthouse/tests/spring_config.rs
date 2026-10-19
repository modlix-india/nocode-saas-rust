//! The Spring compat endpoint against the Java config server: every golden in
//! `tests/fixtures/spring` was captured from `nocode-saas/config` (native profile) serving the
//! synthetic fixture, and Lighthouse must answer the same bytes (the fixture's path and the
//! version aside: the native backend has no version, Lighthouse gives the snapshot's). Then the
//! guardrails the Java server lacked.

mod common;

use std::time::Duration;

use common::*;
use lighthouse::config::spring::AppRule;
use serde_json::Value;

async fn node(tweak: impl FnOnce(&mut lighthouse::config::LighthouseConfig)) -> TestNode {
    let (l, url) = bind().await;
    let mut c = config_server(&url, &[], &format!("dir:{}", fixture().display()), "dev");
    c.config.spring.profiles = ["ocidev", "ocistage", "ociprod", "default"].map(String::from).to_vec();
    tweak(&mut c);
    let n = TestNode::start(l, c);
    let cs = n.node.config.clone().unwrap();
    assert!(eventually(Duration::from_secs(5), || async { cs.served().is_some() }).await, "no snapshot");
    n
}

fn open_apps(c: &mut lighthouse::config::LighthouseConfig, apps: &[&str]) {
    for a in apps {
        c.config.spring.apps.insert(a.to_string(), AppRule { open: true, ..AppRule::default() });
    }
}

const GOLDENS: &[(&str, &str)] = &[
    ("ai_default", "/ai/default"),
    ("ai_ocidev", "/ai/ocidev"),
    ("core_ocidev", "/core/ocidev"),
    ("core_ocistage", "/core/ocistage"),
    ("gateway_ocidev", "/gateway/ocidev"),
    ("multi_ocidev", "/multi/ocidev"),
    ("security_ocidev", "/security/ocidev"),
    ("security_ocidev_master", "/security/ocidev/master"),
    ("security_ocidev_ociprod", "/security/ocidev,ociprod"),
    ("security_ociprod", "/security/ociprod"),
    ("security_ocistage", "/security/ocistage"),
    ("ssr_ocidev", "/ssr/ocidev"),
    ("ssr_ociprod", "/ssr/ociprod"),
    ("typing_ocidev", "/typing/ocidev"),
    ("unknown_ocidev", "/unknown/ocidev"),
];

#[tokio::test]
async fn the_same_bytes_as_the_java_config_server() {
    let n = node(|c| open_apps(c, &["ai", "core", "gateway", "multi", "security", "ssr", "typing", "unknown"])).await;
    let sha = n.node.config.as_ref().unwrap().served().unwrap().snapshot.sha.clone();
    let root = fixture().canonicalize().unwrap().display().to_string();
    for (golden, path) in GOLDENS {
        let file = fixture().join(format!("../spring/{golden}.json"));
        let want = std::fs::read_to_string(&file).unwrap().replace("{root}", &root).replace("\"version\":null", &format!("\"version\":\"{sha}\""));
        let r = get(format!("{}{path}", n.url), None).await;
        assert_eq!(r.status(), 200, "{path}");
        assert_eq!(r.headers()["content-type"], "application/json");
        let got = r.text().await.unwrap();
        assert!(got == want, "{path} differs from the Java server's answer:\n got: {got}\nwant: {want}");
    }
}

/// What nocode-ai keeps of an answer (app/services/config_server.py): every source in order,
/// `ai.*` and `adzump.*` keys, later sources overwriting earlier ones, shared `redis.*` when
/// there is no `ai.redis`.
fn ai_reads(env: &Value) -> serde_json::Map<String, Value> {
    let mut config = serde_json::Map::new();
    let mut redis = serde_json::Map::new();
    for s in env["propertySources"].as_array().unwrap() {
        for (k, v) in s["source"].as_object().unwrap() {
            if k.starts_with("ai.") || k.starts_with("adzump.") {
                config.insert(k.clone(), v.clone());
            } else if k.starts_with("redis.") {
                redis.insert(k.clone(), v.clone());
            }
        }
    }
    if !config.keys().any(|k| k.starts_with("ai.redis.")) {
        config.extend(redis);
    }
    config
}

/// What ssr-server's configLoader.ts reads: the first source only.
fn ssr_reads(env: &Value) -> Value {
    env["propertySources"][0]["source"].clone()
}

#[tokio::test]
async fn open_apps_are_open_to_the_trusted_networks_only() {
    // The caller (this test, from 127.0.0.1) is outside the trusted network.
    let n = node(|c| {
        c.config.spring.apps.insert("ssr".into(), AppRule { open: true, ..AppRule::default() });
        c.allowed.trusted = vec!["10.255.0.0/16".into()];
    })
    .await;
    let u = |p: &str| format!("{}{p}", n.url);
    assert_eq!(get(u("/ssr/ocidev"), None).await.status(), 401);
    assert_eq!(get(u("/ssr/ocidev"), Some(AI_TOKEN)).await.status(), 200);
}

#[tokio::test]
async fn guardrails() {
    let n = node(|c| {
        open_apps(c, &["security", "broken"]);
        c.config.spring.apps.insert("ai".into(), AppRule { prefixes: vec!["ai.".into(), "adzump.".into(), "redis.".into()], ..AppRule::default() });
        let ssr = ["ssr.", "ssr-", "gateway.", "ui.", "security.appCodeSuffix", "server.port"].map(String::from).to_vec();
        c.config.spring.apps.insert("ssr".into(), AppRule { open: true, prefixes: ssr.clone(), merge_sources: false });
        c.config.spring.apps.insert("ssr-merged".into(), AppRule { open: true, prefixes: ssr, merge_sources: true });
    })
    .await;
    let u = |p: &str| format!("{}{p}", n.url);
    let status = |r: reqwest::Response| r.status().as_u16();

    // Reserved names, apps not listed, profiles and labels not served.
    assert_eq!(status(get(u("/eureka/ocidev"), None).await), 404);
    assert_eq!(status(get(u("/v1/ocidev"), None).await), 404);
    assert_eq!(status(get(u("/core/ocidev"), None).await), 404);
    assert_eq!(status(get(u("/security/ocitest"), None).await), 403);
    assert_eq!(status(get(u("/security/ocidev,ocitest"), None).await), 403);
    assert_eq!(status(get(u("/security/ocidev/main"), None).await), 404);
    assert_eq!(status(get(u("/security/ocidev/feature(_)x"), None).await), 404);
    let sha = n.node.config.as_ref().unwrap().served().unwrap().snapshot.sha.clone();
    let by_sha: Value = get(u(&format!("/security/ocidev/{sha}")), None).await.json().await.unwrap();
    assert_eq!(by_sha["label"], Value::String(sha));

    // A file Spring cannot read: Spring Boot's error body, as the Java server answered.
    let r = get(u("/broken/ocidev"), None).await;
    assert_eq!(r.status(), 500);
    let body: Value = r.json().await.unwrap();
    assert_eq!((body["status"].as_u64(), body["error"].as_str(), body["path"].as_str()), (Some(500), Some("Internal Server Error"), Some("/broken/ocidev")));

    // ai needs a token: Bearer, or Basic as nocode-ai sends it from a URL with credentials.
    assert_eq!(status(get(u("/ai/ocidev"), None).await), 401);
    assert_eq!(status(get(u("/ai/ocidev"), Some(UNITS_TOKEN)).await), 403);
    assert_eq!(status(get(u("/ai/ocidev"), Some(ADMIN_TOKEN)).await), 200);
    let with_userinfo = n.url.replace("http://", &format!("http://ai:{AI_TOKEN}@"));
    let ai: Value = http().get(format!("{with_userinfo}/ai/ocidev")).send().await.unwrap().json().await.unwrap();
    for s in ai["propertySources"].as_array().unwrap() {
        assert!(s["source"].as_object().unwrap().keys().all(|k| k.starts_with("ai.") || k.starts_with("adzump.") || k.starts_with("redis.")));
    }
    // nocode-ai reads the same from the guarded answer as from the Java server's.
    let java: Value = serde_json::from_str(&std::fs::read_to_string(fixture().join("../spring/ai_ocidev.json")).unwrap()).unwrap();
    assert_eq!(ai_reads(&ai), ai_reads(&java));
    assert_eq!(ai["propertySources"].as_array().unwrap().len(), java["propertySources"].as_array().unwrap().len());

    // ssr is open; it reads the first source only, and the prefixes keep what it reads.
    let ssr: Value = get(u("/ssr/ociprod"), None).await.json().await.unwrap();
    let java: Value = serde_json::from_str(&std::fs::read_to_string(fixture().join("../spring/ssr_ociprod.json")).unwrap()).unwrap();
    assert_eq!(ssr_reads(&ssr), ssr_reads(&java));
    let ssr_dev: Value = get(u("/ssr/ocidev"), None).await.json().await.unwrap();
    let first = ssr_reads(&ssr_dev);
    assert!(first.get("ssr.redis.url").is_some() && first.get("spring.r2dbc.password").is_none(), "secrets of other services stay out");

    // Merged: one source with every key's winning value.
    let merged: Value = get(u("/ssr-merged/ociprod"), None).await.json().await.unwrap();
    let sources = merged["propertySources"].as_array().unwrap();
    assert_eq!(sources.len(), 1);
    // From application-ociprod.yml and from application.yml's first document.
    assert_eq!(sources[0]["source"]["ui.cdnHostName"], "cdn.fixture.test");
    assert_eq!(sources[0]["source"]["ui.jsURL"], "https://cdn.fixture.test/js/dist");
}

#[tokio::test]
async fn nothing_is_served_before_a_snapshot_or_without_a_config_server() {
    let (l, url) = bind().await;
    let mut c = config_server(&url, &[], "dir:/nonexistent/lighthouse-fixture", "dev");
    open_apps(&mut c, &["security"]);
    let _n = TestNode::start(l, c);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(get(format!("{url}/security/ocidev"), None).await.status(), 503);
    let view: Value = get(format!("{url}/v1/config"), Some(ADMIN_TOKEN)).await.json().await.unwrap();
    assert!(view["lastError"].as_str().unwrap().contains("cannot be read"));
    assert_eq!(view["snapshot"], Value::Null);

    let (l, url) = bind().await;
    let _off = TestNode::start(l, config(&url, &[]));
    assert_eq!(get(format!("{url}/security/ocidev"), None).await.status(), 404);
    let view: Value = get(format!("{url}/v1/config"), Some(ADMIN_TOKEN)).await.json().await.unwrap();
    assert_eq!(view["enabled"], false);
}
