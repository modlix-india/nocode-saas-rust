//! The config endpoints: tokens and scopes, the units' documents (each with its own secrets
//! only), versions and ETags, the env files (byte for byte the script's), missing values
//! answered by name only, the admin refresh, the peer snapshot, and `lighthouse parity`.

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use common::*;
use lighthouse::config::source::Snapshot;
use serde_json::Value;

async fn node(env: &str) -> TestNode {
    let (l, url) = bind().await;
    let c = config_server(&url, &[], &format!("dir:{}", fixture().display()), env);
    let n = TestNode::start(l, c);
    let cs = n.node.config.clone().unwrap();
    assert!(eventually(Duration::from_secs(5), || async { cs.served().is_some() }).await, "no snapshot");
    n
}

fn golden(env: &str, file: &str) -> String {
    std::fs::read_to_string(fixture().join("../render").join(env).join(file)).unwrap()
}

/// The value of a variable in one of the script's env files.
fn golden_var(env: &str, file: &str, name: &str) -> String {
    let text = golden(env, file);
    let raw = text.lines().find_map(|l| l.strip_prefix(&format!("{name}="))).unwrap();
    lighthouse::config::cli::env_value(raw)
}

#[tokio::test]
async fn unit_documents() {
    let n = node("dev").await;
    let u = |p: &str| format!("{}{p}", n.url);

    let r = get(u("/v1/units/multi/config"), None).await;
    assert_eq!(r.status(), 401);
    assert!(r.headers().get("www-authenticate").is_some());
    assert_eq!(get(u("/v1/units/multi/config"), Some(AI_TOKEN)).await.status(), 403);
    assert_eq!(get(u("/v1/units/multi/config"), Some(MULTI_TOKEN)).await.status(), 200);
    assert_eq!(get(u("/v1/units/core-exec/config"), Some(MULTI_TOKEN)).await.status(), 403, "a token limited to multi");
    assert_eq!(get(u("/v1/units/multi/config"), Some(ADMIN_TOKEN)).await.status(), 200);
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("multi:{UNITS_TOKEN}"));
    let r = http().get(u("/v1/units/multi/config")).header("authorization", format!("Basic {basic}")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let etag = r.headers()["etag"].to_str().unwrap().to_string();
    let body: Value = r.json().await.unwrap();
    assert_eq!(etag, format!("\"{}\"", body["version"].as_str().unwrap()));
    assert_eq!((body["unit"].as_str(), body["env"].as_str()), (Some("multi"), Some("dev")));
    assert_eq!(body["live"], serde_json::json!(["telemetry.log_level", "features"]));
    assert_eq!(body["secrets"], serde_json::json!({}), "multi has no secrets");
    let want: toml::Table = golden("dev", "multi.toml").parse().unwrap();
    assert_eq!(body["config"], lighthouse::config::units::toml_to_json(&toml::Value::Table(want)), "the rendered TOML as JSON");

    let r = http().get(u("/v1/units/multi/config")).bearer_auth(UNITS_TOKEN).header("if-none-match", &etag).send().await.unwrap();
    assert_eq!(r.status(), 304);
    let r = get(u("/v1/units/multi/version"), Some(UNITS_TOKEN)).await;
    assert_eq!(r.text().await.unwrap(), body["version"].as_str().unwrap());
    let r = http().get(u("/v1/units/multi/version")).bearer_auth(UNITS_TOKEN).header("if-none-match", &etag).send().await.unwrap();
    assert_eq!(r.status(), 304);
    assert_eq!(get(u("/v1/units/nope/config"), Some(UNITS_TOKEN)).await.status(), 404);
    assert_eq!(get(u("/v1/units/nope/version"), Some(UNITS_TOKEN)).await.status(), 404);

    // security-auth: its TOML plus its own secrets at their paths, nothing of the others'.
    let sa: Value = get(u("/v1/units/security-auth/config"), Some(UNITS_TOKEN)).await.json().await.unwrap();
    let c = &sa["config"];
    assert_eq!(c["database"]["password"].as_str().unwrap(), golden_var("dev", "rust-units.env", "SECURITY_DB_PASSWORD"));
    assert_eq!(c["jwt"]["key"].as_str().unwrap(), golden_var("dev", "rust-units.env", "MODLIX__JWT__KEY"));
    assert_eq!(c["mq"]["uri"].as_str().unwrap(), golden_var("dev", "rust-units.env", "MODLIX__MQ__URI"));
    assert_eq!(c["sms"]["two_factor_api_key"].as_str().unwrap(), golden_var("dev", "rust-units.env", "MODLIX__SMS__TWO_FACTOR_API_KEY"));
    assert!(c.get("storage").is_none() && c.get("mongo").is_none() && c.get("shell").is_none());
    assert_eq!(sa["secrets"]["database.password"], "SECURITY_DB_PASSWORD");
    let shell: Value = get(u("/v1/units/ui-shell/config"), Some(UNITS_TOKEN)).await.json().await.unwrap();
    assert!(shell["config"]["shell"]["analytics_engine_secret"].is_string());
    assert!(shell["config"].get("jwt").is_none() && shell["config"].get("editor").is_none());
    assert!(shell["config"]["mongo"]["uri"].is_string());
    let editor: Value = get(u("/v1/units/ui-editor/config"), Some(UNITS_TOKEN)).await.json().await.unwrap();
    assert!(editor["config"]["editor"]["apple_api_key_content"].as_str().unwrap().contains('\n'));

    // The TOML view: secrets redacted unless asked otherwise.
    let secret = golden_var("dev", "rust-units.env", "SECURITY_DB_PASSWORD");
    let redacted = get(u("/v1/units/security-auth/config.toml"), Some(UNITS_TOKEN)).await.text().await.unwrap();
    assert!(redacted.contains("<redacted>") && !redacted.contains(&secret));
    let full = get(u("/v1/units/security-auth/config.toml?redact=false"), Some(ADMIN_TOKEN)).await.text().await.unwrap();
    assert!(full.contains(&secret));
    assert_eq!(get(u("/v1/units/security-auth/config.toml"), None).await.status(), 401);
}

#[tokio::test]
async fn env_files_are_the_scripts() {
    let n = node("dev").await;
    let u = |p: &str| format!("{}{p}", n.url);
    assert_eq!(get(u("/v1/env/ai"), None).await.status(), 401);
    assert_eq!(get(u("/v1/env/ai"), Some(UNITS_TOKEN)).await.status(), 403);
    for (path, file) in [("/v1/env/ai", "ai.env"), ("/v1/env/ssr", "ssr.env"), ("/v1/env/ssr?region=in", "ssr-in.env")] {
        let r = get(u(path), Some(AI_TOKEN)).await;
        assert_eq!(r.status(), 200, "{path}");
        let etag = r.headers()["etag"].to_str().unwrap().to_string();
        assert_eq!(r.bytes().await.unwrap(), golden("dev", file).as_bytes(), "{path}");
        let again = http().get(u(path)).bearer_auth(AI_TOKEN).header("if-none-match", etag).send().await.unwrap();
        assert_eq!(again.status(), 304);
    }
    assert_eq!(get(u("/v1/env/ssr?region=eu"), Some(AI_TOKEN)).await.status(), 404);
    assert_eq!(get(u("/v1/env/ai?region=in"), Some(AI_TOKEN)).await.status(), 404);
    assert_eq!(get(u("/v1/env/rust-units"), Some(ADMIN_TOKEN)).await.status(), 404);

    // prod: ssr.env has a value ssr-server reads with no variable for it, which only warns.
    let p = node("prod").await;
    let r = get(format!("{}/v1/env/ssr", p.url), Some(AI_TOKEN)).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), golden("prod", "ssr.env"));
}

#[tokio::test]
async fn missing_values_are_named_never_shown() {
    let n = node("stage").await;
    let u = |p: &str| format!("{}{p}", n.url);
    let r = get(u("/v1/units/files-serve/config"), Some(UNITS_TOKEN)).await;
    assert_eq!(r.status(), 500);
    let text = r.text().await.unwrap();
    let body: Value = serde_json::from_str(&text).unwrap();
    let missing: Vec<&str> = body["missing"].as_array().unwrap().iter().map(|m| m.as_str().unwrap()).collect();
    assert!(missing.iter().any(|m| m.starts_with("files.resources.bucketPrefix")), "{missing:?}");
    assert!(missing.iter().any(|m| m.starts_with("MODLIX__STORAGE__SECRET_ACCESS_KEY")), "{missing:?}");
    for value in ["fixture-files-stage", "STAGEACCESS", "a.fixture.test"] {
        assert!(!text.contains(value), "a value leaked: {value}");
    }
    assert_eq!(get(u("/v1/units/files-serve/version"), Some(UNITS_TOKEN)).await.status(), 500);
    assert_eq!(get(u("/v1/units/multi/config"), Some(UNITS_TOKEN)).await.status(), 200);
    let ui = get(u("/v1/units/ui-engine/config"), Some(UNITS_TOKEN)).await;
    assert_eq!(ui.status(), 500);
    let ui: Value = ui.json().await.unwrap();
    assert!(ui["missing"].to_string().contains("UI_MONGO_URI names no database"));
    let r = get(u("/v1/env/ai"), Some(AI_TOKEN)).await;
    assert_eq!(r.status(), 500);
    let body: Value = r.json().await.unwrap();
    assert!(body["missing"][0].as_str().unwrap().starts_with("APPBUILDER_CODER_ENABLED"));

    // The dashboard view shows the problem by name too, to the admin only.
    assert_eq!(get(u("/v1/config"), None).await.status(), 401);
    assert_eq!(get(u("/v1/config"), Some(UNITS_TOKEN)).await.status(), 403);
    let view: Value = get(u("/v1/config"), Some(ADMIN_TOKEN)).await.json().await.unwrap();
    let fs = view["units"].as_array().unwrap().iter().find(|x| x["unit"] == "files-serve").unwrap();
    assert!(fs["problem"].as_str().unwrap().starts_with("missing: "));
    assert_eq!(fs["version"], Value::Null);
}

#[tokio::test]
async fn refresh_and_peer_snapshot() {
    let n = node("dev").await;
    let u = |p: &str| format!("{}{p}", n.url);
    assert_eq!(http().post(u("/v1/admin/refresh")).send().await.unwrap().status(), 401);
    assert_eq!(http().post(u("/v1/admin/refresh")).bearer_auth(AI_TOKEN).send().await.unwrap().status(), 403);
    let r: Value = http().post(u("/v1/admin/refresh?full=true")).bearer_auth(ADMIN_TOKEN).send().await.unwrap().json().await.unwrap();
    assert_eq!(r["changed"], false);
    assert!(r["sha"].is_string() && r["error"].is_null());

    assert_eq!(get(u("/v1/peer/snapshot"), None).await.status(), 401);
    assert_eq!(get(u("/v1/peer/snapshot"), Some(UNITS_TOKEN)).await.status(), 401, "the peer token check comes first");
    let r = get(u("/v1/peer/snapshot"), Some(PEER_TOKEN)).await;
    assert_eq!(r.status(), 200);
    let snap = Snapshot::decode(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(snap.sha, n.node.config.as_ref().unwrap().served().unwrap().snapshot.sha);
    assert!(snap.file("rust/units.toml").is_some());

    // Dashboard management takes an ops token only.
    let st = admin("PUT", u("/v1/admin/apps/X/x/status?value=OUT_OF_SERVICE"), Some(UNITS_TOKEN)).await;
    assert_eq!(st, 403);
}

fn copy_render(env: &str, name: &str) -> PathBuf {
    let src = fixture().join("../render").join(env);
    let dst = std::env::temp_dir().join(format!("lighthouse-parity-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dst);
    std::fs::create_dir_all(&dst).unwrap();
    for e in std::fs::read_dir(&src).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), dst.join(e.file_name())).unwrap();
    }
    dst
}

fn edit(path: &Path, from: &str, to: &str) {
    let text = std::fs::read_to_string(path).unwrap();
    assert!(text.contains(from));
    std::fs::write(path, text.replacen(from, to, 1)).unwrap();
}

#[tokio::test]
async fn parity_with_a_rendered_directory() {
    let n = node("dev").await;
    std::env::set_var("LIGHTHOUSE_TOKEN", ADMIN_TOKEN);
    let args = |dir: &Path| vec![dir.display().to_string(), n.url.clone(), "dev".to_string()];
    let run = |dir: PathBuf| {
        let a = args(&dir);
        async move {
            let (mut o, mut e) = (Vec::new(), Vec::new());
            let code = lighthouse::config::cli::parity_command(&a, &mut o, &mut e).await;
            (code, String::from_utf8(o).unwrap(), String::from_utf8(e).unwrap())
        }
    };
    let same = copy_render("dev", "same");
    let (code, out, err) = run(same.clone()).await;
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("units compared: 15") && out.contains("differing: 0"), "{out}");
    assert!(out.contains("ai.env: ") && out.contains("ssr-in.env: ") && out.contains("byte-identical: yes"));

    let changed = copy_render("dev", "changed");
    edit(&changed.join("multi.toml"), "port = 8110", "port = 8111");
    edit(&changed.join("rust-units.env"), "fixture-jwt-default", "something-else");
    edit(&changed.join("ai.env"), "LLM_PROVIDER='anthropic'", "LLM_PROVIDER='other'");
    std::fs::write(changed.join("rust-units.env"), std::fs::read_to_string(changed.join("rust-units.env")).unwrap() + "EXTRA='x'\n").unwrap();
    let (code, out, _) = run(changed.clone()).await;
    assert_eq!(code, 1);
    assert!(out.contains("multi: ") && out.contains("  differs: server.port"), "{out}");
    assert!(out.contains("  differs: jwt.key"), "{out}");
    assert!(out.contains("  differs: LLM_PROVIDER") && out.contains("byte-identical: no"), "{out}");
    assert!(out.contains("served to no unit: EXTRA"));
    for value in ["something-else", "fixture-jwt-default", "anthropic", "8111"] {
        assert!(!out.contains(value), "parity printed a value: {value}");
    }
    std::fs::write(changed.join("nope.toml"), "a = 1\n").unwrap();
    let (code, _, err) = run(changed.clone()).await;
    assert_eq!(code, 2);
    assert!(err.contains("/v1/units/nope/config answered 404"), "{err}");
    let (code, _, err) = run(Path::new("/nonexistent").to_path_buf()).await;
    assert_eq!(code, 2);
    assert!(err.contains("rust-units.env"));
    let (mut o, mut e) = (Vec::new(), Vec::new());
    assert_eq!(lighthouse::config::cli::parity_command(&["x".into()], &mut o, &mut e).await, 2);
    // A server rendering another environment is refused.
    let (code, _, err) = {
        let a = vec![same.display().to_string(), n.url.clone(), "prod".to_string()];
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let code = lighthouse::config::cli::parity_command(&a, &mut o, &mut e).await;
        (code, String::from_utf8(o).unwrap(), String::from_utf8(e).unwrap())
    };
    assert_eq!(code, 2);
    assert!(err.contains("renders"), "{err}");
    std::fs::remove_dir_all(&same).unwrap();
    std::fs::remove_dir_all(&changed).unwrap();
}
