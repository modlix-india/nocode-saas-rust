//! Read parity between the Java core service and the Rust app-data engines, on real local
//! data. READ ONLY: the Rust engines run with provisioning and index management off, so
//! they issue no DDL, and only reads are sent to Java.
//!
//! For each storage it runs the same queries through `POST /api/core/data/{storage}/query`
//! (and the read, aggregate and version endpoints) on Java and through the engine directly,
//! and compares the JSON. `SAME` means equal including key order; `SAME*` equal as values
//! with keys in another order; `EXPECT` a difference listed in crates/appdata/DIFFERENCES.md;
//! `DIFF` prints the first difference.
//!
//! cargo run -p appdata --example parity_appdata [-- <filter substring>]
//! Env: JAVA_CORE (http://localhost:8005), JAVA_SECURITY (http://localhost:8001),
//! MONGO_URI (mongodb://localhost:27017),
//! CONFIG_SERVER (http://localhost:8888) for core's own MySQL datasource.

use std::sync::Arc;

use appdata::engine::{Ctx, Hooks, PassThrough};
use appdata::lookup::MongoDefinitions;
use appdata::model::{AggregateQuery, Connection, Query, Storage};
use appdata::mongo::{MongoAppDataService, MongoEngineConfig};
use appdata::mysql::{MySqlAppDataService, MySqlEngineConfig};
use appdata::selection::{backend_for, Backend, Engines};
use appdata::value::Value;
use platform::cache::CacheService;

const USER: &str = "142";
const PASSWORD: &str = "Pass@1234";

fn basic() -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = format!("{USER}:{PASSWORD}").into_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    format!("Basic {out}")
}

struct Case {
    app: &'static str,
    client: &'static str,
    storage: &'static str,
}

/// Only storages SYSTEM user 142 can read through Java: it gets 401 on leadtrack and
/// orangeab and as MONKC (monkbars' MONKC filterlab table), and 403 on loopzump, fleetopsv,
/// stillwater and crumbco, so those are left out rather than compared against an error.
const CASES: &[Case] = &[
    // MySQL, through an appData connection with useDefaultConnection. Only storages whose
    // tables already exist: a Java read of a storage with no table would create it.
    Case { app: "appa", client: "SYSTEM", storage: "aitems" },
    Case { app: "appa", client: "SYSTEM", storage: "docs" },
    Case { app: "leadzumptwo", client: "SYSTEM", storage: "blogs" },
    Case { app: "leadzumptwo", client: "SYSTEM", storage: "blogCategories" },
    // Mongo, no appData connection.
    Case { app: "monkbars", client: "SYSTEM", storage: "docs" },
    Case { app: "monkbars", client: "SYSTEM", storage: "ddCity" },
    Case { app: "monkbars", client: "SYSTEM", storage: "aggSales" },
    Case { app: "monkbars", client: "SYSTEM", storage: "filterlab" },
    Case { app: "monkbars", client: "SYSTEM", storage: "shared" },
    Case { app: "markauto", client: "SYSTEM", storage: "ConditionsStorage" },
    Case { app: "appbuilder", client: "SYSTEM", storage: "Doc" },
    Case { app: "atelierno", client: "SYSTEM", storage: "project" },
    Case { app: "kirunlive", client: "SYSTEM", storage: "ticket" },
    Case { app: "sitezump", client: "SYSTEM", storage: "templateStorage" },
    Case { app: "sitezump", client: "SYSTEM", storage: "templateCategoryStorage" },
];

/// Equal as values: numbers by value (1 and 1.0 are different JSON types, so they stay
/// different), objects ignoring key order.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w))),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q)),
        _ => a == b,
    }
}

fn first_diff(path: &str, a: &Value, b: &Value) -> String {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for (k, v) in x {
                match y.get(k) {
                    None => return format!("{path}.{k}: only in java ({})", short(v)),
                    Some(w) if !same(v, w) => return first_diff(&format!("{path}.{k}"), v, w),
                    _ => {}
                }
            }
            for k in y.keys() {
                if !x.contains_key(k) {
                    return format!("{path}.{k}: only in rust ({})", short(&y[k]));
                }
            }
            format!("{path}: key order differs")
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (p, q)) in x.iter().zip(y).enumerate() {
                if !same(p, q) {
                    return first_diff(&format!("{path}[{i}]"), p, q);
                }
            }
            format!("{path}: arrays differ")
        }
        _ => format!("{path}: java {} / rust {}", short(a), short(b)),
    }
}

fn short(v: &Value) -> String {
    let s = v.to_java_json();
    if s.len() > 160 {
        format!("{}...", &s[..160])
    } else {
        s
    }
}

struct Tally {
    same: usize,
    reordered: usize,
    expected: usize,
    diff: usize,
}

impl Tally {
    /// A difference listed in crates/appdata/DIFFERENCES.md, under the name given.
    fn record_expected(&mut self, label: &str, java: &Value, rust: &Value, entry: &str) {
        self.expected += 1;
        println!("EXPECT {label}  (DIFFERENCES.md: {entry})\n       {}", first_diff("$", java, rust));
    }

    fn record(&mut self, label: &str, java: &Value, rust: &Value) {
        if java == rust {
            self.same += 1;
            println!("SAME   {label}");
        } else if same(java, rust) {
            self.reordered += 1;
            println!("SAME*  {label}  (key order)");
        } else {
            self.diff += 1;
            println!("DIFF   {label}\n       {}", first_diff("$", java, rust));
        }
    }
}

async fn java(http: &reqwest::Client, base: &str, c: &Case, method: reqwest::Method, path: &str, body: Option<&str>) -> Value {
    // Every Basic-authenticated call makes core ask the security service for the context,
    // and a busy local security service times that out as a 500 (or hangs). So a 500 or a
    // failed call is asked again once security answers its health check; a 500 Java really
    // gives comes back the same.
    let mut answer = None;
    for attempt in 0..3 {
        if attempt > 0 {
            wait_for_security(http).await;
        }
        match java_once(http, base, c, method.clone(), path, body).await {
            Some((status, v)) if status != 500 => return v,
            Some((_, v)) => answer = Some(v),
            None => {}
        }
    }
    answer.expect("java answered nothing in three attempts")
}

async fn wait_for_security(http: &reqwest::Client) {
    let health = std::env::var("JAVA_SECURITY").unwrap_or_else(|_| "http://localhost:8001".into()) + "/actuator/health";
    for _ in 0..60 {
        let up = http.get(&health).timeout(std::time::Duration::from_secs(5)).send().await;
        if up.is_ok_and(|r| r.status().is_success()) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    panic!("the security service has not been healthy for five minutes");
}

async fn java_once(
    http: &reqwest::Client,
    base: &str,
    c: &Case,
    method: reqwest::Method,
    path: &str,
    body: Option<&str>,
) -> Option<(u16, Value)> {
    let mut req = http
        .request(method, format!("{base}/api/core/data/{path}"))
        .timeout(std::time::Duration::from_secs(90))
        .header("Authorization", basic())
        .header("clientCode", c.client)
        .header("appCode", c.app);
    if let Some(b) = body {
        req = req.header("Content-Type", "application/json").body(b.to_string());
    }
    let resp = req.send().await.ok()?;
    let status = resp.status();
    let text = resp.text().await.ok()?;
    let mut v = Value::parse_json(&text).unwrap_or(Value::String(text));
    if !status.is_success() {
        // Errors are compared by status and message only; ids and stacks differ by nature.
        let message = v.as_object().and_then(|o| o.get("message")).cloned().unwrap_or(Value::Null);
        let mut d = appdata::value::Document::new();
        d.insert("status".into(), Value::Int(status.as_u16() as i64));
        d.insert("message".into(), message);
        v = Value::Object(d);
    }
    Some((status.as_u16(), v))
}

fn rust_error(e: appdata::AppDataError) -> Value {
    let mut d = appdata::value::Document::new();
    d.insert("status".into(), Value::Int(e.status().as_u16() as i64));
    d.insert(
        "message".into(),
        if e.status().is_server_error() { Value::Null } else { Value::from(e.message()) },
    );
    Value::Object(d)
}

/// Java's 500 body says "Please try again"; only the status is compared for a 500.
fn normalise_500(v: Value) -> Value {
    match &v {
        Value::Object(o) if o.get("status") == Some(&Value::Int(500)) => {
            let mut d = o.clone();
            d.insert("message".into(), Value::Null);
            Value::Object(d)
        }
        _ => v,
    }
}

async fn config_value(http: &reqwest::Client, key: &str) -> Option<String> {
    let base = std::env::var("CONFIG_SERVER").unwrap_or_else(|_| "http://localhost:8888".into());
    let v: serde_json::Value = http.get(format!("{base}/core/default")).send().await.ok()?.json().await.ok()?;
    for ps in v["propertySources"].as_array()? {
        if let Some(s) = ps["source"][key].as_str() {
            return Some(s.to_string());
        }
    }
    None
}

#[tokio::main]
async fn main() {
    let only = std::env::args().nth(1);
    let base = std::env::var("JAVA_CORE").unwrap_or_else(|_| "http://localhost:8005".into());
    let mongo_uri = std::env::var("MONGO_URI").unwrap_or_else(|_| "mongodb://localhost:27017".into());
    let http = reqwest::Client::new();
    let core = mongodb::Client::with_uri_str(&mongo_uri).await.expect("mongo").database("core");
    let defs = Arc::new(MongoDefinitions::new(core));
    let hooks = Hooks { validator: Arc::new(PassThrough), schemas: Some(defs.clone()), storages: Some(defs.clone()), authority: None };
    let cache = CacheService::new("cmn", "evictionChannel", None).expect("cache");

    let engines = Engines {
        mongo: Arc::new(MongoAppDataService::new(
            MongoEngineConfig { default_uri: Some(mongo_uri.clone()), skip_index_management: true, ..Default::default() },
            hooks.clone(),
            &cache,
        )),
        mysql: Arc::new(MySqlAppDataService::new(
            MySqlEngineConfig {
                default_url: config_value(&http, "core.db.url").await,
                default_username: config_value(&http, "core.db.username").await,
                default_password: config_value(&http, "core.db.password").await,
                skip_provisioning: true,
                ..Default::default()
            },
            hooks.clone(),
            &cache,
        )),
    };
    let mut tally = Tally { same: 0, reordered: 0, expected: 0, diff: 0 };

    for c in CASES {
        let tag = format!("{}/{}/{}", c.app, c.client, c.storage);
        if only.as_ref().is_some_and(|o| !tag.contains(o.as_str())) {
            continue;
        }
        let storage: Storage = match defs.storage(c.storage, c.app, c.client).await.unwrap() {
            Some(s) => s,
            None => defs.storage(c.storage, c.app, "SYSTEM").await.unwrap().expect("storage exists"),
        };
        let conn: Option<Connection> = defs.app_data_connection(c.app, c.client).await.unwrap();
        let backend = match backend_for(conn.as_ref()).unwrap() {
            Backend::Mongo => "mongo",
            Backend::MySql => "mysql",
        };
        let engine = engines.for_connection(conn.as_ref()).unwrap();
        let cx = Ctx {
            url_client_code: Some(c.client.into()),
            user_id: Some(142),
            authorities: vec!["Authorities.Logged_IN".into()],
            draft: false,
        };
        // What the rows look like decides the field-specific queries.
        let first = java(&http, &base, c, reqwest::Method::POST, &format!("{}/query", c.storage), Some(r#"{"size":2}"#)).await;
        let rows: Vec<appdata::value::Document> = first
            .as_object()
            .and_then(|o| o.get("content"))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|r| r.as_object().cloned()).collect())
            .unwrap_or_default();
        let string_field = rows.first().and_then(|r| {
            r.iter()
                .find(|(k, v)| *k != "_id" && matches!(v, Value::String(s) if !s.is_empty() && s.len() < 60 && !s.contains('"') && !s.contains('\\')))
                .map(|(k, v)| (k.clone(), v.java_string()))
        });
        let ids: Vec<String> = rows.iter().filter_map(|r| r.get("_id").map(Value::java_string)).collect();

        let mut queries: Vec<String> = vec![
            "{}".into(),
            r#"{"size":3,"page":1,"sort":{"property":"_id"}}"#.into(),
            r#"{"size":4,"count":false,"sort":[{"property":"_id","direction":"DESC"}]}"#.into(),
            r#"{"size":2,"page":500}"#.into(),
        ];
        if let Some((f, v)) = &string_field {
            queries.push(format!(r#"{{"condition":{{"field":"{f}","value":"{v}"}}}}"#));
            queries.push(format!(r#"{{"condition":{{"field":"{f}","value":"{v}","negate":true}},"size":3}}"#));
            let part: String = v.chars().skip(1).take(3).collect();
            queries.push(format!(r#"{{"condition":{{"field":"{f}","operator":"STRING_LOOSE_EQUAL","value":"{part}"}}}}"#));
            queries.push(format!(r#"{{"fields":["{f}"],"size":3,"sort":{{"property":"{f}"}}}}"#));
            queries.push(format!(r#"{{"fields":["{f}"],"excludeFields":true,"size":2}}"#));
            queries.push(format!(
                r#"{{"condition":{{"operator":"OR","conditions":[{{"field":"{f}","operator":"IS_NULL"}},{{"field":"{f}","value":null}},{{"field":"{f}","operator":"LIKE","value":"%"}}]}},"size":3}}"#
            ));
        }
        if ids.len() == 2 {
            queries.push(format!(r#"{{"condition":{{"field":"_id","operator":"IN","value":"{},{}"}}}}"#, ids[0], ids[1]));
        }
        queries.push(r#"{"condition":{"field":"$where","value":1}}"#.into());
        queries.push(r#"{"condition":{"field":"x","operator":"BETWEEN","value":1}}"#.into());

        for q in &queries {
            let jv = normalise_500(java(&http, &base, c, reqwest::Method::POST, &format!("{}/query", c.storage), Some(q)).await);
            let rv = match engine.read_page(&cx, c.client, conn.as_ref(), &storage, &Query::from_value(&Value::parse_json(q).unwrap()).unwrap()).await {
                Ok(p) => p.to_value(),
                Err(e) => rust_error(e),
            };
            tally.record(&format!("{backend:5} {tag}  query {q}"), &jv, &rv);
        }

        for id in ids.iter().take(1).cloned().chain(std::iter::once("6ac7d4a11a578c042996bca0".to_string())) {
            let jv = normalise_500(java(&http, &base, c, reqwest::Method::GET, &format!("{}/{id}", c.storage), None).await);
            let rv = match engine.read(&cx, c.client, conn.as_ref(), &storage, &id).await {
                Ok(d) => Value::Object(d),
                Err(e) => rust_error(e),
            };
            tally.record(&format!("{backend:5} {tag}  read {id}"), &jv, &rv);
        }

        if let Some((f, _)) = &string_field {
            for a in [
                // The group key breaks ties: Mongo hands equal counts back in no fixed order, so
                // Java alone answers them differently from one call to the next.
                format!(r#"{{"groupBy":[{{"field":"{f}"}}],"aggregations":[{{"function":"COUNT"}}],"sort":[{{"property":"count","direction":"DESC"}},{{"property":"{f}","direction":"ASC"}}],"size":5,"count":true}}"#),
                r#"{"aggregations":[{"function":"COUNT"},{"function":"COUNT_DISTINCT","field":"_id","alias":"ids"}]}"#.to_string(),
            ] {
                let jv = normalise_500(java(&http, &base, c, reqwest::Method::POST, &format!("{}/aggregate", c.storage), Some(&a)).await);
                let rv = match engine.aggregate(&cx, c.client, conn.as_ref(), &storage, &AggregateQuery::from_value(&Value::parse_json(&a).unwrap()).unwrap()).await {
                    Ok(p) => p.to_value(),
                    Err(e) => rust_error(e),
                };
                let label = format!("{backend:5} {tag}  aggregate {a}");
                let java_500 = jv.as_object().and_then(|o| o.get("status")) == Some(&Value::Int(500));
                let rust_ok = rv.as_object().is_some_and(|o| !o.contains_key("status"));
                if backend == "mongo" && a.contains("COUNT_DISTINCT") && java_500 && rust_ok {
                    tally.record_expected(&label, &jv, &rv, "Mongo COUNT_DISTINCT");
                } else {
                    tally.record(&label, &jv, &rv);
                }
            }
        }

        if storage.keeps_history() {
            if let Some(id) = ids.first() {
                let q = r#"{"size":3}"#;
                let jv = normalise_500(java(&http, &base, c, reqwest::Method::POST, &format!("{}/version/{id}/query", c.storage), Some(q)).await);
                let rv = match engine
                    .read_page_version(&cx, c.client, conn.as_ref(), &storage, id, &Query::from_value(&Value::parse_json(q).unwrap()).unwrap(), Some(true))
                    .await
                {
                    Ok(p) => p.to_value(),
                    Err(e) => rust_error(e),
                };
                tally.record(&format!("{backend:5} {tag}  versions {id}"), &jv, &rv);
            }
        }
    }

    println!(
        "parity_appdata: {} cases, {} SAME, {} SAME* (key order only), {} EXPECTED (DIFFERENCES.md), {} DIFF",
        tally.same + tally.reordered + tally.expected + tally.diff,
        tally.same,
        tally.reordered,
        tally.expected,
        tally.diff
    );
}
