//! Reads URI-building cases as JSON lines and prints the result the way the Java harness does
//! (`{"ok": uri}` or `{"err": message}`), for diffing against Spring.

use std::collections::HashMap;
use std::io::BufRead;

use connections::rest::spring_uri::{build_request_uri, build_to_uri, build_to_uri_string, WebClientEncodingMode};
use serde_json::{json, Value};

fn main() {
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(&line).expect("json");
        let url = v["url"].as_str().unwrap_or_default();
        let query: Vec<(String, String)> = v["query"]
            .as_array()
            .map(|a| a.iter().map(|p| (p[0].as_str().unwrap().to_string(), p[1].as_str().unwrap().to_string())).collect())
            .unwrap_or_default();
        let res = match v["kind"].as_str().unwrap_or_default() {
            "rest" => {
                let path: HashMap<String, String> = v["path"]
                    .as_object()
                    .map(|m| m.iter().map(|(k, x)| (k.clone(), x.as_str().unwrap().to_string())).collect())
                    .unwrap_or_default();
                WebClientEncodingMode::value_of(v["mode"].as_str().unwrap_or_default())
                    .and_then(|mode| build_request_uri(url, mode, &query, &path))
            }
            "touri" => build_to_uri(url, &query),
            _ => build_to_uri_string(url, &query),
        };
        let out = match res {
            Ok(s) => json!({"ok": s}),
            Err(e) => json!({"err": e.message()}),
        };
        println!("{out}");
    }
}
