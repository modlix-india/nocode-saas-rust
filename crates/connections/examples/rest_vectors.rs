//! Runs the REST cases (JSON lines) through `basic::call` against a local echo server and
//! prints `{name, status, headers, data}` (or `{name, err}`) the way the Java harness prints
//! them, for diffing against `BasicRestService`. Private targets are not blocked here.

use std::collections::HashMap;
use std::io::BufRead;
use std::sync::Arc;

use async_trait::async_trait;
use connections::connection::{Connection, ConnectionStore};
use connections::error::ConnResult;
use connections::rest::auth::{AuthTokenFunction, EventResult};
use connections::rest::{basic, RestRequest};
use connections::tokens::{CoreToken, TokenStore, TokenType};
use connections::{java, Connections, ConnectionsConfig};
use serde_json::{json, Map, Value};

struct NoStore;
#[async_trait]
impl ConnectionStore for NoStore {
    async fn read_internal(&self, _: &str, _: &str, _: &str, _: &str) -> ConnResult<Option<Connection>> {
        Ok(None)
    }
}

struct NoTokens;
#[async_trait]
impl TokenStore for NoTokens {
    async fn active_access_token_tuple(&self, _: &str, _: &str, _: &str) -> ConnResult<Option<(Option<String>, Option<chrono::NaiveDateTime>)>> {
        Ok(None)
    }
    async fn active_token(&self, _: &str, _: &str, _: &str, _: TokenType) -> ConnResult<Option<CoreToken>> {
        Ok(None)
    }
    async fn by_state(&self, _: Option<&str>) -> ConnResult<Option<CoreToken>> {
        Ok(None)
    }
    async fn revoke(&self, _: &str, _: &str, _: &str, _: Option<TokenType>) -> ConnResult<bool> {
        Ok(false)
    }
    async fn create(&self, t: &CoreToken) -> ConnResult<CoreToken> {
        Ok(t.clone())
    }
    async fn update(&self, t: &CoreToken) -> ConnResult<Option<CoreToken>> {
        Ok(Some(t.clone()))
    }
}

struct NoFunctions;
#[async_trait]
impl AuthTokenFunction for NoFunctions {
    async fn execute(&self, _: Option<&str>, _: &str, _: Option<&str>, _: Option<&str>) -> ConnResult<Option<Vec<EventResult>>> {
        Ok(None)
    }
}

#[tokio::main]
async fn main() {
    let cache = platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap();
    let svc = Connections::new(
        ConnectionsConfig { block_private_targets: false, ..Default::default() },
        Arc::new(NoStore),
        Arc::new(NoTokens),
        cache,
        Arc::new(NoFunctions),
    );
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let c: Value = serde_json::from_str(&line).unwrap();
        let conn = Connection::from_json(json!({"name": "conn", "connectionDetails": c["details"]})).unwrap();
        let headers: Vec<(String, Vec<String>)> = c["headers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), vec![v.as_str().unwrap().to_string()]))
            .collect();
        let query: Map<String, Value> = c["query"].as_object().unwrap().clone();
        let query: Vec<(String, String)> =
            java::hash_map_order(query).into_iter().map(|(k, v)| (k, v.as_str().unwrap().to_string())).collect();
        let path: HashMap<String, String> =
            c["path"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect();
        let request = RestRequest {
            url: c["url"].as_str().unwrap().to_string(),
            headers: if headers.is_empty() { None } else { Some(headers) },
            path_parameters: path,
            query_parameters: if query.is_empty() { None } else { Some(query) },
            timeout: c["timeout"].as_i64().unwrap() as i32,
            method: c["method"].as_str().unwrap().to_string(),
            payload: c.get("payload").cloned(),
            ignore_default_headers: c["ignore"].as_bool().unwrap(),
        };
        let name = c["name"].clone();
        let out = match basic::call(&svc, &conn, request, c["download"].as_bool().unwrap()).await {
            Ok(Some(r)) => json!({"name": name, "status": r.status, "headers": r.headers_json(), "data": r.data.to_gson_tree()}),
            Ok(None) => json!({"name": name, "empty": true}),
            Err(e) => json!({"name": name, "err": e.message()}),
        };
        println!("{out}");
    }
}
