//! REST calls compared with Java's `BasicRestService`, recorded on 2026-10-15: the same 66
//! cases were run through the Java class (JDK 21, the local core's classpath, a Python echo
//! server on 8191) and the requests the server saw and the `RestResponse`s Java returned were
//! saved. Here the cases run through `basic::call` against an in-process server that answers
//! the same bytes, and both sides are compared.
//!
//! Known and listed in DIFFERENCES.md: request header names go out in lower case (hyper), and
//! the message of a malformed-JSON response differs (Gson's parser versus serde's).

use std::collections::HashMap;
use std::io::Write as _;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use connections::connection::{Connection, ConnectionStore};
use connections::error::ConnResult;
use connections::rest::auth::{AuthTokenFunction, EventResult};
use connections::rest::{basic, RestRequest};
use connections::tokens::{CoreToken, TokenStore, TokenType};
use connections::{java, Connections, ConnectionsConfig};
use parking_lot::Mutex;
use serde_json::{json, Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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

fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// The echo server's canned answers (scratch `echo_server.py`).
fn canned(path: &str) -> (u16, Vec<(&'static str, &'static str)>, Vec<u8>) {
    let json_body = br#"{"a":1,"b":null,"c":[1,null,{"d":null,"e":2.5}],"f":"x","big":12345678901234567890}"#.to_vec();
    let table: Vec<(&str, u16, Vec<(&'static str, &'static str)>, Vec<u8>)> = vec![
        ("/resp/gzip", 200, vec![("Content-Type", "application/json"), ("Content-Encoding", "gzip")], gz(br#"{"zipped":[1,2,3]}"#)),
        ("/resp/json", 200, vec![("Content-Type", "application/json"), ("X-Total-Count", "3")], json_body),
        ("/resp/json-array", 200, vec![("Content-Type", "application/json;charset=UTF-8")], br#"[1,"two",null,{"x":null}]"#.to_vec()),
        ("/resp/json-num", 200, vec![("Content-Type", "application/json")], b"42".to_vec()),
        ("/resp/json-str", 200, vec![("Content-Type", "application/json")], br#""hello""#.to_vec()),
        ("/resp/json-blank", 200, vec![("Content-Type", "application/json")], b"   ".to_vec()),
        ("/resp/json-bad", 200, vec![("Content-Type", "application/json")], b"{oops".to_vec()),
        ("/resp/text", 200, vec![("Content-Type", "text/plain;charset=UTF-8")], "h\u{e9}llo".as_bytes().to_vec()),
        ("/resp/html", 201, vec![("Content-Type", "text/html")], b"<p>hi</p>".to_vec()),
        ("/resp/none", 200, vec![], b"no content type here".to_vec()),
        ("/resp/pdf", 200, vec![("Content-Type", "application/pdf")], vec![0x25, 0x50, 0x44, 0x46, 0xFF, 0x00]),
        ("/resp/xml", 200, vec![("Content-Type", "application/xml")], b"<a/>".to_vec()),
        ("/resp/apijson", 200, vec![("Content-Type", "application/vnd.api+json")], br#"{"data":1}"#.to_vec()),
        (
            "/resp/disposition",
            200,
            vec![("Content-Type", "text/csv"), ("Content-Disposition", "attachment; filename=\"r.csv\"")],
            b"a,b\n".to_vec(),
        ),
        ("/resp/204", 204, vec![], vec![]),
        ("/resp/empty200", 200, vec![("Content-Type", "application/json")], vec![]),
        ("/resp/404", 404, vec![("Content-Type", "application/json")], br#"{"error":"missing"}"#.to_vec()),
        ("/resp/500", 500, vec![("Content-Type", "text/plain")], b"boom".to_vec()),
        (
            "/resp/lower",
            200,
            vec![("content-type", "application/json"), ("x-lower", "1"), ("X-Dup", "a"), ("x-dup", "b")],
            br#"{"k":"v"}"#.to_vec(),
        ),
        ("/resp/redirect", 302, vec![("Location", "https://example.com/elsewhere")], vec![]),
    ];
    for (suffix, status, headers, body) in table {
        if path.ends_with(suffix) {
            return (status, headers, body);
        }
    }
    (200, vec![("Content-Type", "application/json")], br#"{"ok":true}"#.to_vec())
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Reads one request (Content-Length or chunked), records it, answers the canned response.
async fn serve(listener: TcpListener, log: Arc<Mutex<Vec<Value>>>) {
    loop {
        let Ok((mut sock, _)) = listener.accept().await else { return };
        let log = log.clone();
        tokio::spawn(async move {
            let mut data = Vec::new();
            let mut buf = [0u8; 65536];
            let head_end = loop {
                if let Some(i) = find(&data, b"\r\n\r\n") {
                    break i;
                }
                let n = sock.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                data.extend_from_slice(&buf[..n]);
            };
            let head = String::from_utf8_lossy(&data[..head_end]).to_string();
            let mut lines = head.split("\r\n");
            let first: Vec<&str> = lines.next().unwrap_or("").splitn(3, ' ').collect();
            let headers: Vec<(String, String)> = lines
                .filter_map(|l| l.split_once(':').map(|(k, v)| (k.to_string(), v.trim().to_string())))
                .collect();
            let mut body = data[head_end + 4..].to_vec();
            let length: usize = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(0);
            let chunked = headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"));
            if chunked {
                while !body.ends_with(b"0\r\n\r\n") {
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&buf[..n]);
                }
                let mut raw = &body[..];
                let mut out = Vec::new();
                while let Some(i) = find(raw, b"\r\n") {
                    let size = usize::from_str_radix(std::str::from_utf8(&raw[..i]).unwrap_or("0").trim(), 16).unwrap_or(0);
                    if size == 0 {
                        break;
                    }
                    out.extend_from_slice(&raw[i + 2..i + 2 + size]);
                    raw = &raw[i + 2 + size + 2..];
                }
                body = out;
            } else {
                while body.len() < length {
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&buf[..n]);
                }
            }
            let target = first.get(1).copied().unwrap_or("").to_string();
            log.lock().push(json!({
                "method": first.first().copied().unwrap_or(""),
                "target": target,
                "headers": headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
                "body": base64::engine::general_purpose::STANDARD.encode(&body),
            }));
            let path = target.split('?').next().unwrap_or("");
            let (status, headers, body) = canned(path);
            let mut out = format!("HTTP/1.1 {status} X\r\n").into_bytes();
            for (k, v) in headers {
                out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
            }
            if status != 204 {
                out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
            }
            out.extend_from_slice(b"Connection: close\r\n\r\n");
            out.extend_from_slice(&body);
            let _ = sock.write_all(&out).await;
        });
    }
}

fn normalize_request(r: &Value, port: &str) -> Value {
    let headers: Vec<Value> = r["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            let k = h[0].as_str().unwrap().to_lowercase();
            let v = h[1].as_str().unwrap().replace("8191", port);
            let v = regex::Regex::new("boundary=[^;]+").unwrap().replace_all(&v, "boundary=B").to_string();
            json!([k, v])
        })
        .collect();
    let mut body = base64::engine::general_purpose::STANDARD.decode(r["body"].as_str().unwrap()).unwrap();
    let boundary = r["headers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h[0].as_str().unwrap().eq_ignore_ascii_case("content-type"))
        .and_then(|h| h[1].as_str().unwrap().split("boundary=").nth(1).map(str::to_string));
    if let Some(b) = boundary {
        body = String::from_utf8_lossy(&body).replace(&b, "B").into_bytes();
    }
    json!({"method": r["method"], "target": r["target"], "headers": headers, "body": String::from_utf8_lossy(&body)})
}

#[tokio::test]
async fn basic_rest_service_matches_java() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    // A port with nothing listening, for the refused cases.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port().to_string()
    };
    let log = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(serve(listener, log.clone()));

    let svc = Connections::new(
        ConnectionsConfig { block_private_targets: false, ..Default::default() },
        Arc::new(NoStore),
        Arc::new(NoTokens),
        platform::cache::CacheService::new("cmn", "evictionChannel", None).unwrap(),
        Arc::new(NoFunctions),
    );

    let cases: Vec<Value> = include_str!("fixtures/rest_cases.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let answers: Vec<Value> =
        include_str!("fixtures/rest_java21_responses.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(cases.len(), answers.len());

    let mut response_diffs = Vec::new();
    for (case, expected) in cases.iter().zip(&answers) {
        let text = case.to_string().replace("8191", &port).replace("8199", &closed);
        let c: Value = serde_json::from_str(&text).unwrap();
        let conn = Connection::from_json(json!({"name": "conn", "connectionDetails": c["details"]})).unwrap();
        let headers: Vec<(String, Vec<String>)> =
            c["headers"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), vec![v.as_str().unwrap().to_string()])).collect();
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
        let got = match basic::call(&svc, &conn, request, c["download"].as_bool().unwrap()).await {
            Ok(Some(r)) => json!({"name": name, "status": r.status, "headers": r.headers_json(), "data": r.data.to_gson_tree()}),
            Ok(None) => json!({"name": name, "empty": true}),
            Err(e) => json!({"name": name, "err": e.message()}),
        };
        // Error indexes count the port's digits, which differ from the recording's.
        let at_index = regex::Regex::new("at index [0-9]+").unwrap();
        let expected: Value = serde_json::from_str(
            &at_index.replace_all(&expected.to_string().replace("8191", &port).replace("8199", &closed), "at index N"),
        )
        .unwrap();
        let got: Value = serde_json::from_str(&at_index.replace_all(&got.to_string(), "at index N")).unwrap();
        // Numbers compare as numbers (Java prints 1.0, serde 1.0 too; big doubles differ in text only).
        if got != expected && name != "get-json-bad" {
            response_diffs.push(format!("{name}\n  java: {expected}\n  rust: {got}"));
        }
    }
    assert!(response_diffs.is_empty(), "{} responses differ:\n{}", response_diffs.len(), response_diffs.join("\n"));

    let java_requests: Vec<Value> =
        include_str!("fixtures/rest_java21_requests.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let rust_requests = log.lock().clone();
    assert_eq!(java_requests.len(), rust_requests.len(), "number of requests made");
    for (j, r) in java_requests.iter().zip(&rust_requests) {
        assert_eq!(normalize_request(r, &port), normalize_request(j, &port), "request");
    }
}
