//! The outbound HTTP client against local servers: decoding, limits, refusals, token-endpoint
//! reads, and the failures callers see.

mod common;

use std::io::Write as _;
use std::net::IpAddr;
use std::sync::Arc;

use common::{server, Canned};
use connections::mq::{create_event, message_properties, EventMessage, Publisher, Route, EVENT_TYPE_ID};
use connections::outbound;
use connections::rest::http::{retrieve_json, HttpClient, JsonTarget, OutboundRequest};

fn get(uri: String) -> OutboundRequest {
    OutboundRequest { method: "GET".into(), uri, headers: vec![], body: None }
}

fn deflate(data: &[u8], zlib: bool) -> Vec<u8> {
    if zlib {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    } else {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }
}

#[tokio::test]
async fn deflate_bodies_and_limits() {
    let client = HttpClient { block_private_targets: false };
    for (zlib, coding) in [(true, "deflate"), (false, "x-deflate")] {
        let (port, _) = server(vec![Canned {
            status: 200,
            headers: vec![("Content-Encoding".into(), coding.into())],
            body: deflate(b"hello deflate", zlib),
            delay_ms: 0,
        }])
        .await;
        let r = client.send(get(format!("http://127.0.0.1:{port}/"))).await.unwrap();
        assert!(r.headers.iter().any(|(k, v)| k == "transfer-encoding" && v == "chunked"));
        assert_eq!(r.read_body(1024).await.unwrap(), b"hello deflate");
    }
    // An unknown coding is left alone.
    let (port, _) = server(vec![Canned { status: 200, headers: vec![("Content-Encoding".into(), "br".into())], body: b"raw".to_vec(), delay_ms: 0 }]).await;
    let r = client.send(get(format!("http://127.0.0.1:{port}/"))).await.unwrap();
    assert_eq!(r.read_body(1024).await.unwrap(), b"raw");
    // Limits, before and after decompression.
    let (port, _) = server(vec![Canned { status: 200, headers: vec![], body: vec![b'x'; 64], delay_ms: 0 }]).await;
    let r = client.send(get(format!("http://127.0.0.1:{port}/"))).await.unwrap();
    assert_eq!(r.read_body(10).await.unwrap_err().message(), "Exceeded limit on max bytes to buffer : 10");
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&[b'y'; 200]).unwrap();
    let (port, _) = server(vec![Canned { status: 200, headers: vec![("Content-Encoding".into(), "gzip".into())], body: gz.finish().unwrap(), delay_ms: 0 }]).await;
    let r = client.send(get(format!("http://127.0.0.1:{port}/"))).await.unwrap();
    assert!(r.read_body(100).await.is_err());
    // An empty encoded body stays empty.
    let (port, _) = server(vec![Canned { status: 204, headers: vec![("Content-Encoding".into(), "gzip".into())], body: vec![], delay_ms: 0 }]).await;
    let r = client.send(get(format!("http://127.0.0.1:{port}/"))).await.unwrap();
    assert!(r.read_body(100).await.unwrap().is_empty());
}

#[tokio::test]
async fn refusals_and_failures() {
    let client = HttpClient { block_private_targets: true };
    // A private literal is never connected to, and neither is a name answering one.
    let (port, log) = server(vec![Canned::json(200, "{}")]).await;
    let e = client.send(get(format!("http://127.0.0.1:{port}/"))).await.unwrap_err();
    assert!(e.message().contains("which is a private or internal address"), "{}", e.message());
    let r: outbound::Resolver = Arc::new(|_: &str| Some(vec!["127.0.0.1".parse::<IpAddr>().unwrap()]));
    let e = outbound::with_resolver(r, client.send(get(format!("http://rebound.example.com:{port}/")))).await.unwrap_err();
    assert!(e.message().contains("'rebound.example.com' resolves to 127.0.0.1"), "{}", e.message());
    assert!(log.lock().is_empty());

    let open = HttpClient { block_private_targets: false };
    let r: outbound::Resolver = Arc::new(|_: &str| None);
    let e = outbound::with_resolver(r, open.send(get("http://nowhere.example.com/".into()))).await.unwrap_err();
    assert_eq!(e.message(), "Failed to resolve 'nowhere.example.com'");
    assert!(open.send(get("ftp://127.0.0.1/".into())).await.unwrap_err().message().starts_with("Unsupported scheme"));
    assert!(open.send(get("not a url".into())).await.is_err());
    assert!(open.send(get("http://[::1]:1/".into())).await.is_err());
    let e = open.send(OutboundRequest { method: "B@D".into(), ..get(format!("http://127.0.0.1:{port}/")) }).await.unwrap_err();
    assert!(e.message().starts_with("Invalid HTTP method"));
    let e = open
        .send(OutboundRequest { headers: vec![("bad header".into(), "v".into())], ..get(format!("http://127.0.0.1:{port}/")) })
        .await
        .unwrap_err();
    assert!(e.message().starts_with("Invalid header name"));
    let e = open
        .send(OutboundRequest { headers: vec![("X".into(), "a\nb".into())], ..get(format!("http://127.0.0.1:{port}/")) })
        .await
        .unwrap_err();
    assert!(e.message().starts_with("Invalid header value"));
    // A TLS handshake with a server that does not speak TLS fails as an error.
    let junk = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let junk_port = junk.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = junk.accept().await else { return };
            use tokio::io::AsyncWriteExt;
            let _ = s.write_all(b"HTTP/1.1 400 Not TLS\r\n\r\n").await;
        }
    });
    let e = open.send(get(format!("https://127.0.0.1:{junk_port}/"))).await.unwrap_err();
    assert!(!e.message().is_empty());
    let r: outbound::Resolver = Arc::new(|_: &str| Some(vec!["127.0.0.1".parse::<IpAddr>().unwrap()]));
    assert!(outbound::with_resolver(r, open.send(get(format!("https://localhost.example.com:{junk_port}/")))).await.is_err());
    // A name served by a local server, with the caller's own Host and User-Agent.
    let (port2, log2) = server(vec![Canned::json(200, "{}")]).await;
    let r: outbound::Resolver = Arc::new(|_: &str| Some(vec!["127.0.0.1".parse::<IpAddr>().unwrap()]));
    let req = OutboundRequest {
        headers: vec![("Host".into(), "h.example.com".into()), ("User-Agent".into(), "me".into()), ("Accept-Encoding".into(), "identity".into())],
        ..get(format!("http://api.example.com:{port2}/x"))
    };
    let resp = outbound::with_resolver(r, open.send(req)).await.unwrap();
    assert_eq!(resp.status, 200);
    let seen = log2.lock()[0].to_lowercase();
    assert!(seen.contains("host: h.example.com") && seen.contains("user-agent: me") && seen.contains("accept-encoding: identity"));
}

#[tokio::test]
async fn token_endpoint_reads() {
    let client = HttpClient { block_private_targets: false };
    let (port, log) = server(vec![
        Canned::json(200, r#"{"access_token":"a"}"#),
        Canned::json(400, r#"{"error":"bad"}"#),
        Canned { status: 200, headers: vec![("Content-Type".into(), "text/plain".into())], body: b"x".to_vec(), delay_ms: 0 },
        Canned { status: 200, headers: vec![], body: b"x".to_vec(), delay_ms: 0 },
        Canned::json(200, "[1]"),
        Canned::json(200, "\"s\""),
        Canned::json(200, ""),
        Canned::json(200, "{oops"),
    ])
    .await;
    let uri = format!("http://127.0.0.1:{port}/token?x=1");
    let v = retrieve_json(&client, "POST", &uri, JsonTarget::Map).await.unwrap().unwrap();
    assert_eq!(v["access_token"], "a");
    assert!(log.lock()[0].starts_with("POST /token?x=1 HTTP/1.1"));
    assert!(log.lock()[0].contains("content-length: 0"));
    let e = retrieve_json(&client, "GET", &uri, JsonTarget::Map).await.unwrap_err();
    assert_eq!(e.message(), format!("400 Bad Request from GET {uri}"));
    let e = retrieve_json(&client, "GET", &uri, JsonTarget::Map).await.unwrap_err();
    assert_eq!(e.message(), "Content type 'text/plain' not supported for bodyType=java.util.Map<java.lang.String, java.lang.Object>");
    let e = retrieve_json(&client, "GET", &uri, JsonTarget::JsonNode).await.unwrap_err();
    assert_eq!(e.message(), "Content type 'application/octet-stream' not supported for bodyType=com.fasterxml.jackson.databind.JsonNode");
    assert!(retrieve_json(&client, "GET", &uri, JsonTarget::Map).await.unwrap_err().message().contains("Array value"));
    assert!(retrieve_json(&client, "GET", &uri, JsonTarget::Map).await.unwrap_err().message().contains("String value"));
    assert_eq!(retrieve_json(&client, "GET", &uri, JsonTarget::Map).await.unwrap(), None);
    assert!(retrieve_json(&client, "GET", &uri, JsonTarget::JsonNode).await.unwrap_err().message().starts_with("JSON decoding error"));
}

#[tokio::test]
async fn publishing_without_a_broker_fails_as_an_error() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let p = Publisher::new(format!("amqp://guest:guest@127.0.0.1:{closed}/%2f"));
    let e = create_event(&p, &Route::events(), &Default::default(), EventMessage::default()).await.unwrap_err();
    assert!(e.message().starts_with("AMQP connection failed"), "{}", e.message());
    let props = message_properties(EVENT_TYPE_ID);
    assert_eq!(props.content_type().as_ref().map(|s| s.to_string()).as_deref(), Some("application/json"));
    assert_eq!(*props.delivery_mode(), Some(2));
}
