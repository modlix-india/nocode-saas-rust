//! Answers recorded from the Java code itself (JDK 21, the local core's classpath) and replayed
//! against the port. The harnesses that produced them call `OutboundUrlUtil` and Spring's
//! `CustomUriBuilderFactory` / `UriComponentsBuilder` directly.

use std::collections::HashMap;
use std::sync::Arc;

use connections::error::ConnError;
use connections::outbound;
use connections::rest::spring_uri::{build_request_uri, build_to_uri, build_to_uri_string, WebClientEncodingMode};
use serde_json::{json, Map, Value};

fn unescape(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out: Vec<u16> = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 5 < chars.len() && chars[i + 1] == 'u' {
            let hex: String = chars[i + 2..i + 6].iter().collect();
            out.push(u16::from_str_radix(&hex, 16).unwrap_or(0));
            i += 6;
        } else {
            let mut buf = [0u16; 2];
            out.extend_from_slice(chars[i].encode_utf16(&mut buf));
            i += 1;
        }
    }
    String::from_utf16_lossy(&out)
}

async fn guard_answer(mode: &str, key: &str, raw: &str) -> String {
    let value = unescape(raw);
    let res = if mode == "details" {
        let mut m = Map::new();
        m.insert(key.to_string(), Value::String(value));
        outbound::validate_connection_details(Some(&m)).await
    } else {
        outbound::validate_resolved(&value).await
    };
    match res {
        Ok(()) => "OK".into(),
        Err(ConnError::Generic { message, .. }) => format!("ERR GenericException: {message}"),
        Err(e) => format!("ERR Other: {e}"),
    }
}

async fn replay_guard(include_resolved: bool) {
    let recorded = include_str!("fixtures/guard_vectors_java21.tsv");
    let mut checked = 0;
    let mut mismatches = Vec::new();
    for line in recorded.lines().filter(|l| !l.is_empty()) {
        let p: Vec<&str> = line.splitn(4, '\t').collect();
        let (mode, key, raw, expected) = (p[0], p[1], p[2], p[3]);
        if mode == "resolved" && !include_resolved {
            continue;
        }
        let got = guard_answer(mode, key, raw).await;
        checked += 1;
        if got.replace('\n', "\\n") != expected {
            mismatches.push(format!("{mode} {key} {raw}\n  java: {expected}\n  rust: {got}"));
        }
    }
    assert!(checked > 500, "only {checked} cases");
    assert!(mismatches.is_empty(), "{} of {checked} differ:\n{}", mismatches.len(), mismatches.join("\n"));
}

/// Save-time checks: no DNS except for numeric-looking names that are not literals, which do
/// not resolve anywhere.
#[tokio::test]
async fn guard_save_time_matches_java() {
    replay_guard(false).await;
}

/// Call-time checks resolve real names (`example.com`, `api.stripe.com`): needs DNS.
/// `cargo test -p connections -- --ignored guard_call_time`
#[tokio::test]
#[ignore]
async fn guard_call_time_matches_java() {
    replay_guard(true).await;
}

/// The same call-time cases with the DNS answers Java saw: a name Java found unresolvable
/// resolves to nothing, a name it found private resolves to that address, every other name to
/// a public address.
#[tokio::test]
async fn guard_call_time_with_javas_dns_answers() {
    let recorded = include_str!("fixtures/guard_vectors_java21.tsv");
    let unresolvable = regex::Regex::new(r"'([^']+)' (?:does not resolve to any address|is not a usable address)").unwrap();
    let private = regex::Regex::new(r"'([^']+)' resolves to ([0-9a-fA-F:.]+), which is a private").unwrap();
    let mut answers: HashMap<String, Option<Vec<std::net::IpAddr>>> = HashMap::new();
    for line in recorded.lines() {
        if let Some(c) = unresolvable.captures(line) {
            answers.insert(c[1].to_string(), None);
        }
        if let Some(c) = private.captures(line) {
            answers.insert(c[1].to_string(), Some(vec![c[2].parse().unwrap()]));
        }
    }
    let resolver: outbound::Resolver = Arc::new(move |name: &str| {
        answers.get(name).cloned().unwrap_or_else(|| Some(vec!["93.184.216.34".parse().unwrap()]))
    });
    outbound::with_resolver(resolver, replay_guard(true)).await;
}

/// `guard_target` (Java's rules, then the same rules on the `url` crate's reading of the host)
/// against the Java verdicts of every call-time vector, with Java's DNS answers. It allows
/// nothing Java refuses, and refuses one URL Java allows: `0177.0.0.1`, which Java reads as the
/// decimal 177.0.0.1 and the `url` crate (the HTTP client's parser) as the octal 127.0.0.1.
#[tokio::test]
async fn guard_target_against_javas_vectors() {
    let recorded = include_str!("fixtures/guard_vectors_java21.tsv");
    let unresolvable = regex::Regex::new(r"'([^']+)' (?:does not resolve to any address|is not a usable address)").unwrap();
    let private = regex::Regex::new(r"'([^']+)' resolves to ([0-9a-fA-F:.]+), which is a private").unwrap();
    let mut answers: HashMap<String, Option<Vec<std::net::IpAddr>>> = HashMap::new();
    for line in recorded.lines() {
        if let Some(c) = unresolvable.captures(line) {
            answers.insert(c[1].to_string(), None);
        }
        if let Some(c) = private.captures(line) {
            answers.insert(c[1].to_string(), Some(vec![c[2].parse().unwrap()]));
        }
    }
    let resolver: outbound::Resolver = Arc::new(move |name: &str| {
        answers.get(name).cloned().unwrap_or_else(|| Some(vec!["93.184.216.34".parse().unwrap()]))
    });
    outbound::with_resolver(resolver, async {
        let mut checked = 0;
        let mut differ = Vec::new();
        for line in recorded.lines().filter(|l| l.starts_with("resolved\t")) {
            let p: Vec<&str> = line.splitn(4, '\t').collect();
            let url = unescape(p[2]);
            let java_ok = p[3] == "OK";
            let ours = outbound::guard_target(&url).await;
            checked += 1;
            if java_ok != ours.is_ok() {
                differ.push(format!("{url}: java {} / guard_target {:?}", p[3], ours.err().map(|e| e.message().to_string())));
            }
        }
        assert!(checked > 800, "only {checked} cases");
        let expected = vec![String::from(
            "http://0177.0.0.1/: java OK / guard_target Some(\"Refusing to call \\\"http://0177.0.0.1/\\\": '127.0.0.1' is a private or internal address. Only addresses reachable from the public internet can be called.\")",
        )];
        assert_eq!(differ, expected, "{} of {checked} differ", differ.len());
    })
    .await;
}

#[test]
fn uri_building_matches_spring() {
    let vectors = [include_str!("fixtures/uri_vectors.jsonl"), include_str!("fixtures/uri_vectors2.jsonl")].concat();
    let answers = [include_str!("fixtures/uri_java21.jsonl"), include_str!("fixtures/uri2_java21.jsonl")].concat();
    let mut n = 0;
    for (v, a) in vectors.lines().zip(answers.lines()) {
        let v: Value = serde_json::from_str(v).unwrap();
        let expected: Value = serde_json::from_str(a).unwrap();
        let url = v["url"].as_str().unwrap();
        let query: Vec<(String, String)> = v["query"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| (p[0].as_str().unwrap().to_string(), p[1].as_str().unwrap().to_string()))
            .collect();
        let res = match v["kind"].as_str().unwrap() {
            "rest" => {
                let path: HashMap<String, String> =
                    v["path"].as_object().unwrap().iter().map(|(k, x)| (k.clone(), x.as_str().unwrap().to_string())).collect();
                WebClientEncodingMode::value_of(v["mode"].as_str().unwrap()).and_then(|m| build_request_uri(url, m, &query, &path))
            }
            "touri" => build_to_uri(url, &query),
            _ => build_to_uri_string(url, &query),
        };
        let got = match res {
            Ok(s) => json!({"ok": s}),
            Err(e) => json!({"err": e.message()}),
        };
        assert_eq!(got, expected, "case {v}");
        n += 1;
    }
    assert!(n > 3000);
}

/// Templates rendered by FreeMarker 2.3.32 with `AbstractTemplateService`'s configuration
/// (JDK 21, `en_US`; `en_IN` gives the same text), the data through `JsonUtil.toMap`. Four
/// cases use features no stored template uses (`<#assign>`, `?seq_contains`, `${}` inside a
/// string literal, scientific number patterns), which the port refuses rather than renders.
#[test]
fn freemarker_matches_java() {
    let unsupported = ["<#assign", "seq_contains", "${\"${", "E0\")"];
    let mut checked = 0;
    for (cases, answers) in [
        (include_str!("fixtures/freemarker_cases.jsonl"), include_str!("fixtures/freemarker_java21.jsonl")),
        (include_str!("fixtures/freemarker_cases2.jsonl"), include_str!("fixtures/freemarker2_java21.jsonl")),
        (include_str!("fixtures/freemarker_cases3.jsonl"), include_str!("fixtures/freemarker3_java21.jsonl")),
    ] {
        for (c, a) in cases.lines().zip(answers.lines()) {
            let c: Value = serde_json::from_str(c).unwrap();
            let a: Value = serde_json::from_str(a).unwrap();
            let src = c["src"].as_str().unwrap();
            let got = connections::template::process("t", Some(src), c["data"].as_object().unwrap());
            if unsupported.iter().any(|u| src.contains(u)) {
                assert!(got.is_err());
                continue;
            }
            match (a.get("ok"), got) {
                (Some(expected), Ok(text)) => assert_eq!(&Value::String(text), expected, "template {src}"),
                (None, Err(_)) => {}
                (expected, got) => panic!("template {src}: java {expected:?}, rust {got:?}"),
            }
            checked += 1;
        }
    }
    assert!(checked > 200);
}

/// `new java.net.URI(s)`: scheme, host and port, or the syntax error's reason and index.
#[test]
fn java_uri_parser_matches_java() {
    let cases = include_str!("fixtures/java_uri_cases.jsonl");
    let answers = include_str!("fixtures/java_uri_java21.jsonl");
    let mut n = 0;
    for (c, a) in cases.lines().zip(answers.lines()) {
        let s: String = serde_json::from_str(c).unwrap();
        let expected: Value = serde_json::from_str(a).unwrap();
        let got = match connections::java::uri::parse(&s) {
            Ok(u) => json!({"scheme": u.scheme, "host": u.host, "port": u.port}),
            Err(e) => json!({"reason": e.reason, "index": e.index}),
        };
        assert_eq!(got, expected, "URI {s:?}");
        n += 1;
    }
    assert!(n > 400);
}

/// `InetAddress.getAllByName` on literal-looking hosts. Hosts Java hands to the resolver
/// (`Literal::Resolve` here) are left out: their answer is the machine's DNS, not the parser.
#[test]
fn inet_literals_match_java() {
    use connections::java::inet::{classify, Literal};
    let mut n = 0;
    for (c, a) in include_str!("fixtures/inet_cases.jsonl").lines().zip(include_str!("fixtures/inet_java21.jsonl").lines()) {
        let host: String = serde_json::from_str(c).unwrap();
        let expected: Value = serde_json::from_str(a).unwrap();
        match classify(&host) {
            Literal::Resolve(_) => continue,
            Literal::Unknown(_) => assert_eq!(expected, json!({"unknown": true}), "host {host:?}"),
            Literal::Address(addr) => {
                let java = expected["ok"][0].as_str().unwrap_or_else(|| panic!("host {host:?}: java {expected}"));
                assert_eq!(addr.host_address(), java.split('%').next().unwrap(), "host {host:?}");
            }
        }
        n += 1;
    }
    assert!(n > 40, "{n}");
}
