//! The file side of transports: the exported `.modl` (a zip of `security.json`, `core.cmodl`
//! and `ui.umodl`, the last two zips themselves), and rewriting a definition for the app and
//! client it is applied to.

use std::io::{Cursor, Read, Write};

use anyhow::{Context, Result};
use num_bigint::BigInt;
use rand::RngCore;
use serde_json::Value;
use zip::write::SimpleFileOptions;

const BASE: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// `UniqueUtil.shortUUID`: a random UUID's 128 bits as a signed big integer, in base 62,
/// left-padded with `0` to 22 characters.
pub fn short_uuid() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    // Version 4, variant 2, as UUID.randomUUID() sets them.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    short_uuid_of(&bytes)
}

fn short_uuid_of(bytes: &[u8; 16]) -> String {
    let mut num = BigInt::from_signed_bytes_be(bytes);
    let base = BigInt::from(62u32);
    let zero = BigInt::from(0u32);
    let mut out = Vec::new();
    while num != zero {
        // Java BigInteger.mod is never negative; divide truncates toward zero.
        let m = ((&num % &base) + &base) % &base;
        let digit = m.to_u32_digits().1.first().copied().unwrap_or(0) as usize;
        out.push(BASE[digit]);
        num /= &base;
    }
    out.reverse();
    let s = String::from_utf8(out).unwrap_or_default();
    format!("{s:0>22}")
}

/// `makeAppCodeChanges(Map, ...)` for a JSON definition part: the part and every object's
/// `data` get the app and client code; Application and Filler objects are renamed to the app.
/// `client_code` is `None` when security found no base client (an app the caller's own client
/// owns): Java writes `null`, and the receiving service then uses the caller's client.
pub fn json_app_code_changes(part: Option<Value>, app_code: &str, client_code: Option<&str>) -> Option<Value> {
    let cc = || client_code.map(|c| Value::String(c.into())).unwrap_or(Value::Null);
    let mut part = part?;
    let Value::Object(map) = &mut part else { return Some(part) };
    if map.is_empty() {
        return Some(part);
    }
    map.insert("appCode".into(), Value::String(app_code.into()));
    map.insert("clientCode".into(), cc());
    map.insert("uniqueTransportCode".into(), Value::String(short_uuid()));
    if let Some(Value::Array(objects)) = map.get_mut("objects") {
        for o in objects.iter_mut() {
            let Value::Object(o) = o else { continue };
            let rename = matches!(o.get("objectType").and_then(Value::as_str), Some("Application") | Some("Filler"));
            if let Some(Value::Object(data)) = o.get_mut("data") {
                data.insert("appCode".into(), Value::String(app_code.into()));
                data.insert("clientCode".into(), cc());
                if rename {
                    data.insert("name".into(), Value::String(app_code.into()));
                }
            }
        }
    }
    Some(part)
}

/// `makeAppCodeChanges(Path, Path, ...)`: every JSON object file in a `.cmodl` / `.umodl` zip
/// gets the app and client code where it has those keys, a fresh `uniqueTransportCode` where it
/// has one, and the app's name when it sits in an `Application` or `Filler` folder. Anything
/// that is not a JSON object is copied unchanged.
pub fn rewrite_modl(zip_bytes: &[u8], app_code: &str, client_code: Option<&str>) -> Result<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes)).context("reading the transport zip")?;
    let mut out = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_string();
        if entry.is_dir() {
            out.add_directory(name, opts)?;
            continue;
        }
        let mut content = Vec::new();
        entry.read_to_end(&mut content)?;
        let content = rewrite_entry(&name, content, app_code, client_code);
        out.start_file(name, opts)?;
        out.write_all(&content)?;
    }
    Ok(out.finish()?.into_inner())
}

fn rewrite_entry(name: &str, content: Vec<u8>, app_code: &str, client_code: Option<&str>) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(&content) else { return content };
    if text.trim().is_empty() {
        return content;
    }
    let Ok(Value::Object(mut m)) = serde_json::from_str::<Value>(text) else { return content };
    if m.contains_key("appCode") {
        m.insert("appCode".into(), Value::String(app_code.into()));
    }
    if m.contains_key("clientCode") {
        m.insert("clientCode".into(), client_code.map(|c| Value::String(c.into())).unwrap_or(Value::Null));
    }
    if m.contains_key("uniqueTransportCode") {
        m.insert("uniqueTransportCode".into(), Value::String(short_uuid()));
    }
    let parent = name.trim_end_matches('/').rsplit_once('/').map(|(p, _)| p).unwrap_or("");
    let parent_name = parent.rsplit('/').next().unwrap_or("");
    if parent_name == "Application" || parent_name == "Filler" {
        m.insert("name".into(), Value::String(app_code.into()));
    }
    serde_json::to_vec(&Value::Object(m)).unwrap_or(content)
}

/// The exported application: `security.json`, `core.cmodl`, `ui.umodl`.
pub fn export_zip(security: &[u8], core: &[u8], ui: &[u8]) -> Result<Vec<u8>> {
    let mut out = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, bytes) in [("security.json", security), ("core.cmodl", core), ("ui.umodl", ui)] {
        out.start_file(name, opts)?;
        out.write_all(bytes)?;
    }
    Ok(out.finish()?.into_inner())
}

/// The three parts of an exported application.
pub struct ModlParts {
    pub security: Option<Value>,
    pub core: Vec<u8>,
    pub ui: Vec<u8>,
}

pub fn read_modl(bytes: &[u8]) -> Result<ModlParts> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).context("reading the application zip")?;
    let mut read = |name: &str| -> Result<Vec<u8>> {
        let slashed = format!("/{name}");
        let found = [name, slashed.as_str()]
            .into_iter()
            .find(|n| archive.index_for_name(n).is_some())
            .with_context(|| format!("{name} missing from the application zip"))?;
        let mut e = archive.by_name(found)?;
        let mut v = Vec::new();
        e.read_to_end(&mut v)?;
        Ok(v)
    };
    let security_bytes = read("security.json")?;
    let security = serde_json::from_slice(&security_bytes).context("security.json is not JSON")?;
    Ok(ModlParts { security: Some(security), core: read("core.cmodl")?, ui: read("ui.umodl")? })
}

/// Whether a downloaded definition is JSON (else a zip), as Java decides it.
pub fn is_json(bytes: &[u8]) -> bool {
    String::from_utf8_lossy(bytes).trim_start().starts_with('{')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn short_uuid_shape() {
        for _ in 0..100 {
            let s = short_uuid();
            assert_eq!(s.len(), 22);
            assert!(s.bytes().all(|b| BASE.contains(&b)));
        }
        assert_eq!(short_uuid_of(&[0u8; 16]), "0".repeat(22));
        let mut one = [0u8; 16];
        one[15] = 63;
        assert_eq!(short_uuid_of(&one), format!("{}11", "0".repeat(20)));
    }

    #[test]
    fn negative_uuids_still_encode() {
        // All bits set is -1 as a Java BigInteger: -1 mod 62 is 61 ('Z'), and -1 / 62 is 0.
        let s = short_uuid_of(&[0xff; 16]);
        assert_eq!(s, format!("{}Z", "0".repeat(21)));
    }

    #[test]
    fn json_changes() {
        let part = json!({"appCode": "old", "objects": [
            {"objectType": "Application", "data": {"name": "old", "appCode": "old"}},
            {"objectType": "Page", "data": {"name": "home"}},
            {"objectType": "Filler"}
        ]});
        let out = json_app_code_changes(Some(part), "new", Some("FIN")).unwrap();
        assert_eq!(out["appCode"], "new");
        assert_eq!(out["clientCode"], "FIN");
        assert_eq!(out["uniqueTransportCode"].as_str().unwrap().len(), 22);
        assert_eq!(out["objects"][0]["data"], json!({"name": "new", "appCode": "new", "clientCode": "FIN"}));
        assert_eq!(out["objects"][1]["data"], json!({"name": "home", "appCode": "new", "clientCode": "FIN"}));
        assert!(json_app_code_changes(None, "a", Some("b")).is_none());
        assert_eq!(json_app_code_changes(Some(json!({})), "a", Some("b")), Some(json!({})));
        let none = json_app_code_changes(Some(json!({"objects": [{"data": {}}]})), "a", None).unwrap();
        assert_eq!(none["clientCode"], Value::Null);
        assert_eq!(none["objects"][0]["data"]["clientCode"], Value::Null);
    }

    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (n, b) in entries {
            if n.ends_with('/') {
                out.add_directory(*n, SimpleFileOptions::default()).unwrap();
            } else {
                out.start_file(*n, SimpleFileOptions::default()).unwrap();
                out.write_all(b).unwrap();
            }
        }
        out.finish().unwrap().into_inner()
    }

    fn entries(z: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut a = zip::ZipArchive::new(Cursor::new(z)).unwrap();
        (0..a.len())
            .map(|i| {
                let mut e = a.by_index(i).unwrap();
                let mut v = Vec::new();
                e.read_to_end(&mut v).unwrap();
                (e.name().to_string(), v)
            })
            .collect()
    }

    #[test]
    fn modl_rewrite_follows_java_rules() {
        let z = zip_of(&[
            ("Application/", b""),
            ("Application/app.json", br#"{"name":"old","appCode":"old","clientCode":"X","uniqueTransportCode":"u"}"#),
            ("Page/home.json", br#"{"name":"home","appCode":"old"}"#),
            ("Page/list.json", br#"[1,2]"#),
            ("Page/empty.json", b""),
            ("bin.dat", &[0xff, 0xfe, 0x00]),
        ]);
        let out = entries(&rewrite_modl(&z, "new", Some("FIN")).unwrap());
        let get = |n: &str| out.iter().find(|(name, _)| name == n).map(|(_, v)| v.clone()).unwrap();
        let app: Value = serde_json::from_slice(&get("Application/app.json")).unwrap();
        assert_eq!(app["name"], "new");
        assert_eq!(app["appCode"], "new");
        assert_eq!(app["clientCode"], "FIN");
        assert_ne!(app["uniqueTransportCode"], "u");
        let page: Value = serde_json::from_slice(&get("Page/home.json")).unwrap();
        assert_eq!(page, json!({"name": "home", "appCode": "new"}), "no clientCode key, none added");
        assert_eq!(get("Page/list.json"), b"[1,2]");
        assert_eq!(get("Page/empty.json"), b"");
        assert_eq!(get("bin.dat"), vec![0xff, 0xfe, 0x00]);
        assert!(out.iter().any(|(n, _)| n == "Application/"));
    }

    #[test]
    fn export_round_trip() {
        let z = export_zip(br#"{"a":1}"#, b"core", b"ui").unwrap();
        let parts = read_modl(&z).unwrap();
        assert_eq!(parts.security, Some(json!({"a": 1})));
        assert_eq!(parts.core, b"core");
        assert_eq!(parts.ui, b"ui");
        assert!(read_modl(b"not a zip").is_err());
        assert!(is_json(b"  {\"x\":1}"));
        assert!(!is_json(&z));
    }
}
