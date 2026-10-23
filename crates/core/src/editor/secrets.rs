//! A connection's credentials never leave core-editor. Every reply that carries a connection
//! (the object, its draft, the eager list's `data`, its version history) has each secret in
//! `connectionDetails` replaced by [`SECRET_MASK`]; the code that opens connections reads the
//! stored document and never sees the mask.
//!
//! Which keys are secrets is `connections::connection::is_secret_key`. Under a secret key every
//! non-empty text is masked, at any depth (other values, such as `isLifeTimeToken: true`, are
//! not credentials and stay). Any other text that is an address with a password in its user
//! part (`mysql://app:pw@db/x`) has that password masked.
//!
//! A save that sends a secret back absent, null, empty or as the mask keeps the stored one, so a
//! page that loads a connection, edits another field and saves the whole thing back changes
//! nothing it did not mean to. A new non-empty value replaces it. "Absent" is a key missing from
//! an object the save does send: a save without `connectionDetails` at all replaces the details
//! as before.

use connections::connection::{is_secret_key, mask_url_password, restore_url_password, SECRET_MASK};
use overridable::write::version::VersionRedaction;
use overridable::{JMap, JValue};

/// The field of a connection that holds its credentials.
pub const DETAILS: &str = "connectionDetails";

/// A connection's version history, held back as the connection is.
pub static HISTORY: [VersionRedaction; 1] = [VersionRedaction { object_type: "CONNECTION", redact: masked, filterable: history_filterable }];

fn history_filterable(field: &str) -> bool {
    filterable(field, "object.")
}

/// The connection as a reply carries it.
pub fn masked(mut entity: JMap) -> JMap {
    if let Some(JValue::Object(d)) = entity.get_mut(DETAILS) {
        mask_map(d, false);
    }
    entity
}

/// `incoming`'s withheld secrets (absent, null, empty or the mask) put back from `current`.
pub fn keep_stored(incoming: &mut JMap, current: &JMap) {
    if let (Some(JValue::Object(i)), Some(JValue::Object(c))) = (incoming.get_mut(DETAILS), current.get(DETAILS)) {
        keep_map(i, c, false);
    }
}

/// A new connection's withheld secrets (null, empty or the mask) left out: there is nothing
/// stored to keep, and the mask is never a credential.
pub fn drop_withheld(incoming: &mut JMap) {
    if let Some(JValue::Object(d)) = incoming.get_mut(DETAILS) {
        drop_map(d, false);
    }
}

/// Whether a list filter, sort or version query may name `field`: nothing inside a
/// connection's details, which could be matched against a guess. `prefix` is what the field
/// path starts with before the document (`object.` on a version row).
pub fn filterable(field: &str, prefix: &str) -> bool {
    // The version row's whole `object` compares the details too.
    if !prefix.is_empty() && field == prefix.trim_end_matches('.') {
        return false;
    }
    let Some(rest) = field.strip_prefix(prefix) else { return true };
    !(rest == DETAILS || rest.starts_with(&format!("{DETAILS}.")))
}

fn masked_text(s: &str) -> bool {
    s.is_empty() || s == SECRET_MASK
}

/// A value under a secret key that the reply masks: text, or a map or list holding some.
fn would_mask(v: &JValue) -> bool {
    match v {
        JValue::Str(s) => !s.is_empty(),
        JValue::Object(m) => m.values().any(would_mask),
        JValue::Array(a) => a.iter().any(would_mask),
        _ => false,
    }
}

/// Sent back withheld: absent, null, empty text or the mask.
fn withheld(v: Option<&JValue>) -> bool {
    match v {
        None | Some(JValue::Null) => true,
        Some(JValue::Str(s)) => masked_text(s),
        _ => false,
    }
}

fn mask_value(v: &mut JValue, secret: bool) {
    match v {
        JValue::Str(s) if secret => {
            if !s.is_empty() {
                *s = SECRET_MASK.to_string();
            }
        }
        JValue::Str(s) => {
            if let Some(m) = mask_url_password(s) {
                *s = m;
            }
        }
        JValue::Object(m) => mask_map(m, secret),
        JValue::Array(a) => a.iter_mut().for_each(|x| mask_value(x, secret)),
        _ => {}
    }
}

fn mask_map(m: &mut JMap, secret: bool) {
    for (k, v) in m.iter_mut() {
        mask_value(v, secret || is_secret_key(k));
    }
}

fn keep_value(incoming: &mut JValue, stored: &JValue, secret: bool) {
    match (incoming, stored) {
        (JValue::Object(i), JValue::Object(s)) => keep_map(i, s, secret),
        (JValue::Array(i), JValue::Array(s)) if i.len() == s.len() => {
            for (x, y) in i.iter_mut().zip(s) {
                keep_value(x, y, secret);
            }
        }
        (i, s) if secret => {
            if withheld(Some(i)) && would_mask(s) {
                *i = s.clone();
            }
        }
        (JValue::Str(i), JValue::Str(s)) => {
            if let Some(r) = restore_url_password(i, s) {
                *i = r;
            }
        }
        _ => {}
    }
}

fn keep_map(incoming: &mut JMap, stored: &JMap, secret: bool) {
    for (k, s) in stored {
        let secret = secret || is_secret_key(k);
        match incoming.get_mut(k.as_str()) {
            Some(i) => keep_value(i, s, secret),
            None if secret && would_mask(s) => {
                incoming.insert(k.clone(), s.clone());
            }
            None => {}
        }
    }
}

fn drop_map(m: &mut JMap, secret: bool) {
    let keys: Vec<String> = m.keys().cloned().collect();
    for k in keys {
        let secret = secret || is_secret_key(&k);
        let remove = match m.get_mut(k.as_str()) {
            Some(JValue::Object(inner)) => {
                drop_map(inner, secret);
                false
            }
            Some(v) => secret && withheld(Some(v)),
            None => false,
        };
        if remove {
            m.shift_remove(k.as_str());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use overridable::json::parse;

    fn obj(s: &str) -> JMap {
        match parse(s.as_bytes()).unwrap() {
            JValue::Object(m) => m,
            _ => panic!(),
        }
    }

    const STORED: &str = r#"{"name":"c","connectionDetails":{
        "baseUrl":"https://example.com","userName":"u","password":"fake-pw",
        "mailProps":{"mail.smtp.host":"smtp.example.com","mail.password":"fake-mail-pw"},
        "tokenDetails":{"url":"https://example.com/t","queryParams":{"client_id":"id","client_secret":"fake-cs"}},
        "headers":{"developer-token":"fake-dt","appCode":"x"},
        "isLifeTimeToken":true,"tokenKey":"access_token","emptySecret":"",
        "url":"mysql://app:fake-db-pw@db.example.com/x",
        "credentials":{"kind":"service","keys":["fake-k1","fake-k2"]},
        "list":[{"apiKey":"fake-ak","label":"l"}]}}"#;

    #[test]
    fn a_reply_masks_every_secret() {
        let out = masked(obj(STORED));
        let d = out[DETAILS].as_object().unwrap();
        let s = |v: &JValue| v.as_str().map(str::to_string);
        assert_eq!(s(&d["password"]).as_deref(), Some(SECRET_MASK));
        assert_eq!(s(&d["userName"]).as_deref(), Some("u"));
        assert_eq!(s(&d["baseUrl"]).as_deref(), Some("https://example.com"));
        let mail = d["mailProps"].as_object().unwrap();
        assert_eq!(s(&mail["mail.password"]).as_deref(), Some(SECRET_MASK));
        assert_eq!(s(&mail["mail.smtp.host"]).as_deref(), Some("smtp.example.com"));
        let q = d["tokenDetails"].as_object().unwrap()["queryParams"].as_object().unwrap();
        assert_eq!(s(&q["client_secret"]).as_deref(), Some(SECRET_MASK));
        assert_eq!(s(&q["client_id"]).as_deref(), Some("id"));
        assert_eq!(s(&d["headers"].as_object().unwrap()["developer-token"]).as_deref(), Some(SECRET_MASK));
        assert_eq!(d["isLifeTimeToken"], JValue::Bool(true), "a flag is no credential");
        assert_eq!(s(&d["tokenKey"]).as_deref(), Some("access_token"), "names a field, holds no secret");
        assert_eq!(s(&d["emptySecret"]).as_deref(), Some(""), "nothing set stays visibly empty");
        assert_eq!(s(&d["url"]).as_deref(), Some("mysql://app:********@db.example.com/x"));
        assert_eq!(d["credentials"], JValue::Object(obj(r#"{"kind":"********","keys":["********","********"]}"#)));
        assert_eq!(d["list"], parse(br#"[{"apiKey":"********","label":"l"}]"#).unwrap());
        assert!(!overridable::json::map_to_compact(&out).contains("fake-"), "no secret survives anywhere");
    }

    #[test]
    fn a_document_without_details_is_untouched() {
        let e = obj(r#"{"name":"c","connectionDetails":null}"#);
        assert_eq!(masked(e.clone()), e);
        let e = obj(r#"{"name":"c"}"#);
        assert_eq!(masked(e.clone()), e);
    }

    #[test]
    fn saving_a_masked_read_back_keeps_every_stored_secret() {
        let stored = obj(STORED);
        let mut incoming = masked(stored.clone());
        incoming.insert("title".into(), JValue::Str("edited".into()));
        keep_stored(&mut incoming, &stored);
        assert_eq!(incoming[DETAILS], stored[DETAILS]);
        assert_eq!(incoming["title"], JValue::Str("edited".into()));
    }

    #[test]
    fn absent_null_and_empty_keep_and_a_new_value_replaces() {
        let stored = obj(STORED);
        let mut incoming = obj(
            r#"{"connectionDetails":{"baseUrl":"https://new.example.com","userName":"v","password":"",
            "mailProps":{"mail.smtp.host":"h2","mail.password":null},
            "tokenDetails":{"queryParams":{"client_id":"id2","client_secret":"fake-new-cs"}},
            "url":"mysql://app:********@db2.example.com/y","credentials":"********"}}"#,
        );
        keep_stored(&mut incoming, &stored);
        let d = incoming[DETAILS].as_object().unwrap();
        assert_eq!(d["password"], JValue::Str("fake-pw".into()), "empty keeps");
        assert_eq!(d["baseUrl"], JValue::Str("https://new.example.com".into()));
        assert_eq!(d["userName"], JValue::Str("v".into()));
        let mail = d["mailProps"].as_object().unwrap();
        assert_eq!(mail["mail.password"], JValue::Str("fake-mail-pw".into()), "null keeps");
        assert_eq!(mail["mail.smtp.host"], JValue::Str("h2".into()));
        let q = d["tokenDetails"].as_object().unwrap()["queryParams"].as_object().unwrap();
        assert_eq!(q["client_secret"], JValue::Str("fake-new-cs".into()), "a new value replaces");
        assert_eq!(d["url"], JValue::Str("mysql://app:fake-db-pw@db2.example.com/y".into()), "the masked part of an address keeps");
        assert_eq!(d["credentials"], stored[DETAILS].as_object().unwrap()["credentials"], "a masked map keeps whole");
        assert!(!d.contains_key("headers"), "a map the save leaves out stays out");
        assert!(!d.contains_key("isLifeTimeToken"), "only credentials are kept when left out");
        assert!(!d.contains_key("emptySecret"), "an empty stored secret has nothing to keep");
    }

    #[test]
    fn absent_secret_keys_come_back() {
        let stored = obj(STORED);
        let mut incoming = obj(r#"{"connectionDetails":{"userName":"u","mailProps":{"mail.smtp.host":"h"}}}"#);
        keep_stored(&mut incoming, &stored);
        let d = incoming[DETAILS].as_object().unwrap();
        assert_eq!(d["password"], JValue::Str("fake-pw".into()));
        assert_eq!(d["mailProps"].as_object().unwrap()["mail.password"], JValue::Str("fake-mail-pw".into()));
        assert!(!d.contains_key("baseUrl"));
    }

    #[test]
    fn no_details_on_either_side_changes_nothing() {
        let stored = obj(STORED);
        let mut incoming = obj(r#"{"connectionDetails":null}"#);
        keep_stored(&mut incoming, &stored);
        assert_eq!(incoming[DETAILS], JValue::Null, "a save without details replaces them, as before");
        let mut incoming = obj(r#"{"connectionDetails":{"password":"********"}}"#);
        keep_stored(&mut incoming, &obj(r#"{"connectionDetails":null}"#));
        assert_eq!(incoming[DETAILS].as_object().unwrap()["password"], JValue::Str(SECRET_MASK.into()));
    }

    #[test]
    fn a_new_connection_drops_withheld_secrets() {
        let mut incoming = obj(
            r#"{"connectionDetails":{"userName":"u","password":"********","apiKey":"","token":null,
            "mailProps":{"mail.password":"********","mail.smtp.host":"h"},"apiToken":"fake-at","isLifeTimeToken":false}}"#,
        );
        drop_withheld(&mut incoming);
        assert_eq!(
            incoming[DETAILS],
            JValue::Object(obj(r#"{"userName":"u","mailProps":{"mail.smtp.host":"h"},"apiToken":"fake-at","isLifeTimeToken":false}"#))
        );
    }

    #[test]
    fn details_cannot_be_filtered_or_sorted_on() {
        for f in ["connectionDetails", "connectionDetails.password", "connectionDetails.url"] {
            assert!(!filterable(f, ""), "{f}");
        }
        for f in ["name", "connectionSubType", "appCode", "connectionDetailsX"] {
            assert!(filterable(f, ""), "{f}");
        }
        for f in ["object", "object.connectionDetails", "object.connectionDetails.mailProps.mail.password"] {
            assert!(!filterable(f, "object."), "{f}");
        }
        for f in ["object.name", "versionNumber", "createdAt", "objectName"] {
            assert!(filterable(f, "object."), "{f}");
        }
    }
}
