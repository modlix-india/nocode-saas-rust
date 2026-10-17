//! `StorageFieldNames`: what a storage field may be called, and the MySQL column it is
//! stored in.
//!
//! A top-level field name becomes a column name, which cannot be bound and is concatenated
//! into DDL between backticks, so a name with a backtick in it would close the quoting.
//! Field names are not forced to be identifiers, though (webhooks send "IFSC Code"): the
//! MySQL backend stores such a field under [`column`], which is the name itself when it is
//! already an identifier and a normalised one otherwise.

use std::collections::HashSet;

use indexmap::IndexMap;
use platform::java::string_hash_code;

use crate::model::Schema;
use crate::value::Value;

const MAX_COLUMN: usize = 63;
const ID: &str = "_id";

/// `^[A-Za-z_][A-Za-z0-9_]{0,62}$`.
pub fn valid(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_COLUMN {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// Whether a schema field may have this name at all: not blank, no leading dollar, and no
/// dot, backtick or control character anywhere.
pub fn storable(name: &str) -> bool {
    if name.trim().is_empty() || name.starts_with('$') {
        return false;
    }
    // Java's isBlank also counts other whitespace; trim() covers what it does here.
    !name.encode_utf16().any(|c| c < 0x20 || c == 0x7f || c == b'.' as u16 || c == b'`' as u16)
}

/// The MySQL column a field is stored in.
pub fn column(name: &str) -> String {
    if valid(name) {
        return name.to_string();
    }
    // Java's regex matches code points, so every character outside the class (one
    // outside the BMP included) becomes a single underscore.
    let mut out: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    if out.is_empty() || out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, '_');
    }
    if out.len() > MAX_COLUMN {
        out.truncate(MAX_COLUMN - 9);
        out.push('_');
        out.push_str(&format!("{:08x}", string_hash_code(name) as u32));
    }
    out
}

/// A field a query is allowed to address: every dotted segment non-empty and not
/// starting with a dollar.
pub fn safe_query_path(field: &str) -> bool {
    if field.trim().is_empty() {
        return false;
    }
    field.split('.').all(|s| !s.is_empty() && !s.starts_with('$'))
}

/// A value a filter may compare against: no map anywhere in it with a dollar key.
pub fn safe_filter_value(value: Option<&Value>) -> bool {
    match value {
        None => true,
        Some(Value::Object(o)) => o.iter().all(|(k, v)| !k.starts_with('$') && safe_filter_value(Some(v))),
        Some(Value::Array(a)) => a.iter().all(|v| safe_filter_value(Some(v))),
        Some(_) => true,
    }
}

/// The same check over a list of values (`multiValue`).
pub fn safe_filter_values(values: Option<&Vec<Value>>) -> bool {
    values.is_none_or(|vs| vs.iter().all(|v| safe_filter_value(Some(v))))
}

/// Every name that cannot be stored, with the reason.
pub fn problems(schema: Option<&Schema>, relation_fields: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let empty = IndexMap::new();
    let props = schema.and_then(|s| s.properties.as_ref()).unwrap_or(&empty);

    let mut by_column: IndexMap<String, String> = IndexMap::new();
    by_column.insert(ID.into(), ID.into());

    for name in props.keys() {
        if !storable(name) {
            out.push(describe_field(name));
        } else {
            collision(name, &mut by_column, &mut out);
        }
    }

    let mut seen = HashSet::new();
    for name in relation_fields {
        if !seen.insert(name.clone()) {
            continue;
        }
        if !valid(name) {
            out.push(describe_relation(name));
        } else {
            collision(name, &mut by_column, &mut out);
        }
    }

    out
}

fn collision(name: &str, by_column: &mut IndexMap<String, String>, out: &mut Vec<String>) {
    let col = column(name);
    match by_column.get(&col) {
        Some(earlier) if earlier != name => out.push(format!(
            "field names {} and {} are both stored as the column {}; rename one of them",
            quoted(earlier),
            quoted(name),
            quoted(&col)
        )),
        Some(_) => {}
        None => {
            by_column.insert(col, name.to_string());
        }
    }
}

fn describe_field(name: &str) -> String {
    format!(
        "field name {} is not usable: a field may not be blank, start with '$', or contain a dot, a backtick or a control character",
        quoted(name)
    )
}

fn describe_relation(name: &str) -> String {
    format!(
        "relation name {} is not usable: a relation has to start with a letter or underscore and continue with letters, digits or underscores, up to 63 characters",
        quoted(name)
    )
}

fn quoted(name: &str) -> String {
    let mut s = String::from("\"");
    for c in name.chars() {
        s.push(if (c as u32) < 0x20 || c == '`' || c == '"' || c == '\\' { '?' } else { c });
    }
    s.push('"');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SchemaType;

    const HOSTILE: &str = "a` INT, ADD COLUMN `pwned";

    fn object(props: &[(&str, SchemaType)]) -> Schema {
        Schema {
            types: Some(vec![SchemaType::Object]),
            properties: Some(
                props
                    .iter()
                    .map(|(n, t)| (n.to_string(), Schema { types: Some(vec![*t]), ..Default::default() }))
                    .collect(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn the_rule() {
        for n in ["name", "createdAt", "_id", "line_1"] {
            assert!(valid(n), "{n}");
        }
        assert!(!valid(HOSTILE));
        assert!(!valid("a`b"));
        for n in ["2fast", "with space", "dotted.path", "$where", ""] {
            assert!(!valid(n), "{n}");
        }
        assert!(!valid(&"a".repeat(64)));
        assert!(valid(&"a".repeat(63)));
    }

    const HDFC: [&str; 16] = [
        "Alert Sequence No",
        "Virtual Account ",
        "Account number",
        "Debit Credit",
        "Amount",
        "Remitter Name",
        "Remitter Account",
        "Remitter Bank",
        "User Reference Number",
        "Cheque No",
        "Mnemonic Code",
        "Value Date",
        "IFSC Code",
        "Transaction Description",
        "Transaction Date",
        "paymentId",
    ];

    #[test]
    fn spaced_names_save() {
        let props: Vec<(&str, SchemaType)> = HDFC.iter().map(|n| (*n, SchemaType::String)).collect();
        assert!(problems(Some(&object(&props)), &[]).is_empty());
    }

    #[test]
    fn normalised() {
        assert_eq!(column("IFSC Code"), "IFSC_Code");
        assert_eq!(column("Virtual Account "), "Virtual_Account_");
        assert_eq!(column("2fast"), "_2fast");
        assert_eq!(column("a-b"), "a_b");
        for n in HDFC {
            assert!(valid(&column(n)), "{n}");
        }
        assert_eq!(column("amount"), "amount");
        assert_eq!(column("_id"), "_id");
        assert_eq!(column(&"a".repeat(63)), "a".repeat(63));
    }

    #[test]
    fn long_names_are_cut_and_stay_apart() {
        let a = format!("{}one", "x ".repeat(40));
        let b = format!("{}two", "x ".repeat(40));
        assert_eq!(column(&a).len(), 63);
        assert!(valid(&column(&a)));
        assert_ne!(column(&a), column(&b));
    }

    #[test]
    fn collisions_are_refused() {
        let p = problems(Some(&object(&[("Debit Credit", SchemaType::String), ("Debit_Credit", SchemaType::String)])), &[]);
        assert_eq!(p.len(), 1);
        assert!(p[0].contains("Debit Credit") && p[0].contains("Debit_Credit"), "{}", p[0]);
        assert_eq!(problems(Some(&object(&[("-id", SchemaType::String)])), &[]).len(), 1);
    }

    #[test]
    fn still_refused() {
        for n in ["$where", "address.city", HOSTILE, "tab\there", " "] {
            assert!(!storable(n), "{n:?}");
        }
        assert_eq!(problems(Some(&object(&[])), &["my customer".into()]).len(), 1);
        let p = problems(Some(&object(&[(HOSTILE, SchemaType::Integer)])), &[]);
        assert_eq!(p.len(), 1);
        assert!(!p[0].contains('`'));
        assert_eq!(problems(Some(&object(&[])), &[HOSTILE.into()]).len(), 1);
    }

    #[test]
    fn query_paths() {
        for p in ["name", "address.city", "items[0].sku"] {
            assert!(safe_query_path(p));
        }
        for p in ["$where", "$expr", "a.$where", "", "a..b"] {
            assert!(!safe_query_path(p), "{p}");
        }
    }

    #[test]
    fn filter_values() {
        let v = |s: &str| Value::parse_json(s).unwrap();
        assert!(safe_filter_value(Some(&v("\"hello\""))));
        assert!(safe_filter_value(Some(&v("42"))));
        assert!(safe_filter_value(None));
        assert!(safe_filter_value(Some(&v(r#"{"city":"Hyderabad"}"#))));
        assert!(safe_filter_value(Some(&v(r#"["a","b"]"#))));
        assert!(!safe_filter_value(Some(&v(r#"{"$gt":0}"#))));
        assert!(!safe_filter_value(Some(&v(r#"{"$ne":{"a":1}}"#))));
        assert!(!safe_filter_value(Some(&v(r#"[{"$where":"1"}]"#))));
        assert!(!safe_filter_value(Some(&v(r#"{"inner":{"$gt":1}}"#))));
    }
}
