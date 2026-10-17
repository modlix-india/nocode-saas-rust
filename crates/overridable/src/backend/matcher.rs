//! MongoDB query semantics for the in-memory backend: enough of the query language to run every
//! filter the services build (equality, comparisons, `$in`/`$nin`, `$exists`, regular
//! expressions, `$not`, `$and`/`$or`/`$nor`), plus sort and projection.
//!
//! `$expr` (only reached by a `fieldExpr` condition) is refused with an error rather than
//! answered wrongly; those filters are checked against a real database.

use std::cmp::Ordering;

use anyhow::{anyhow, bail, Result};
use mongodb::bson::{Bson, Document};
use regex::Regex;

/// Whether `doc` matches the query `filter`.
pub fn matches(doc: &Document, filter: &Document) -> Result<bool> {
    for (key, cond) in filter {
        let ok = match key.as_str() {
            "$and" => all_of(doc, cond)?.iter().all(|b| *b),
            "$or" => all_of(doc, cond)?.iter().any(|b| *b),
            "$nor" => !all_of(doc, cond)?.iter().any(|b| *b),
            "$expr" => bail!("$expr is not supported by the in-memory backend"),
            k if k.starts_with('$') => bail!("unsupported top-level operator {k}"),
            path => field_matches(&lookup(doc, path), cond)?,
        };
        if !ok {
            return Ok(false);
        }
    }
    Ok(true)
}

fn all_of(doc: &Document, cond: &Bson) -> Result<Vec<bool>> {
    let Bson::Array(list) = cond else { bail!("$and/$or/$nor need an array") };
    list.iter()
        .map(|c| match c {
            Bson::Document(d) => matches(doc, d),
            _ => Err(anyhow!("$and/$or/$nor elements must be documents")),
        })
        .collect()
}

/// The values at a dotted path: one value, several when the path crosses an array, none when
/// it is missing.
fn lookup<'a>(doc: &'a Document, path: &str) -> Vec<&'a Bson> {
    let mut current: Vec<&Bson> = Vec::new();
    let mut parts = path.split('.');
    let Some(first) = parts.next() else { return current };
    if let Some(v) = doc.get(first) {
        current.push(v);
    }
    for part in parts {
        let mut next = Vec::new();
        for v in current {
            match v {
                Bson::Document(d) => next.extend(d.get(part)),
                Bson::Array(a) => {
                    for x in a {
                        if let Bson::Document(d) = x {
                            next.extend(d.get(part));
                        }
                    }
                }
                _ => {}
            }
        }
        current = next;
    }
    current
}

fn is_operator_doc(d: &Document) -> bool {
    d.keys().next().is_some_and(|k| k.starts_with('$'))
}

fn field_matches(values: &[&Bson], cond: &Bson) -> Result<bool> {
    match cond {
        Bson::Document(d) if is_operator_doc(d) => {
            let options = d.get_str("$options").unwrap_or("");
            for (op, arg) in d {
                if op == "$options" {
                    continue;
                }
                if !operator(values, op, arg, options)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Bson::RegularExpression(r) => regex_any(values, &r.pattern, &r.options),
        other => Ok(equals_any(values, other)),
    }
}

fn operator(values: &[&Bson], op: &str, arg: &Bson, options: &str) -> Result<bool> {
    Ok(match op {
        "$eq" => equals_any(values, arg),
        "$ne" => !equals_any(values, arg),
        "$gt" => compare_any(values, arg, |o| o == Ordering::Greater),
        "$gte" => compare_any(values, arg, |o| o != Ordering::Less),
        "$lt" => compare_any(values, arg, |o| o == Ordering::Less),
        "$lte" => compare_any(values, arg, |o| o != Ordering::Greater),
        "$in" => in_list(values, arg)?,
        "$nin" => !in_list(values, arg)?,
        "$exists" => {
            let want = !matches!(arg, Bson::Boolean(false) | Bson::Int32(0) | Bson::Int64(0));
            values.is_empty() != want
        }
        "$regex" => match arg {
            Bson::String(p) => regex_any(values, p, options)?,
            Bson::RegularExpression(r) => regex_any(values, &r.pattern, if options.is_empty() { &r.options } else { options })?,
            _ => bail!("$regex needs a string"),
        },
        "$not" => !field_matches(values, arg)?,
        other => bail!("unsupported operator {other}"),
    })
}

/// Equality as Mongo applies it to a field: a missing field equals null, and an array field
/// matches when it equals the value or holds an element that does.
fn equals_any(values: &[&Bson], target: &Bson) -> bool {
    if values.is_empty() {
        return matches!(target, Bson::Null);
    }
    values.iter().any(|v| {
        bson_eq(v, target)
            || match v {
                Bson::Array(a) => a.iter().any(|x| bson_eq(x, target)),
                _ => false,
            }
    })
}

fn in_list(values: &[&Bson], list: &Bson) -> Result<bool> {
    let Bson::Array(list) = list else { bail!("$in/$nin need an array") };
    for t in list {
        let hit = match t {
            Bson::RegularExpression(r) => regex_any(values, &r.pattern, &r.options)?,
            other => equals_any(values, other),
        };
        if hit {
            return Ok(true);
        }
    }
    Ok(false)
}

fn compare_any(values: &[&Bson], target: &Bson, ok: impl Fn(Ordering) -> bool) -> bool {
    values.iter().any(|v| {
        let direct = compare(v, target).is_some_and(&ok);
        direct
            || match v {
                Bson::Array(a) => a.iter().any(|x| compare(x, target).is_some_and(&ok)),
                _ => false,
            }
    })
}

fn regex_any(values: &[&Bson], pattern: &str, options: &str) -> Result<bool> {
    let mut flags = String::new();
    for c in options.chars() {
        if matches!(c, 'i' | 'm' | 's' | 'x') {
            flags.push(c);
        }
    }
    let full = if flags.is_empty() { pattern.to_string() } else { format!("(?{flags}){pattern}") };
    let re = Regex::new(&full)?;
    Ok(values.iter().any(|v| match v {
        Bson::String(s) => re.is_match(s),
        Bson::Array(a) => a.iter().any(|x| matches!(x, Bson::String(s) if re.is_match(s))),
        _ => false,
    }))
}

fn number(b: &Bson) -> Option<f64> {
    match b {
        Bson::Int32(i) => Some(*i as f64),
        Bson::Int64(i) => Some(*i as f64),
        Bson::Double(d) => Some(*d),
        _ => None,
    }
}

/// Mongo equality: numbers by value whatever their type, documents and arrays structurally.
pub fn bson_eq(a: &Bson, b: &Bson) -> bool {
    match (number(a), number(b)) {
        (Some(x), Some(y)) => x == y,
        _ => match (a, b) {
            (Bson::Document(x), Bson::Document(y)) => {
                x.len() == y.len() && x.iter().zip(y.iter()).all(|((ka, va), (kb, vb))| ka == kb && bson_eq(va, vb))
            }
            (Bson::Array(x), Bson::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| bson_eq(p, q)),
            (Bson::Undefined, Bson::Null) | (Bson::Null, Bson::Undefined) => true,
            _ => a == b,
        },
    }
}

/// The order of two values of comparable types; `None` across types (Mongo's comparison
/// operators only match values of the same type bracket).
pub fn compare(a: &Bson, b: &Bson) -> Option<Ordering> {
    if let (Some(x), Some(y)) = (number(a), number(b)) {
        return x.partial_cmp(&y);
    }
    match (a, b) {
        (Bson::String(x), Bson::String(y)) => Some(x.cmp(y)),
        (Bson::DateTime(x), Bson::DateTime(y)) => Some(x.cmp(y)),
        (Bson::Boolean(x), Bson::Boolean(y)) => Some(x.cmp(y)),
        (Bson::ObjectId(x), Bson::ObjectId(y)) => Some(x.bytes().cmp(&y.bytes())),
        _ => None,
    }
}

/// The rank of a type in Mongo's sort order (null first, then numbers, strings, documents...).
fn type_rank(b: Option<&Bson>) -> u8 {
    match b {
        None | Some(Bson::Null) | Some(Bson::Undefined) => 1,
        Some(Bson::Int32(_) | Bson::Int64(_) | Bson::Double(_) | Bson::Decimal128(_)) => 2,
        Some(Bson::String(_) | Bson::Symbol(_)) => 3,
        Some(Bson::Document(_)) => 4,
        Some(Bson::Array(_)) => 5,
        Some(Bson::Binary(_)) => 6,
        Some(Bson::ObjectId(_)) => 7,
        Some(Bson::Boolean(_)) => 8,
        Some(Bson::DateTime(_)) => 9,
        _ => 10,
    }
}

/// Sorts documents as Mongo does for a `{field: 1|-1, ...}` sort document. Stable, so equal
/// keys keep their stored order.
pub fn sort(docs: &mut [Document], spec: &Document) {
    docs.sort_by(|x, y| {
        for (field, dir) in spec {
            let desc = matches!(dir, Bson::Int32(d) if *d < 0) || matches!(dir, Bson::Int64(d) if *d < 0);
            let a = lookup(x, field).into_iter().next();
            let b = lookup(y, field).into_iter().next();
            let o = match (a, b) {
                (Some(p), Some(q)) if type_rank(a) == type_rank(b) => compare(p, q).unwrap_or(Ordering::Equal),
                _ => type_rank(a).cmp(&type_rank(b)),
            };
            let o = if desc { o.reverse() } else { o };
            if o != Ordering::Equal {
                return o;
            }
        }
        Ordering::Equal
    });
}

/// Applies a projection: an inclusion list (top-level fields, `_id` kept unless excluded) or an
/// exclusion list.
pub fn project(doc: &Document, projection: &Document) -> Document {
    let included: Vec<&str> = projection
        .iter()
        .filter(|(k, v)| k.as_str() != "_id" && is_truthy(v))
        .map(|(k, _)| k.as_str())
        .collect();
    let keep_id = projection.get("_id").is_none_or(is_truthy);
    if included.is_empty() {
        let mut out = doc.clone();
        for (k, v) in projection {
            if !is_truthy(v) {
                out.remove(k);
            }
        }
        return out;
    }
    doc.iter()
        .filter(|(k, _)| (k.as_str() == "_id" && keep_id) || included.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn is_truthy(v: &Bson) -> bool {
    !matches!(v, Bson::Boolean(false) | Bson::Int32(0) | Bson::Int64(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::{doc, oid::ObjectId, DateTime, Regex as BRegex};

    fn d() -> Document {
        doc! {
            "_id": ObjectId::parse_str("63bd2d154d18a31536e81fa5").unwrap(),
            "name": "home", "n": 5_i32, "f": 2.5, "flag": true, "nul": null,
            "tags": ["a", "b"], "object": {"id": "x1", "deep": {"k": 1_i64}},
            "list": [{"k": "p"}, {"k": "q"}], "when": DateTime::from_millis(1000),
        }
    }

    fn m(f: Document) -> bool {
        matches(&d(), &f).unwrap()
    }

    #[test]
    fn equality_and_paths() {
        assert!(m(doc! {"name": "home"}));
        assert!(!m(doc! {"name": "other"}));
        assert!(m(doc! {"n": 5.0}), "numbers compare by value across types");
        assert!(m(doc! {"object.id": "x1"}));
        assert!(m(doc! {"object.deep.k": 1_i32}));
        assert!(m(doc! {"list.k": "q"}), "a path through an array matches any element");
        assert!(m(doc! {"tags": "b"}), "an array field matches an element");
        assert!(m(doc! {"tags": ["a", "b"]}));
        assert!(m(doc! {"missing": null}), "a missing field equals null");
        assert!(m(doc! {"nul": null}));
        assert!(m(doc! {"object": {"id": "x1", "deep": {"k": 1_i32}}}));
        assert!(!m(doc! {"object": {"deep": {"k": 1_i32}, "id": "x1"}}), "documents compare in order");
        assert!(m(doc! {}));
    }

    #[test]
    fn operators() {
        assert!(m(doc! {"n": {"$gt": 4_i32, "$lt": 6_i64}}));
        assert!(!m(doc! {"n": {"$gte": 6_i32}}));
        assert!(m(doc! {"n": {"$lte": 5_i32}}));
        assert!(m(doc! {"f": {"$eq": 2.5}}));
        assert!(m(doc! {"name": {"$ne": "x"}}));
        assert!(!m(doc! {"nul": {"$ne": null}}));
        assert!(!m(doc! {"missing": {"$ne": null}}));
        assert!(m(doc! {"name": {"$in": ["x", "home"]}}));
        assert!(m(doc! {"missing": {"$in": [null]}}));
        assert!(m(doc! {"name": {"$nin": ["x"]}}));
        assert!(m(doc! {"name": {"$in": [BRegex { pattern: "^ho".into(), options: String::new() }]}}));
        assert!(m(doc! {"missing": {"$exists": false}}));
        assert!(m(doc! {"name": {"$exists": true}}));
        assert!(!m(doc! {"name": {"$exists": 0_i32}}));
        assert!(m(doc! {"name": {"$regex": "OM", "$options": "i"}}));
        assert!(m(doc! {"name": {"$regex": BRegex { pattern: "om".into(), options: String::new() }}}));
        assert!(m(doc! {"name": BRegex { pattern: "^h".into(), options: String::new() }}));
        assert!(m(doc! {"tags": BRegex { pattern: "b".into(), options: String::new() }}));
        assert!(!m(doc! {"n": BRegex { pattern: "5".into(), options: String::new() }}), "a regex only matches strings");
        assert!(m(doc! {"name": {"$not": BRegex { pattern: "x".into(), options: String::new() }}}));
        assert!(!m(doc! {"name": {"$not": {"$eq": "home"}}}));
        assert!(m(doc! {"when": {"$gt": DateTime::from_millis(1)}}));
        assert!(m(doc! {"tags": {"$gt": "a"}}), "comparisons reach into arrays");
        assert!(!m(doc! {"name": {"$gt": 1_i32}}), "no comparison across types");
        assert!(m(doc! {"flag": {"$gte": false}}));
        assert!(m(doc! {"_id": {"$gt": ObjectId::parse_str("000000000000000000000000").unwrap()}}));
    }

    #[test]
    fn logical() {
        assert!(m(doc! {"$and": [{"name": "home"}, {"n": 5_i32}]}));
        assert!(!m(doc! {"$and": [{"name": "home"}, {"n": 6_i32}]}));
        assert!(m(doc! {"$or": [{"name": "x"}, {"n": 5_i32}]}));
        assert!(m(doc! {"$nor": [{"name": "x"}]}));
        assert!(m(doc! {"$and": [{}]}));
    }

    #[test]
    fn refusals() {
        assert!(matches(&d(), &doc! {"$expr": {"$eq": ["$a", 1_i32]}}).is_err());
        assert!(matches(&d(), &doc! {"$where": "x"}).is_err());
        assert!(matches(&d(), &doc! {"$and": 1_i32}).is_err());
        assert!(matches(&d(), &doc! {"$and": [1_i32]}).is_err());
        assert!(matches(&d(), &doc! {"n": {"$size": 1_i32}}).is_err());
        assert!(matches(&d(), &doc! {"n": {"$in": 1_i32}}).is_err());
        assert!(matches(&d(), &doc! {"n": {"$regex": 1_i32}}).is_err());
        assert!(matches(&d(), &doc! {"name": {"$regex": "("}}).is_err());
    }

    #[test]
    fn equality_helpers() {
        assert!(bson_eq(&Bson::Undefined, &Bson::Null));
        assert!(bson_eq(&Bson::Null, &Bson::Undefined));
        assert!(!bson_eq(&Bson::Array(vec![]), &Bson::Array(vec![Bson::Null])));
        assert_eq!(compare(&Bson::Null, &Bson::Null), None);
    }

    #[test]
    fn sorting_and_projection() {
        let mut docs = vec![
            doc! {"a": 2_i32, "b": "x"},
            doc! {"a": 1_i32, "b": "y"},
            doc! {"b": "z"},
            doc! {"a": "s", "b": "w"},
            doc! {"a": 1_i32, "b": "a"},
        ];
        sort(&mut docs, &doc! {"a": 1_i32, "b": -1_i32});
        let order: Vec<&str> = docs.iter().map(|x| x.get_str("b").unwrap()).collect();
        assert_eq!(order, ["z", "y", "a", "x", "w"]);
        sort(&mut docs, &doc! {"a": -1_i64});
        assert_eq!(docs[0].get_str("b").unwrap(), "w");
        let ranks: Vec<u8> = [
            None,
            Some(Bson::Document(doc! {})),
            Some(Bson::Array(vec![])),
            Some(Bson::Binary(mongodb::bson::Binary { subtype: mongodb::bson::spec::BinarySubtype::Generic, bytes: vec![] })),
            Some(Bson::ObjectId(ObjectId::new())),
            Some(Bson::Boolean(true)),
            Some(Bson::DateTime(DateTime::from_millis(0))),
            Some(Bson::MaxKey),
        ]
        .iter()
        .map(|b| type_rank(b.as_ref()))
        .collect();
        assert_eq!(ranks, [1, 4, 5, 6, 7, 8, 9, 10]);

        let src = d();
        let p = project(&src, &doc! {"name": 1_i32, "n": true});
        assert_eq!(p.keys().collect::<Vec<_>>(), ["_id", "name", "n"]);
        let p = project(&src, &doc! {"name": 1_i32, "_id": 0_i32});
        assert_eq!(p.keys().collect::<Vec<_>>(), ["name"]);
        let p = project(&src, &doc! {"object": 0_i32, "list": false});
        assert!(!p.contains_key("object") && !p.contains_key("list") && p.contains_key("name"));
    }
}
